"""EPHEMERAL staging of `kali-mcp` artifacts (PURE STDLIB).

El plano de DATOS en el lado del runner. Cuando una tool termina, su resultado CRUDO se
**staged** here indexed by ``execution_id`` and SERVED over HTTP (see
``artifact_http.py``); the client downloads it by stream to its persistent store. This
staging is ephemeral (lives in the Kali container): it is not the source of truth, only the
punto de entrega del dato grande SIN que viaje por el canal de control (MCP), evitando
the 1 MiB limit of a single SSE event.

Why a separate module, like ``tool_streaming.py`` (testability):
``kali_mcp_server.py`` imports ``mcp``/``anyio`` (not in the dev venv). This
mechanism uses ONLY the standard library, so it is covered by tests without the SDK.

Disciplina de seguridad: el blob es DATO NO CONFIABLE (salida verbatim de una tool
against a real target). Here it is TRANSPORTED and PERSISTED verbatim; it is never interpreted.
Paths are CONFINED under the root (no ``..``/separators) so that a
``execution_id``/``name`` manipulado no escape del directorio de staging.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

# Staging root. Configurable via environment; default `/artifacts` (container dir of
# Kali, ephemeral). The client reads over HTTP, not via shared FS.
_DEFAULT_ROOT = "/artifacts"

_META_NAME = "meta.json"

# Chunk size for copying/reading without loading the whole file into RAM.
_CHUNK_SIZE = 65536


def _now_iso() -> str:
    """Timestamp ISO-8601 en UTC (sufijo 'Z') — mismo estilo que tool_streaming."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def root_dir() -> Path:
    """Staging root directory (``KALI_ARTIFACTS_DIR`` or ``/artifacts``)."""
    return Path(os.environ.get("KALI_ARTIFACTS_DIR", _DEFAULT_ROOT))


def _safe_segment(value: str) -> str:
    """Valida que un segmento de ruta sea confinable (sin ``..``, ``/``, ``\\``, NUL).

    Frontera del plano de datos: ``execution_id`` y ``name`` se validan ANTES de
    tocar el filesystem. Devuelve el propio valor si es seguro; si no, ``ValueError``.
    """
    if not value or not isinstance(value, str):
        raise ValueError("empty or non-string artifact segment")
    if value in (".", "..") or "/" in value or "\\" in value or "\x00" in value:
        raise ValueError("segmento de artefacto inseguro: %r" % (value,))
    return value


def _execution_dir(execution_id: str) -> Path:
    return root_dir() / _safe_segment(execution_id)


def resolve(execution_id: str, name: str) -> Path:
    """Resolves the path of a staged artifact CONFINED under the root.

    Valida ``execution_id``/``name`` (sin traversal ni separadores) y verifica que la
    resolved path falls under the staging root. Raises ``ValueError`` if anything tries to
    escapar. NO comprueba existencia (eso es cosa del caller: 404 si no existe).
    """
    safe_exec = _safe_segment(execution_id)
    safe_name = _safe_segment(name)
    root = root_dir().resolve()
    candidate = (root / safe_exec / safe_name).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError("artifact path outside the staging root")
    return candidate


# --- per-execution metadata (meta.json) -------------------------------------


def _meta_path(execution_id: str) -> Path:
    return _execution_dir(execution_id) / _META_NAME


def read_meta(execution_id: str) -> dict[str, Any]:
    """Returns the index of staged artifacts for an execution (``{}`` if none).

    Estructura: ``{"execution_id": str, "artifacts": {name: {size, sha256, staged_at,
    meta}}}``. Un ``execution_id`` desconocido o un meta ilegible devuelven ``{}``
    (no revienta).
    """
    path = _meta_path(execution_id)
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_meta(execution_id: str, index: dict[str, Any]) -> None:
    """Writes the execution meta index atomically (tmp+replace)."""
    exec_dir = _execution_dir(execution_id)
    exec_dir.mkdir(parents=True, exist_ok=True)
    path = _meta_path(execution_id)
    fd, tmp_name = tempfile.mkstemp(dir=exec_dir, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(index, handle, ensure_ascii=False, indent=2)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _record_meta(
    execution_id: str, name: str, size: int, sha256: str, meta: dict[str, Any] | None
) -> dict[str, Any]:
    """Adds/updates an artifact entry in the execution's meta.json."""
    index = read_meta(execution_id)
    if not index:
        index = {"execution_id": execution_id, "artifacts": {}}
    index.setdefault("artifacts", {})
    entry = {
        "name": name,
        "size": size,
        "sha256": sha256,
        "staged_at": _now_iso(),
        "meta": dict(meta or {}),
    }
    index["artifacts"][name] = entry
    _write_meta(execution_id, index)
    return entry


# --- staging (atomic, streamed) -------------------------------------------


def _stage_stream(
    execution_id: str, name: str, chunks: Iterable[bytes | str]
) -> tuple[int, str]:
    """Escribe un stream de chunks al destino confinado (tmp+replace) -> (size, sha256).

    Computes size + sha256 on the fly, without materializing the entire artifact in
    RAM (clave para resultados grandes).
    """
    dest = resolve(execution_id, name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    hasher = hashlib.sha256()
    size = 0
    fd, tmp_name = tempfile.mkstemp(dir=dest.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as handle:
            for chunk in chunks:
                if not chunk:
                    continue
                data = chunk.encode("utf-8") if isinstance(chunk, str) else bytes(chunk)
                handle.write(data)
                hasher.update(data)
                size += len(data)
        os.replace(tmp_name, dest)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    return size, hasher.hexdigest()


def put_bytes(
    execution_id: str,
    name: str,
    data: bytes,
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Stages ``data`` as artifact ``name`` of the execution and records its meta.

    Devuelve la entrada de meta ``{name, size, sha256, staged_at, meta}``.
    """
    size, sha256 = _stage_stream(execution_id, name, (data,))
    return _record_meta(execution_id, name, size, sha256, meta)


def put_file(
    execution_id: str,
    name: str,
    src_path: str | os.PathLike[str],
    meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Stages the file ``src_path`` as artifact ``name`` (copying it in chunks).

    Copia el contenido de ``src_path`` al destino confinado por stream (no carga el
    fichero entero en RAM) ANTES de que el caller limpie su directorio temporal.
    Devuelve la entrada de meta ``{name, size, sha256, staged_at, meta}``.
    """
    src = Path(src_path)

    def _chunks() -> Iterator[bytes]:
        with src.open("rb") as handle:
            while True:
                chunk = handle.read(_CHUNK_SIZE)
                if not chunk:
                    break
                yield chunk

    size, sha256 = _stage_stream(execution_id, name, _chunks())
    return _record_meta(execution_id, name, size, sha256, meta)


def stat(execution_id: str, name: str) -> dict[str, Any] | None:
    """Devuelve la entrada de meta de un artefacto staged, o ``None`` si no existe.

    No revienta ante ``execution_id``/``name`` desconocidos (devuelve ``None``). Un
    ``name`` con traversal se rechaza en ``resolve`` (``ValueError``), que el caller
    (HTTP) traduce a 400.
    """
    index = read_meta(execution_id)
    artifacts = index.get("artifacts", {}) if isinstance(index, dict) else {}
    entry = artifacts.get(name)
    return dict(entry) if isinstance(entry, dict) else None
