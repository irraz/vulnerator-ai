"""Staging EFÍMERO de artefactos de `kali-mcp` (STDLIB PURA).

El plano de DATOS en el lado del runner. Cuando una tool termina, su resultado CRUDO se
**stagea** aquí indexado por ``execution_id`` y se SIRVE por HTTP (ver
``artifact_http.py``); el cliente lo baja por stream a su almacén persistente. Este
staging es efímero (vive en el contenedor Kali): no es la fuente de verdad, sólo el
punto de entrega del dato grande SIN que viaje por el canal de control (MCP), evitando
el límite de 1 MiB de un único evento SSE.

Por qué un módulo aparte, igual que ``tool_streaming.py`` (testeabilidad):
``kali_mcp_server.py`` importa ``mcp``/``anyio`` (no están en el venv de dev). Esta
mecánica usa SOLO la librería estándar, así se cubre con tests sin el SDK.

Disciplina de seguridad: el blob es DATO NO CONFIABLE (salida verbatim de una tool
contra un target real). Aquí se TRANSPORTA y PERSISTE verbatim; nunca se interpreta.
Las rutas se CONFINAN bajo la raíz (sin ``..``/separadores) para que un
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

# Raíz del staging. Configurable por entorno; default `/artifacts` (dir del contenedor
# Kali, efímero). El cliente lee por HTTP, no por FS compartido.
_DEFAULT_ROOT = "/artifacts"

_META_NAME = "meta.json"

# Tamaño de chunk para copiar/leer sin cargar el fichero entero en RAM.
_CHUNK_SIZE = 65536


def _now_iso() -> str:
    """Timestamp ISO-8601 en UTC (sufijo 'Z') — mismo estilo que tool_streaming."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def root_dir() -> Path:
    """Directorio raíz del staging (``KALI_ARTIFACTS_DIR`` o ``/artifacts``)."""
    return Path(os.environ.get("KALI_ARTIFACTS_DIR", _DEFAULT_ROOT))


def _safe_segment(value: str) -> str:
    """Valida que un segmento de ruta sea confinable (sin ``..``, ``/``, ``\\``, NUL).

    Frontera del plano de datos: ``execution_id`` y ``name`` se validan ANTES de
    tocar el filesystem. Devuelve el propio valor si es seguro; si no, ``ValueError``.
    """
    if not value or not isinstance(value, str):
        raise ValueError("segmento de artefacto vacío o no-string")
    if value in (".", "..") or "/" in value or "\\" in value or "\x00" in value:
        raise ValueError("segmento de artefacto inseguro: %r" % (value,))
    return value


def _execution_dir(execution_id: str) -> Path:
    return root_dir() / _safe_segment(execution_id)


def resolve(execution_id: str, name: str) -> Path:
    """Resuelve la ruta de un artefacto staged CONFINADA bajo la raíz.

    Valida ``execution_id``/``name`` (sin traversal ni separadores) y verifica que la
    ruta resuelta cae bajo la raíz del staging. Levanta ``ValueError`` si algo intenta
    escapar. NO comprueba existencia (eso es cosa del caller: 404 si no existe).
    """
    safe_exec = _safe_segment(execution_id)
    safe_name = _safe_segment(name)
    root = root_dir().resolve()
    candidate = (root / safe_exec / safe_name).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError("ruta de artefacto fuera de la raíz de staging")
    return candidate


# --- metadatos por ejecución (meta.json) -------------------------------------


def _meta_path(execution_id: str) -> Path:
    return _execution_dir(execution_id) / _META_NAME


def read_meta(execution_id: str) -> dict[str, Any]:
    """Devuelve el índice de artefactos staged de una ejecución (``{}`` si no hay).

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
    """Escribe el índice de meta de la ejecución de forma atómica (tmp+replace)."""
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
    """Añade/actualiza la entrada de un artefacto en el meta.json de la ejecución."""
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


# --- staging (atómico, por stream) -------------------------------------------


def _stage_stream(
    execution_id: str, name: str, chunks: Iterable[bytes | str]
) -> tuple[int, str]:
    """Escribe un stream de chunks al destino confinado (tmp+replace) -> (size, sha256).

    Calcula tamaño + sha256 sobre la marcha, sin materializar el artefacto entero en
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
    """Stagea ``data`` como artefacto ``name`` de la ejecución y registra su meta.

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
    """Stagea el fichero ``src_path`` como artefacto ``name`` (copiándolo por chunks).

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
