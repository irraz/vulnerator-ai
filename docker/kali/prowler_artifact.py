"""Prowler scan finalization: raw output -> artifact + bridge (PURE STDLIB).

Vive aparte de ``kali_mcp_server.py`` (que importa ``mcp``/``anyio``, no instalados en
el venv de dev) para poder cubrir con tests el camino post-escaneo SIN el SDK, igual
que ``tool_streaming.py``/``artifact_store.py``.

What it does when a scan finishes:
  1. Locates and reads the raw OCSF/JSON file Prowler wrote in ``outdir``.
  2. **Puente de compat:** guarda los findings paginables con
     ``tool_streaming.set_findings`` so ``read_scan_findings`` keeps serving them
     if the data plane is not configured.
  3. **Plano de DATOS:** stagea el fichero CRUDO como artefacto
     (``artifact_store.put_file``) y construye el ``done`` del control con una
     small **reference** (``artifact``) — NEVER inline findings.

The raw output is UNTRUSTED DATA: transported verbatim, interpreted no further than
contar los findings para el resumen de control.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import artifact_store
import tool_streaming

# Canonical name of Prowler's raw artifact inside staging/store.
PROWLER_ARTIFACT_NAME = "prowler.ocsf.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_prowler_output(outdir: Path) -> tuple[Path | None, list[dict] | None]:
    """Returns ``(path, findings)`` of the most recent readable OCSF/JSON file.

    Un solo parse por candidato (eficiente con ficheros grandes): en cuanto uno
    parses, its path and the extracted findings list are returned. If none is
    readable, ``(None, None)`` (the caller treats it as a scan with no valid output).
    """
    candidates = sorted(
        [*outdir.rglob("*.ocsf.json"), *outdir.rglob("*.json")],
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    )
    for path in candidates:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, list):
            return path, data
        if isinstance(data, dict):
            for key in ("findings", "results", "data"):
                if isinstance(data.get(key), list):
                    return path, data[key]
            return path, [data]
    return None, None


def _stage_artifact(
    execution_id: str,
    path: Path,
    returncode: int,
    params: dict[str, Any],
    findings_count: int,
) -> dict[str, Any] | None:
    """Stagea el fichero crudo como artefacto y devuelve la ref para el ``done``.

    Best-effort: si el staging falla (p. ej. FS no escribible), devuelve ``None`` y el
    worker publica el ``done`` sin ``artifact`` ref — se cae entonces al puente
    ``read_scan_findings``. El plano de datos no debe tumbar el escaneo.
    """
    meta = {
        "tool": "prowler",
        "phase": "collection",
        "params": dict(params),
        "ts": _now_iso(),
        "returncode": returncode,
        "status": "done",
    }
    try:
        entry = artifact_store.put_file(
            execution_id, PROWLER_ARTIFACT_NAME, path, meta
        )
    except Exception:  # noqa: BLE001 - staging best-effort; el puente cubre el fallo
        return None
    return {
        "execution_id": execution_id,
        "name": PROWLER_ARTIFACT_NAME,
        "size": entry["size"],
        "sha256": entry["sha256"],
        "findings_count": findings_count,
    }


def finalize_scan(
    execution_id: str,
    outdir: Path,
    returncode: int,
    params: dict[str, Any],
) -> dict[str, Any] | None:
    """Construye el estado ``done`` del escaneo: puente + artefacto por referencia.

    Returns the ``done`` dict that ``get_scan_status`` will publish:
      ``{status:'done', returncode, timed_out:False, findings_count, artifact?}``.
    The CONTROL channel carries ONLY that summary + the small ``artifact`` ref; the
    findings NO viajan inline. Si no hay salida legible, devuelve ``None`` (el caller
    publishes ``failed`` with a diagnostic).
    """
    path, findings = read_prowler_output(outdir)
    if findings is None or path is None:
        return None

    # Puente de compat: findings paginables disponibles ANTES de publicar done.
    tool_streaming.set_findings(execution_id, findings)

    done: dict[str, Any] = {
        "status": "done",
        "returncode": returncode,
        "timed_out": False,
        "findings_count": len(findings),
    }
    artifact = _stage_artifact(execution_id, path, returncode, params, len(findings))
    if artifact is not None:
        done["artifact"] = artifact
    return done
