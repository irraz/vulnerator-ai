"""Durable audit log of raw shell executions (`kali-mcp`, PURE STDLIB).

What it is: the re-runnable record of EVERY ``kali_run``/``kali_exec`` execution. A
JSONL file per engagement —`` <engagement_id>/session.jsonl`` under the root of the
artifact plane (``/artifacts``)— with one record per line containing the EXACT command,
its FULL output verbatim (not the capped 2000-line view the LLM receives), the
returncode and timestamps. It is the single source for reconstructing/reproducing what the
agente contra el target, independiente del transcript de Hermes (que trunca salidas
grandes) y del ring en memoria (capado a ``RING_MAXLEN``).

Why this layer exists: ``shell_exec.run_shell`` returns to the LLM the ring output
(last ``RING_MAXLEN`` lines, context protection). For audit/reproduction, the
COMPLETE stdout/stderr is needed; this module persists it WITHOUT touching what the LLM sees.

Where it lives and why a separate module: like ``finding_store`` / ``artifact_store`` /
``tool_streaming``, it uses ONLY the standard library (no ``mcp``) to be covered by tests in
el venv de dev. Reutiliza el confinamiento de rutas de ``artifact_store`` (sin ``..`` ni
separadores) para que un ``engagement_id`` manipulado no escape del directorio.

Lifecycle / retention: it inherits ``finding_store``'s — persists in the named volume
``kali-artifacts``, no automatic purge; cleared by the operator (or ``docker compose
down -v``). No own retention is deliberately defined (a single mental model with the
findings).

Disciplina de seguridad: ``command``/``output`` son DATO NO CONFIABLE (salida verbatim de
a tool against a real target). Here it is PERSISTED verbatim; it is never interpreted nor are
embedded instructions obeyed. The ``output`` is serialized inside a SINGLE JSON line
``json.dumps`` escapes internal newlines), so the JSONL remains one-line-per-
record even if the output has thousands of lines.
"""

from __future__ import annotations

import json
import os
from typing import Any

import artifact_store

# Canonical name of the session log inside the engagement directory.
SESSION_LOG_NAME = "session.jsonl"

# Bucket por defecto cuando el agente NO declara engagement_id (o es inseguro). El eje de
# real session is reconstructed downstream by cross-referencing Hermes' transcript with the
# ``execution_id`` (Hermes does NOT expose its run_id to the agent, so kali cannot label
# by session; see the audit design docs).
DEFAULT_ENGAGEMENT = "_unscoped"


def safe_engagement(engagement_id: Any) -> str:
    """Devuelve un ``engagement_id`` confinable, o ``DEFAULT_ENGAGEMENT`` si no lo es.

    Empty, non-string, or with traversal/separators -> default bucket (fail-open: it is
    audited anyway, in a safe directory, rather than crashing or escaping the root).
    """
    if not engagement_id or not isinstance(engagement_id, str):
        return DEFAULT_ENGAGEMENT
    try:
        artifact_store.resolve(engagement_id, SESSION_LOG_NAME)
    except ValueError:
        return DEFAULT_ENGAGEMENT
    return engagement_id


def record(engagement_id: Any, entry: dict[str, Any]) -> dict[str, Any]:
    """Appends ``entry`` as a JSON line to the engagement's ``session.jsonl``.

    Line-level atomic append (same pattern as ``finding_store.append``): the
    record is serialized to a SINGLE JSON line (``json.dumps`` escapes newlines in the
    ``output``) y se escribe con ``O_APPEND`` en una sola llamada ``write``, de modo que
    appends concurrentes de distintos workers (p. ej. varios ``kali_exec`` en background)
    no se entrelacen. El ``engagement_id`` se sanea a un segmento confinable.

    Devuelve el ``entry`` (con el ``engagement_id`` efectivo ya aplicado por el caller).
    """
    eng = safe_engagement(engagement_id)
    path = artifact_store.resolve(eng, SESSION_LOG_NAME)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    # O_APPEND: each write is positioned at the end atomically; a whole line in one
    # solo write evita el entrelazado entre escritores concurrentes.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)
    return entry


def read(
    engagement_id: Any, cursor: int = 0, limit: int | None = None
) -> dict[str, Any]:
    """Reads the engagement records PAGINATED by line index (for the UI/tests).

    Cursor pattern identical to ``finding_store.read``: ``cursor`` is the 0-based index of the
    primer registro a devolver; se devuelven hasta ``limit`` (o todos los restantes si es
    ``None``). Corrupt lines (invalid JSON) are SKIPPED without crashing.

    Returns:
        ``{"executions": [...], "next_cursor": int, "done": bool, "total": int}``. Un
        an engagement without a file (or unsafe id) returns an empty page with ``done=True`` and
        ``total=0`` (no revienta).
    """
    eng = safe_engagement(engagement_id)
    try:
        path = artifact_store.resolve(eng, SESSION_LOG_NAME)
    except ValueError:
        return {"executions": [], "next_cursor": cursor, "done": True, "total": 0}

    if not path.is_file():
        return {"executions": [], "next_cursor": cursor, "done": True, "total": 0}

    records: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw in handle:
            raw = raw.strip()
            if not raw:
                continue
            try:
                doc = json.loads(raw)
            except json.JSONDecodeError:
                continue  # corrupt line: skipped, not interpreted
            if isinstance(doc, dict):
                records.append(doc)

    total = len(records)
    start = max(0, cursor)
    end = total if limit is None else min(total, start + max(0, limit))
    page = records[start:end]
    return {
        "executions": page,
        "next_cursor": end,
        "done": end >= total,
        "total": total,
    }
