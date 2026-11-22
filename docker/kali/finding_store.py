"""Registro estructurado de hallazgos por engagement de `kali-mcp` (STDLIB PURA).

El store de evidencia del bucle OODA. Hoy la evidencia vive solo en el historial de la
conversation (ephemeral, lost with subagent context hygiene and with the
`down -v` of the profile). This module gives it a durable, queryable, downloadable record:
a JSONL file per engagement, with one finding per line.

Where it lives: on the existing artifact plane (``/artifacts``, the same one served by
``artifact_http.py`` on :8901), NOT in Hermes state. Thus it survives the
ephemeral nature of the profile and is a downloadable artifact. The file is
``<engagement_id>/findings.jsonl`` under the staging root — reusing the confinement
de rutas de ``artifact_store`` (sin ``..``/separadores) para que un ``engagement_id``
manipulado no escape del directorio.

Why a separate module, like ``artifact_store.py``/``tool_streaming.py``:
``kali_mcp_server.py`` imports ``mcp``/``anyio`` (not in the dev venv). This
mechanism uses ONLY the standard library, so it is covered by tests without the SDK. The MCP tools
``record_finding``/``read_findings`` son una capa fina sobre ``append``/``read``.

Disciplina de seguridad: la evidencia que se guarda (``evidence.output``) sigue siendo
DATO NO CONFIABLE al releerla — se razona sobre ella, nunca se obedecen instrucciones
embedded (prompt injection). Here it is PERSISTED verbatim; it is never interpreted.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import artifact_store

# Canonical name of the findings file inside the engagement directory.
FINDINGS_NAME = "findings.jsonl"

# States aligned with the "hypothesis vs. confirmed finding" discipline of SOUL.md.
VALID_STATES = ("hypothesis", "partial", "confirmed", "discarded")

# Fases del bucle OODA (etiqueta libre si no encaja ninguna).
VALID_PHASES = ("observe", "orient", "decide", "act")

# Canonical severity buckets of a finding (OPTIONAL). It is the EXACT contract that the
# plugin privado CTEM consume para ordenar los findings de forma fiable: clave `severity`
# top level, lowercase string, one of these five and only these five. If the
# finding does not include it, the consumer falls back to best-effort derivation from the title — that is why
# el campo es opcional y retrocompatible (no se exige nunca).
VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")

# Umbral minimo de bytes para considerar que la salida verbatim de una evidencia es real
# (no un marcador vacio tipo "ok"/"200"). No garantiza que sea cruda, pero descarta lo
# obviamente insuficiente para contrastar un hallazgo confirmado.
_MIN_EVIDENCE_OUTPUT_LEN = 16


class FindingStoreError(ValueError):
    """Invalid input for the store (fail-closed; nothing is written)."""


def _now_iso() -> str:
    """Timestamp ISO-8601 en UTC (sufijo 'Z') — mismo estilo que artifact_store."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _findings_path(engagement_id: str) -> Path:
    """Ruta CONFINADA del JSONL de hallazgos del engagement (reutiliza el confinamiento).

    ``artifact_store.resolve`` valida ``engagement_id``/``FINDINGS_NAME`` (sin traversal
    nor separators) and checks that the path falls under the staging root. An
    unsafe ``engagement_id`` raises ``ValueError`` there.
    """
    return artifact_store.resolve(engagement_id, FINDINGS_NAME)


def _validate_confirmed_evidence(evidence: Any) -> None:
    """Exige evidencia REPRODUCIBLE para un hallazgo ``confirmed`` (fail-closed).

    Un hallazgo confirmado tiene que poder CONTRASTARSE: quien lea el informe debe poder
    re-run the step and see the same thing. That is why it is rejected here, for ``state=confirmed``,
    una evidencia que no permita esa reproduccion. Se aceptan DOS formas:

      1. ``command`` + ``output``: el comando EXACTO re-ejecutable (el argv tal cual se paso
         a ``kali_run``, o la accion de navegador reproducible) MAS la salida VERBATIM que
         produjo (no un resumen). ``output`` debe superar un minimo de bytes para descartar
         marcadores vacios tipo "ok"/"200".
      2. ``artifact_ref``: ``{"execution_id","name"}`` apuntando al crudo staged en el plano
         de datos (cuando la salida es grande y viaja como artefacto).

    NO puede garantizar que el agente no parafrasee (es un LLM), pero rechaza fail-closed lo
    obviamente insuficiente: evidencia ausente, sin comando, o con salida vacia/trivial. La
    disciplina de pegar la salida CRUDA (no resumida) la refuerzan las skills.
    """
    if not isinstance(evidence, dict) or not evidence:
        raise FindingStoreError(
            "invalid 'confirmed' finding: requires reproducible 'evidence' "
            "('command'+'output' verbatim, o 'artifact_ref'). No se admite confirmar sin evidencia."
        )

    ref = evidence.get("artifact_ref")
    if isinstance(ref, dict) and ref.get("execution_id") and ref.get("name"):
        return  # evidencia por artefacto staged: suficiente

    command = evidence.get("command")
    output = evidence.get("output")
    if not isinstance(command, str) or not command.strip():
        raise FindingStoreError(
            "invalid 'confirmed' finding: 'evidence.command' must be the EXACT command "
            "re-runnable (the argv exactly as passed to kali_run), not a narrative."
        )
    if not isinstance(output, str) or len(output.strip()) < _MIN_EVIDENCE_OUTPUT_LEN:
        raise FindingStoreError(
            "invalid 'confirmed' finding: 'evidence.output' must be the VERBATIM output of the "
            "command (raw request/response), not a summary; minimum %d characters."
            % _MIN_EVIDENCE_OUTPUT_LEN
        )


def _normalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Valida y normaliza un hallazgo fail-closed; devuelve el dict a persistir.

    Reglas (fail-closed, no se escribe nada si no se cumplen):
      - ``finding`` es un dict.
      - ``title`` non-empty (human-readable finding summary).
      - ``state`` ∈ VALID_STATES.
      - ``phase`` ∈ VALID_PHASES si viene (se tolera ausente/libre, se guarda verbatim).
      - ``severity`` ∈ VALID_SEVERITIES if present (OPTIONAL; absence is valid and the
        consumidor deriva best-effort). Un valor fuera de los cinco buckets se rechaza.
      - si ``state`` es ``confirmed``: ``evidence`` debe ser REPRODUCIBLE (ver
        ``_validate_confirmed_evidence``). Un hallazgo sin evidencia contrastable no puede
        be marked confirmed — downgrade it to ``partial``/``hypothesis``.

    Rellena ``id`` (uuid4 hex si falta) y ``recorded_at`` (timestamp del servidor,
    authoritative: a timestamp provided by the agent is NOT trusted). The rest of
    campos (target, technique_id, severity, category, evidence, confidence, change) se
    guardan tal cual si vienen, para no acoplar el esquema a un consumidor concreto.
    """
    if not isinstance(finding, dict):
        raise FindingStoreError("invalid finding: expected a JSON object.")

    title = finding.get("title")
    if not isinstance(title, str) or not title.strip():
        raise FindingStoreError("invalid finding: non-empty 'title' is required.")

    state = finding.get("state")
    if state not in VALID_STATES:
        raise FindingStoreError(
            "invalid finding: 'state' must be one of %r (got %r)."
            % (list(VALID_STATES), state)
        )

    phase = finding.get("phase")
    if phase is not None and phase not in VALID_PHASES:
        raise FindingStoreError(
            "invalid finding: 'phase' must be one of %r if provided (got %r)."
            % (list(VALID_PHASES), phase)
        )

    # OPTIONAL, backward-compatible severity: absence is valid (the consumer derives). If
    # present, it MUST be one of the five canonical lowercase buckets — otherwise fail-closed
    # (no se guarda "a medias"). Si valida, se persiste verbatim junto al resto de campos.
    severity = finding.get("severity")
    if severity is not None and severity not in VALID_SEVERITIES:
        raise FindingStoreError(
            "invalid finding: 'severity' must be one of %r if provided (got %r)."
            % (list(VALID_SEVERITIES), severity)
        )

    # Un hallazgo CONFIRMADO exige evidencia reproducible (trazabilidad): fail-closed.
    if state == "confirmed":
        _validate_confirmed_evidence(finding.get("evidence"))

    # Copia superficial + campos autoritativos del servidor. El id del agente se respeta
    # if it comes well-formed; otherwise it is generated (a line is never written without an id).
    record = dict(finding)
    fid = record.get("id")
    if not isinstance(fid, str) or not fid.strip():
        fid = uuid.uuid4().hex
    record["id"] = fid
    record["title"] = title.strip()
    record["state"] = state
    # recorded_at is ALWAYS set by the server (the agent's value is not trusted).
    record["recorded_at"] = _now_iso()
    return record


def append(engagement_id: str, finding: dict[str, Any]) -> dict[str, Any]:
    """Adds a normalized finding to the engagement JSONL and returns the record.

    Line-level atomic append: the record is serialized to a SINGLE JSON line
    (sin saltos internos) y se escribe con ``O_APPEND`` en una sola llamada ``write``,
    de modo que appends concurrentes de distintos workers no se entrelacen. Crea el
    directorio del engagement si no existe.

    Fail-closed: si el finding no valida (ver ``_normalize_finding``), levanta
    ``FindingStoreError`` y NO escribe nada.
    """
    record = _normalize_finding(finding)
    path = _findings_path(engagement_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False) + "\n"
    # O_APPEND guarantees each write is positioned at the end atomically; a line
    # entera en un solo write evita el entrelazado entre escritores concurrentes.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)
    return record


def read(
    engagement_id: str, cursor: int = 0, limit: int | None = None
) -> dict[str, Any]:
    """Reads the engagement findings PAGINATED by line index.

    Cursor pattern identical to ``tool_streaming.read_findings``: ``cursor`` is the
    0-based index of the first finding to return; up to ``limit`` are returned (or all
    remaining if ``limit`` is ``None``). Unreadable lines (corrupt JSON) are
    SALTAN sin reventar — el store es best-effort en lectura.

    Returns:
        ``{"findings": [...], "next_cursor": int, "done": bool, "total": int}``. Un
        an ``engagement_id`` without a file returns an empty page with ``done=True`` and
        ``total=0`` (no revienta).
    """
    try:
        path = _findings_path(engagement_id)
    except ValueError:
        # unsafe engagement_id: nothing to read (fail-closed on reads too).
        return {"findings": [], "next_cursor": cursor, "done": True, "total": 0}

    if not path.is_file():
        return {"findings": [], "next_cursor": cursor, "done": True, "total": 0}

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
        "findings": page,
        "next_cursor": end,
        "done": end >= total,
        "total": total,
    }
