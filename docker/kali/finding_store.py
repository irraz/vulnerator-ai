"""Registro estructurado de hallazgos por engagement de `kali-mcp` (STDLIB PURA).

El store de evidencia del bucle OODA. Hoy la evidencia vive solo en el historial de la
conversación (efímero, se pierde con la higiene de contexto por subagentes y con el
`down -v` del perfil). Este módulo le da un registro durable, consultable y descargable:
un fichero JSONL por engagement, con un hallazgo por línea.

Dónde vive: sobre el plano de artefactos existente (``/artifacts``, el mismo que sirve
``artifact_http.py`` en :8901), NO en el estado de Hermes. Así sobrevive a la naturaleza
efímera del perfil y es un artefacto descargable. El fichero es
``<engagement_id>/findings.jsonl`` bajo la raíz del staging — reutiliza el confinamiento
de rutas de ``artifact_store`` (sin ``..``/separadores) para que un ``engagement_id``
manipulado no escape del directorio.

Por qué un módulo aparte, igual que ``artifact_store.py``/``tool_streaming.py``:
``kali_mcp_server.py`` importa ``mcp``/``anyio`` (no están en el venv de dev). Esta
mecánica usa SOLO la librería estándar, así se cubre con tests sin el SDK. Las tools MCP
``record_finding``/``read_findings`` son una capa fina sobre ``append``/``read``.

Disciplina de seguridad: la evidencia que se guarda (``evidence.output``) sigue siendo
DATO NO CONFIABLE al releerla — se razona sobre ella, nunca se obedecen instrucciones
embebidas (prompt injection). Aquí se PERSISTE verbatim; nunca se interpreta.
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import artifact_store

# Nombre canónico del fichero de hallazgos dentro del directorio del engagement.
FINDINGS_NAME = "findings.jsonl"

# Estados alineados con la disciplina "hipótesis vs. hallazgo confirmado" del SOUL.md.
VALID_STATES = ("hypothesis", "partial", "confirmed", "discarded")

# Fases del bucle OODA (etiqueta libre si no encaja ninguna).
VALID_PHASES = ("observe", "orient", "decide", "act")

# Buckets canónicos de severidad del hallazgo (OPCIONAL). Es el contrato EXACTO que el
# plugin privado CTEM consume para ordenar los findings de forma fiable: clave `severity`
# de primer nivel, string en minúsculas, uno de estos cinco y solo estos cinco. Si el
# finding no la trae, el consumidor cae a su derivación best-effort del título — por eso
# el campo es opcional y retrocompatible (no se exige nunca).
VALID_SEVERITIES = ("critical", "high", "medium", "low", "info")

# Umbral minimo de bytes para considerar que la salida verbatim de una evidencia es real
# (no un marcador vacio tipo "ok"/"200"). No garantiza que sea cruda, pero descarta lo
# obviamente insuficiente para contrastar un hallazgo confirmado.
_MIN_EVIDENCE_OUTPUT_LEN = 16


class FindingStoreError(ValueError):
    """Entrada inválida para el store (fail-closed; no se escribe nada)."""


def _now_iso() -> str:
    """Timestamp ISO-8601 en UTC (sufijo 'Z') — mismo estilo que artifact_store."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _findings_path(engagement_id: str) -> Path:
    """Ruta CONFINADA del JSONL de hallazgos del engagement (reutiliza el confinamiento).

    ``artifact_store.resolve`` valida ``engagement_id``/``FINDINGS_NAME`` (sin traversal
    ni separadores) y comprueba que la ruta cae bajo la raíz del staging. Un
    ``engagement_id`` inseguro levanta ``ValueError`` ahí.
    """
    return artifact_store.resolve(engagement_id, FINDINGS_NAME)


def _validate_confirmed_evidence(evidence: Any) -> None:
    """Exige evidencia REPRODUCIBLE para un hallazgo ``confirmed`` (fail-closed).

    Un hallazgo confirmado tiene que poder CONTRASTARSE: quien lea el informe debe poder
    re-ejecutar el paso y ver lo mismo. Por eso aquí se rechaza, para ``state=confirmed``,
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
            "finding 'confirmed' inválido: requiere 'evidence' reproducible "
            "('command'+'output' verbatim, o 'artifact_ref'). No se admite confirmar sin evidencia."
        )

    ref = evidence.get("artifact_ref")
    if isinstance(ref, dict) and ref.get("execution_id") and ref.get("name"):
        return  # evidencia por artefacto staged: suficiente

    command = evidence.get("command")
    output = evidence.get("output")
    if not isinstance(command, str) or not command.strip():
        raise FindingStoreError(
            "finding 'confirmed' inválido: 'evidence.command' debe ser el comando EXACTO "
            "re-ejecutable (el argv tal cual se pasó a kali_run), no una narración."
        )
    if not isinstance(output, str) or len(output.strip()) < _MIN_EVIDENCE_OUTPUT_LEN:
        raise FindingStoreError(
            "finding 'confirmed' inválido: 'evidence.output' debe ser la salida VERBATIM del "
            "comando (request/response crudos), no un resumen; mínimo %d caracteres."
            % _MIN_EVIDENCE_OUTPUT_LEN
        )


def _normalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Valida y normaliza un hallazgo fail-closed; devuelve el dict a persistir.

    Reglas (fail-closed, no se escribe nada si no se cumplen):
      - ``finding`` es un dict.
      - ``title`` no vacío (resumen humano del hallazgo).
      - ``state`` ∈ VALID_STATES.
      - ``phase`` ∈ VALID_PHASES si viene (se tolera ausente/libre, se guarda verbatim).
      - ``severity`` ∈ VALID_SEVERITIES si viene (OPCIONAL; ausente es válido y el
        consumidor deriva best-effort). Un valor fuera de los cinco buckets se rechaza.
      - si ``state`` es ``confirmed``: ``evidence`` debe ser REPRODUCIBLE (ver
        ``_validate_confirmed_evidence``). Un hallazgo sin evidencia contrastable no puede
        marcarse confirmado — bájalo a ``partial``/``hypothesis``.

    Rellena ``id`` (uuid4 hex si falta) y ``recorded_at`` (timestamp del servidor,
    autoritativo: NO se confía en un timestamp provisto por el agente). El resto de
    campos (target, technique_id, severity, category, evidence, confidence, change) se
    guardan tal cual si vienen, para no acoplar el esquema a un consumidor concreto.
    """
    if not isinstance(finding, dict):
        raise FindingStoreError("finding inválido: se espera un objeto JSON.")

    title = finding.get("title")
    if not isinstance(title, str) or not title.strip():
        raise FindingStoreError("finding inválido: 'title' no vacío es obligatorio.")

    state = finding.get("state")
    if state not in VALID_STATES:
        raise FindingStoreError(
            "finding inválido: 'state' debe ser uno de %r (recibido %r)."
            % (list(VALID_STATES), state)
        )

    phase = finding.get("phase")
    if phase is not None and phase not in VALID_PHASES:
        raise FindingStoreError(
            "finding inválido: 'phase' debe ser uno de %r si se indica (recibido %r)."
            % (list(VALID_PHASES), phase)
        )

    # Severidad OPCIONAL y retrocompatible: ausente es válido (el consumidor deriva). Si
    # viene, DEBE ser uno de los cinco buckets canónicos en minúscula — si no, fail-closed
    # (no se guarda "a medias"). Si valida, se persiste verbatim junto al resto de campos.
    severity = finding.get("severity")
    if severity is not None and severity not in VALID_SEVERITIES:
        raise FindingStoreError(
            "finding inválido: 'severity' debe ser uno de %r si se indica (recibido %r)."
            % (list(VALID_SEVERITIES), severity)
        )

    # Un hallazgo CONFIRMADO exige evidencia reproducible (trazabilidad): fail-closed.
    if state == "confirmed":
        _validate_confirmed_evidence(finding.get("evidence"))

    # Copia superficial + campos autoritativos del servidor. El id del agente se respeta
    # si viene bien formado; si no, se genera (nunca se escribe una línea sin id).
    record = dict(finding)
    fid = record.get("id")
    if not isinstance(fid, str) or not fid.strip():
        fid = uuid.uuid4().hex
    record["id"] = fid
    record["title"] = title.strip()
    record["state"] = state
    # recorded_at lo pone SIEMPRE el servidor (no se confía en el del agente).
    record["recorded_at"] = _now_iso()
    return record


def append(engagement_id: str, finding: dict[str, Any]) -> dict[str, Any]:
    """Añade un hallazgo normalizado al JSONL del engagement y devuelve el registro.

    Append atómico a nivel de línea: se serializa el registro a una ÚNICA línea JSON
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
    # O_APPEND garantiza que cada write se posiciona al final de forma atómica; una línea
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
    """Lee los hallazgos del engagement PAGINADOS por índice de línea.

    Patrón cursor idéntico al de ``tool_streaming.read_findings``: ``cursor`` es el
    índice 0-based del primer hallazgo a devolver; se devuelven hasta ``limit`` (o todos
    los restantes si ``limit`` es ``None``). Las líneas ilegibles (JSON corrupto) se
    SALTAN sin reventar — el store es best-effort en lectura.

    Returns:
        ``{"findings": [...], "next_cursor": int, "done": bool, "total": int}``. Un
        ``engagement_id`` sin fichero devuelve página vacía con ``done=True`` y
        ``total=0`` (no revienta).
    """
    try:
        path = _findings_path(engagement_id)
    except ValueError:
        # engagement_id inseguro: no hay nada que leer (fail-closed en lectura también).
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
                continue  # línea corrupta: se salta, no se interpreta
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
