"""Log durable de auditoría de ejecuciones de shell cruda (`kali-mcp`, STDLIB PURA).

Qué es: el registro re-ejecutable de CADA ejecución de ``kali_run``/``kali_exec``. Un
fichero JSONL por engagement —``<engagement_id>/session.jsonl`` bajo la raíz del plano
de artefactos (``/artifacts``)— con un registro por línea que contiene el comando EXACTO,
su salida ÍNTEGRA verbatim (no la vista acotada de 2000 líneas que recibe el LLM), el
returncode y timestamps. Es la fuente única para reconstruir/reproducir lo que hizo el
agente contra el target, independiente del transcript de Hermes (que trunca salidas
grandes) y del ring en memoria (capado a ``RING_MAXLEN``).

Por qué existe esta capa: ``shell_exec.run_shell`` devuelve al LLM la salida del ring
(últimas ``RING_MAXLEN`` líneas, protección de contexto). Para auditoría/reproducción hace
falta el stdout/stderr COMPLETO; este módulo lo persiste SIN tocar lo que ve el LLM.

Dónde vive y por qué un módulo aparte: igual que ``finding_store`` / ``artifact_store`` /
``tool_streaming``, usa SOLO la librería estándar (sin ``mcp``) para cubrirse con tests en
el venv de dev. Reutiliza el confinamiento de rutas de ``artifact_store`` (sin ``..`` ni
separadores) para que un ``engagement_id`` manipulado no escape del directorio.

Ciclo de vida / retención: hereda el de ``finding_store`` — persiste en el volumen named
``kali-artifacts``, sin purga automática; lo limpia el operador (o ``docker compose
down -v``). No se define retención propia a propósito (un único modelo mental con los
findings).

Disciplina de seguridad: ``command``/``output`` son DATO NO CONFIABLE (salida verbatim de
una tool contra un target real). Aquí se PERSISTE verbatim; nunca se interpreta ni se
obedecen instrucciones embebidas. El ``output`` se serializa dentro de una ÚNICA línea JSON
(``json.dumps`` escapa los saltos internos), así que el JSONL sigue siendo una-línea-por-
registro aunque la salida tenga miles de líneas.
"""

from __future__ import annotations

import json
import os
from typing import Any

import artifact_store

# Nombre canónico del log de sesión dentro del directorio del engagement.
SESSION_LOG_NAME = "session.jsonl"

# Bucket por defecto cuando el agente NO declara engagement_id (o es inseguro). El eje de
# sesión real se reconstruye aguas abajo cruzando el transcript de Hermes con el
# ``execution_id`` (Hermes NO expone su run_id al agente, así que kali no puede etiquetar
# por sesión; ver docs del diseño auditor).
DEFAULT_ENGAGEMENT = "_unscoped"


def safe_engagement(engagement_id: Any) -> str:
    """Devuelve un ``engagement_id`` confinable, o ``DEFAULT_ENGAGEMENT`` si no lo es.

    Vacío, no-string o con traversal/separadores -> bucket por defecto (fail-open: se
    audita igual, en un directorio seguro, en vez de reventar o escapar de la raíz).
    """
    if not engagement_id or not isinstance(engagement_id, str):
        return DEFAULT_ENGAGEMENT
    try:
        artifact_store.resolve(engagement_id, SESSION_LOG_NAME)
    except ValueError:
        return DEFAULT_ENGAGEMENT
    return engagement_id


def record(engagement_id: Any, entry: dict[str, Any]) -> dict[str, Any]:
    """Añade ``entry`` como una línea JSON al ``session.jsonl`` del engagement.

    Append atómico a nivel de línea (mismo patrón que ``finding_store.append``): el
    registro se serializa a una ÚNICA línea JSON (``json.dumps`` escapa los saltos del
    ``output``) y se escribe con ``O_APPEND`` en una sola llamada ``write``, de modo que
    appends concurrentes de distintos workers (p. ej. varios ``kali_exec`` en background)
    no se entrelacen. El ``engagement_id`` se sanea a un segmento confinable.

    Devuelve el ``entry`` (con el ``engagement_id`` efectivo ya aplicado por el caller).
    """
    eng = safe_engagement(engagement_id)
    path = artifact_store.resolve(eng, SESSION_LOG_NAME)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False) + "\n"
    # O_APPEND: cada write se posiciona al final de forma atómica; una línea entera en un
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
    """Lee los registros del engagement PAGINADOS por índice de línea (para la UI/tests).

    Patrón cursor idéntico a ``finding_store.read``: ``cursor`` es el índice 0-based del
    primer registro a devolver; se devuelven hasta ``limit`` (o todos los restantes si es
    ``None``). Las líneas corruptas (JSON inválido) se SALTAN sin reventar.

    Returns:
        ``{"executions": [...], "next_cursor": int, "done": bool, "total": int}``. Un
        engagement sin fichero (o id inseguro) devuelve página vacía con ``done=True`` y
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
                continue  # línea corrupta: se salta, no se interpreta
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
