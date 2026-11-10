"""Parser de la línea de estado OODA del agente (STDLIB PURA).

El SOUL.md obliga a Hermes a abrir CADA respuesta con una línea de estado exacta:

    OODA — <PHASE> (step <N>): <descripción de una línea>

Esa línea es la señal más barata y fiable de "en qué fase está el bucle" sin pedirle nada
más al modelo. Este módulo la extrae del texto del asistente para que la GUI pueda etiquetar
cada tool-call, span y hallazgo con la fase/paso OODA en la que ocurrió.

Tolerancia (el texto lo escribe un LLM, no un parser): admite guion largo, medio o normal
(``—`` ``–`` ``-``), negritas/backticks de Markdown alrededor, mayúsculas/minúsculas y
espacios extra. ``REPORT`` se acepta además de las cuatro fases porque el SOUL lo usa como
fase de cierre en el todo_list.

Disciplina: el texto del asistente es DATO NO CONFIABLE. Aquí solo se reconoce un patrón y
se devuelven campos acotados; nunca se interpreta ni se ejecuta nada derivado de él.
"""

from __future__ import annotations

import re
from typing import Any

PHASES = ("OBSERVE", "ORIENT", "DECIDE", "ACT", "REPORT")

# Longitud máxima de la descripción devuelta (la línea es "de una línea" por contrato;
# esto solo acota un texto anómalo).
_DESC_MAX = 400

_LINE_RE = re.compile(
    r"""^[\s>*_`#]*            # adornos markdown al inicio (quote, negrita, cursiva, código)
        OODA\s*[—–\-:]+\s*      # 'OODA —' (cualquier guion)
        [*_`]*(?P<phase>OBSERVE|ORIENT|DECIDE|ACT|REPORT)[*_`]*
        \s*\(\s*step\s*(?P<step>\d{1,6})\s*\)   # '(step N)'
        [*_`]*\s*[:：\-—–]?[*_`]*\s*         # ':' con negritas antes o después
        (?P<desc>.*?)[\s*_`]*$
    """,
    re.IGNORECASE | re.VERBOSE,
)


def parse_line(line: str) -> dict[str, Any] | None:
    """Reconoce UNA línea de estado OODA. Devuelve ``{phase, step, description}`` o None."""
    if not isinstance(line, str):
        return None
    m = _LINE_RE.match(line.strip())
    if not m:
        return None
    desc = m.group("desc").strip()
    if len(desc) > _DESC_MAX:
        desc = desc[: _DESC_MAX - 1] + "…"
    return {
        "phase": m.group("phase").upper(),
        "step": int(m.group("step")),
        "description": desc,
    }


def parse_text(text: str) -> list[dict[str, Any]]:
    """Extrae TODAS las líneas de estado OODA de un bloque de texto, en orden."""
    if not isinstance(text, str) or "OODA" not in text.upper():
        return []
    out = []
    for raw in text.splitlines():
        hit = parse_line(raw)
        if hit is not None:
            out.append(hit)
    return out
