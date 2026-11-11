"""Parser for the agent's OODA status line (PURE STDLIB).

SOUL.md forces Hermes to open EVERY response with an exact status line:

    OODA — <PHASE> (step <N>): <one-line description>

That line is the cheapest and most reliable signal of "which phase the loop is in" without
asking the model for anything else. This module extracts it from the assistant text so the
GUI can tag each tool-call, span and finding with the OODA phase/step in which it occurred.

Tolerance (the text is written by an LLM, not a parser): it accepts em, en or normal dashes
(``—`` ``–`` ``-``), surrounding Markdown bold/backticks, upper/lower case and extra
whitespace. ``REPORT`` is accepted in addition to the four phases because SOUL uses it as the
closing phase in the todo_list.

Discipline: the assistant text is UNTRUSTED DATA. Here only a pattern is recognized and
bounded fields are returned; nothing derived from it is ever interpreted or executed.
"""

from __future__ import annotations

import re
from typing import Any

PHASES = ("OBSERVE", "ORIENT", "DECIDE", "ACT", "REPORT")

# Maximum length of the returned description (the line is "one-line" by contract;
# this only bounds anomalous text).
_DESC_MAX = 400

_LINE_RE = re.compile(
    r"""^[\s>*_`#]*            # markdown decorations at the start (quote, bold, italic, code)
        OODA\s*[—–\-:]+\s*      # 'OODA —' (any dash)
        [*_`]*(?P<phase>OBSERVE|ORIENT|DECIDE|ACT|REPORT)[*_`]*
        \s*\(\s*step\s*(?P<step>\d{1,6})\s*\)   # '(step N)'
        [*_`]*\s*[:：\-—–]?[*_`]*\s*         # ':' with bold before or after
        (?P<desc>.*?)[\s*_`]*$
    """,
    re.IGNORECASE | re.VERBOSE,
)


def parse_line(line: str) -> dict[str, Any] | None:
    """Recognizes ONE OODA status line. Returns ``{phase, step, description}`` or None."""
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
    """Extracts ALL OODA status lines from a block of text, in order."""
    if not isinstance(text, str) or "OODA" not in text.upper():
        return []
    out = []
    for raw in text.splitlines():
        hit = parse_line(raw)
        if hit is not None:
            out.append(hit)
    return out
