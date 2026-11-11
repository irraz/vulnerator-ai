"""Tests for the ``vulnerator_watch`` CLI (SSE parser, terminal sanitizing and formatting)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import vulnerator_watch as vw  # noqa: E402

P = vw.Painter(False)


def test_parse_sse_messages_ids_and_comments():
    wire = ["retry: 2000", "", ": ping", "", "id: 7", "event: ev", 'data: {"a":1}', "",
            "id: 8", "event: ev", "data: line1", "data: line2", ""]
    got = list(vw.parse_sse(wire))
    assert got == [("7", "ev", '{"a":1}'), ("8", "ev", "line1\nline2")]


def test_sanitize_neutralizes_terminal_escapes():
    evil = "ok\x1b]0;owned\x07\x1b[2J\x9b31m"
    clean = vw.sanitize(evil)
    assert "\x1b" not in clean and "\x07" not in clean and "\x9b" not in clean
    assert vw.sanitize("tab\tand text") == "tab\tand text"


def test_format_ooda_and_call_and_result():
    ooda = vw.format_event({"kind": "ooda", "phase": "ACT", "step": 4, "text": "probe"}, P)
    assert ooda[-1] == "[ACT 4] probe"
    call = vw.format_event({"kind": "tool.call", "tool_display": "kali_run", "category": "shell",
                            "summary": "nmap -sV 192.0.2.10"}, P)
    assert call == ["$ kali_run nmap -sV 192.0.2.10"]
    res = vw.format_event({"kind": "tool.result", "tool_display": "kali_run", "ts": 12.5,
                           "text": json.dumps({"status": "done", "output": "a\nb\nc"})},
                          P, output_lines=2, call_ts=10.0)
    assert res[0].strip().startswith("✓ 2.50s") and res[1].endswith("a") and "1 more lines" in res[-1]


def test_format_hides_reasoning_and_pure_ooda_assistant_text():
    assert vw.format_event({"kind": "reasoning", "text": "x"}, P, reasoning=False) == []
    assert vw.format_event({"kind": "assistant", "text": "OODA — ACT (step 1): x"}, P) == []
    assert vw.format_event({"kind": "web.request"}, P) == []


def test_untrusted_output_is_sanitized_in_result_lines():
    res = vw.format_event({"kind": "tool.result", "tool": "t",
                           "text": json.dumps({"output": "pwn\x1b[2J"})}, P)
    assert all("\x1b" not in line for line in res)


def test_output_text_unwraps():
    assert vw.output_text(json.dumps({"result": {"output": "hi"}})) == "hi"
    assert vw.output_text("plain") == "plain"
