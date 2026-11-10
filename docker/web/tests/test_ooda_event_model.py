"""Tests de ``ooda_parse`` y ``event_model`` (stdlib pura, sin red)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import event_model as em  # noqa: E402
import ooda_parse  # noqa: E402
from fixtures import synthetic_session as fx  # noqa: E402
from trace_store import TraceStore  # noqa: E402


def test_ooda_line_variants():
    assert ooda_parse.parse_line("OODA — OBSERVE (step 1): recon") == {
        "phase": "OBSERVE", "step": 1, "description": "recon"}
    bold = ooda_parse.parse_line("**OODA – act (step 12):** exploit")
    assert bold == {"phase": "ACT", "step": 12, "description": "exploit"}
    assert ooda_parse.parse_line("**OODA — ORIENT (step 2)**: map it")["description"] == "map it"
    assert ooda_parse.parse_line("> `OODA - DECIDE (step 3)`: pick vector")["step"] == 3
    assert ooda_parse.parse_line("OODA — REPORT (step 9): hand-off")["phase"] == "REPORT"
    assert ooda_parse.parse_line("the OODA loop is great") is None
    assert ooda_parse.parse_line("OODA — PANIC (step 1): nope") is None


def test_parse_text_multiple_and_cheap_reject():
    txt = "OODA — ORIENT (step 2): a\nbody\nOODA — DECIDE (step 3): b"
    assert [h["step"] for h in ooda_parse.parse_text(txt)] == [2, 3]
    assert ooda_parse.parse_text("no status line here") == []


def test_tool_names_and_categories():
    assert em.tool_display_name("mcp_kali_kali_run") == "kali_run"
    assert em.tool_display_name("mcp_playwright_browser_click") == "browser_click"
    assert em.tool_category("mcp_kali_kali_run") == "shell"
    assert em.tool_category("mcp_playwright_browser_navigate") == "browser"
    assert em.tool_category("mcp_kali_record_finding") == "finding"
    assert em.tool_category("mcp_kali_caido_history") == "web"
    assert em.tool_category("kanban_create") == "tracking"
    assert em.tool_category("mcp_kali_dns_recon") == "recon"
    assert em.tool_category("something_else") == "tool"


def test_parse_tool_calls_variants():
    openai = json.dumps([{"id": "c1", "function": {"name": "x", "arguments": '{"a": 1}'}}])
    assert em.parse_tool_calls(openai) == [{"id": "c1", "index": 0, "name": "x", "args": {"a": 1}}]
    flat = [{"call_id": "c2", "name": "y", "args": {"b": 2}}]
    assert em.parse_tool_calls(flat)[0]["args"] == {"b": 2}
    assert em.parse_tool_calls("not json") == []
    bad_args = [{"id": "c3", "function": {"name": "z", "arguments": "{broken"}}]
    assert em.parse_tool_calls(bad_args)[0]["args"] == "{broken"


def test_message_to_events_assistant_with_tool_call():
    msgs = fx.messages()
    evs = em.message_to_events(fx.SID, msgs[1])
    kinds = [e["kind"] for e in evs]
    assert kinds == ["ooda", "reasoning", "assistant", "tool.call"]
    call = evs[-1]
    assert call["call_id"] == "call_nmap"
    assert call["tool_display"] == "kali_run"
    assert call["summary"] == "nmap -sV -p 80,443 192.0.2.10"
    assert evs[0]["phase"] == "OBSERVE" and evs[0]["step"] == 1
    assert len({e["key"] for e in evs}) == len(evs)


def test_reasoning_belongs_to_its_own_ooda_step():
    """El razonamiento de un mensaje se emite DESPUÉS de su línea OODA y, en el store, hereda
    la fase/step de ESE paso (no la del anterior). Fixture sintética (RFC 5737)."""
    msgs = [
        {"id": 1, "role": "assistant", "timestamp": 100.0,
         "content": "OODA — OBSERVE (step 1): map services on 192.0.2.10"},
        {"id": 2, "role": "assistant", "timestamp": 110.0,
         "content": "OODA — ACT (step 2): probe the login form",
         "reasoning": "The login form at http://192.0.2.10/login is the cheapest entry point."},
    ]
    evs = em.messages_to_events(fx.SID, msgs)
    assert [e["kind"] for e in evs] == ["ooda", "assistant", "ooda", "reasoning", "assistant"]
    st = TraceStore()
    st.upsert_session(fx.session_meta())
    st.ingest_messages(fx.SID, msgs)
    stored = st.session_events(fx.SID)
    reasoning = [e for e in stored if e["kind"] == "reasoning"][0]
    assert (reasoning["phase"], reasoning["step"]) == ("ACT", 2)


def test_tool_result_and_error_detection():
    msgs = fx.messages()
    ok = em.message_to_events(fx.SID, msgs[2])[0]
    assert ok["kind"] == "tool.result" and ok["call_id"] == "call_nmap" and not ok["error"]
    oos = em.message_to_events(fx.SID, msgs[-1])[0]
    assert oos["error"] is True
    rejected = em.message_to_events(fx.SID, msgs[11])[0]
    assert rejected["error"] is True


def test_returncode_nonzero_is_not_error():
    text = json.dumps({"status": "done", "returncode": 1, "output": "no matches"})
    assert em.looks_like_error(text) is False


def test_unwrap_result_wrappers():
    inner = {"status": "done", "returncode": 0, "output": "hi"}
    assert em.unwrap_result(json.dumps(inner)) == inner
    assert em.unwrap_result(json.dumps({"result": inner})) == inner
    parts = [{"type": "text", "text": json.dumps(inner)}]
    assert em.unwrap_result(json.dumps(parts)) == inner
    assert em.unwrap_result("plain text") is None
    assert em.tool_output_text(json.dumps({"result": inner})) == "hi"
    assert em.tool_output_text("raw") == "raw"


def test_clip_and_one_line():
    text, trunc = em.clip("x" * 10, 4)
    assert text == "xxxx" and trunc is True
    assert em.one_line("a\n  b\tc") == "a b c"
    assert len(em.one_line("y" * 1000, 50)) == 50


def test_content_parts_and_untrusted_html_kept_as_text():
    msg = {"id": 99, "role": "user", "timestamp": 1.0,
           "content": [{"type": "text", "text": "<img src=x onerror=alert(1)>"}]}
    ev = em.message_to_events("s", msg)[0]
    assert ev["text"] == "<img src=x onerror=alert(1)>"  # verbatim: el frontend lo pinta como texto
