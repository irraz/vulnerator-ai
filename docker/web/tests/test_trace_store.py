"""Tests for ``trace_store`` (in-memory SQLite, synthetic fixtures)."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fixtures import synthetic_session as fx  # noqa: E402
from trace_store import TraceStore, web_entry_to_event  # noqa: E402


def _loaded():
    st = TraceStore()
    st.upsert_session(fx.session_meta())
    st.ingest_messages(fx.SID, fx.messages())
    return st


def test_ingest_is_idempotent():
    st = _loaded()
    before = st.max_seq()
    again = st.ingest_messages(fx.SID, fx.messages())
    assert again == [] and st.max_seq() == before


def test_incremental_ingest_only_new_messages():
    st = TraceStore()
    msgs = fx.messages()
    first = st.ingest_messages(fx.SID, msgs[:3])
    second = st.ingest_messages(fx.SID, msgs)
    assert first and second
    assert min(e["seq"] for e in second) > max(e["seq"] for e in first)


def test_phase_tagging_follows_ooda_lines():
    st = _loaded()
    calls = {e["call_id"]: e for e in st.events(0, session_id=fx.SID, kinds=["tool.call"])}
    assert calls["call_nmap"]["phase"] == "OBSERVE"
    assert calls["call_nav"]["phase"] == "ORIENT"
    assert calls["call_sqli"]["phase"] == "ACT" and calls["call_sqli"]["step"] == 4
    assert st.session(fx.SID)["last_phase"] == "ACT"


def test_spans_durations_and_status():
    st = _loaded()
    spans = {s["call_id"]: s for s in st.spans(fx.SID)}
    assert spans["call_nmap"]["duration"] == 12.5
    assert spans["call_nmap"]["status"] == "ok"
    assert spans["call_oos"]["status"] == "error"
    assert spans["call_bad"]["status"] == "error"
    assert abs(spans["call_sqli"]["duration"] - 2.75) < 1e-9


def test_running_span_until_result_arrives():
    st = TraceStore()
    msgs = fx.messages()
    st.ingest_messages(fx.SID, msgs[:2])
    assert st.spans(fx.SID)[0]["status"] == "running"
    st.ingest_messages(fx.SID, msgs[:3])
    assert st.spans(fx.SID)[0]["status"] == "ok"


def test_trace_summary_aggregates():
    st = _loaded()
    summary = st.trace_summary(fx.SID)
    assert summary["spans"] == 6 and summary["errors"] == 2 and summary["running"] == 0
    tools = {t["tool"]: t for t in summary["tools"]}
    assert tools["kali_run"]["calls"] == 3
    assert tools["record_finding"]["errors"] == 1


def test_list_sessions_counters():
    st = _loaded()
    row = st.list_sessions()[0]
    assert row["id"] == fx.SID and row["spans"] == 6 and row["findings"] == 2
    assert row["cost_usd"] == 0.042


def test_upsert_session_reports_change():
    st = TraceStore()
    assert st.upsert_session(fx.session_meta()) is True
    assert st.upsert_session(fx.session_meta()) is False
    assert st.upsert_session(fx.session_meta(message_count=20)) is True


def test_events_cursor_kinds_and_text_limit():
    st = _loaded()
    all_evs = st.events(0, session_id=fx.SID)
    assert [e["seq"] for e in all_evs] == sorted(e["seq"] for e in all_evs)
    mid = all_evs[5]["seq"]
    assert all(e["seq"] > mid for e in st.events(mid, session_id=fx.SID))
    clipped = st.events(0, session_id=fx.SID, kinds=["tool.result"], text_limit=10)
    assert all(len(e.get("text", "")) <= 10 for e in clipped)
    assert st.events(0, kinds=["nope"])  # unknown kind is ignored (does not filter to empty)


def test_web_ingest_dedup_and_mapping():
    st = TraceStore()
    new = st.ingest_web(fx.caido_entries())
    assert len(new) == 2 and st.ingest_web(fx.caido_entries()) == []
    ev = web_entry_to_event(fx.caido_entries()[1])
    assert ev["extra"]["url"] == "https://shop.example.com/login"
    assert ev["extra"]["status"] is None
    first = web_entry_to_event(fx.caido_entries()[0])
    assert first["extra"]["url"] == "http://shop.example.com/item"
    assert abs(first["ts"] - (fx.T0 + 18)) < 0.01


def test_tail_events_returns_last_n_ascending():
    st = _loaded()
    tail = st.tail_events(fx.SID, 3)
    assert len(tail) == 3 and tail[-1]["seq"] == st.max_seq()
