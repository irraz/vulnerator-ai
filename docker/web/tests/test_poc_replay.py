"""Tests for ``poc_replay`` (OODA chain + reproduction + exports)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import poc_replay  # noqa: E402
from fixtures import synthetic_session as fx  # noqa: E402
from trace_store import TraceStore  # noqa: E402


def _pocs():
    st = TraceStore()
    st.ingest_messages(fx.SID, fx.messages())
    return poc_replay.build_pocs(st.session_events(fx.SID))


def test_one_poc_per_record_finding():
    pocs = _pocs()
    assert [p["finding"]["title"] for p in pocs] == [
        "Boolean SQL injection in /item?id", "Admin panel exposed"]


def test_confirmed_poc_links_real_execution():
    poc = _pocs()[0]
    assert poc["confirmed"] is True and poc["store_status"] == "recorded"
    exe = poc["reproduction"]["execution"]
    assert exe is not None and exe["call_id"] == "call_sqli"
    assert exe["returncode"] == 0 and abs(exe["duration"] - 2.75) < 1e-9
    assert "admin-only" in exe["output"]
    assert poc["phase"] == "ACT" and poc["step"] == 5


def test_rejected_confirmed_without_evidence():
    poc = _pocs()[1]
    assert poc["store_status"] == "rejected" and poc["confirmed"] is False
    assert "evidence" in poc["store_error"]
    assert poc["reproduction"]["execution"] is None
    assert poc["replay"][-1]["stream"] == "err"


def test_chain_contains_ooda_path_and_tools():
    poc = _pocs()[0]
    phases = [s["phase"] for s in poc["ooda_path"]]
    assert phases == ["OBSERVE", "ORIENT", "DECIDE", "ACT", "ACT"]
    tools = [s for s in poc["chain"] if s["kind"] == "tool.call"]
    assert [t["tool"] for t in tools] == ["kali_run", "browser_navigate", "kali_run"]
    assert tools[0]["result"]["status"] == "ok"


def test_replay_script_shape():
    frames = _pocs()[0]["replay"]
    assert frames[0]["stream"] == "note"
    assert any(f["stream"] == "cmd" and f["text"].startswith("$ curl") for f in frames)
    assert frames[-1]["stream"] == "ok"
    ts = [f["t"] for f in frames]
    assert ts == sorted(ts) and ts[-1] <= 30


def test_asciicast_is_valid_v2_and_neutralizes_escapes():
    poc = _pocs()[0]
    poc["replay"].append({"t": 99.0, "stream": "out", "text": "evil \x1b]0;pwn\x07"})
    cast = poc_replay.to_asciicast(poc).splitlines()
    header = json.loads(cast[0])
    assert header["version"] == 2 and header["width"] > 0
    for line in cast[1:]:
        t, kind, data = json.loads(line)
        assert kind == "o" and isinstance(t, (int, float))
    assert "\x1b]0;pwn" not in poc_replay.to_asciicast(poc)


def test_markdown_has_command_and_fence_safety():
    poc = _pocs()[0]
    md = poc_replay.to_markdown(poc)
    assert fx.SQLI_CMD in md and "## Reproduction" in md and "OBSERVE" in md
    poc["reproduction"]["execution"]["output"] = "```\nbreakout"
    md = poc_replay.to_markdown(poc)
    assert "````" in md  # the fence grows so output containing ``` does not break the block


def test_command_matching_is_whitespace_insensitive():
    st = TraceStore()
    msgs = fx.messages()
    find_args = json.loads(json.loads(msgs[8]["tool_calls"])[0]["function"]["arguments"])
    find_args["evidence"]["command"] = "  " + fx.SQLI_CMD.replace(" -H", "   -H") + " "
    calls = json.loads(msgs[8]["tool_calls"])
    calls[0]["function"]["arguments"] = json.dumps(find_args)
    msgs[8]["tool_calls"] = json.dumps(calls)
    st.ingest_messages(fx.SID, msgs)
    poc = poc_replay.build_pocs(st.session_events(fx.SID))[0]
    assert poc["reproduction"]["execution"]["call_id"] == "call_sqli"
