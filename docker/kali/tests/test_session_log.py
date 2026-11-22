"""Stdlib-only tests of the per-engagement audit log (`docker/kali/session_log.py`).

They do not import `mcp`/`anyio`: only standard library + pytest. They verify:
  - ``record`` persists a record as a SINGLE JSON line (even if the output has
    thousands of lines: newlines are escaped inside the JSON string);
  - ``read`` paginates by cursor and skips corrupt lines;
  - ``safe_engagement`` falls back to ``_unscoped`` for empty/non-string/traversal ids, and the
    file does NOT escape the staging root;
  - CONCURRENT appends (O_APPEND) do not interleave: N lines, all valid JSON.
"""

from __future__ import annotations

import json
import sys
import threading
from pathlib import Path

import pytest

# The module under test lives in docker/kali/ (alongside the MCP server, which is NOT imported
# here because it pulls in `mcp`/`anyio`). We add it to the path explicitly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import session_log  # noqa: E402


@pytest.fixture()
def staging(tmp_path, monkeypatch):
    """Points the staging root to a tmp dir per test (env read at call time)."""
    monkeypatch.setenv("KALI_ARTIFACTS_DIR", str(tmp_path))
    return tmp_path


def _entry(**over):
    base = {
        "execution_id": "exec-1",
        "engagement_id": "eng-1",
        "tool": "kali_run",
        "command": "id",
        "status": "done",
        "returncode": 0,
        "output": "[stdout] uid=0(root)\n",
    }
    base.update(over)
    return base


# ------------------------------------------------------------------ record / read


def test_record_writes_single_json_line_under_engagement(staging):
    session_log.record("eng-1", _entry())

    path = staging / "eng-1" / session_log.SESSION_LOG_NAME
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    doc = json.loads(lines[0])
    assert doc["execution_id"] == "exec-1"
    assert doc["command"] == "id"


def test_record_multiline_output_stays_one_physical_line(staging):
    # Output with 5000 newlines: json.dumps escapes them -> ONE physical line in the file.
    big = "\n".join(f"[stdout] line-{i}" for i in range(5000)) + "\n"
    session_log.record("eng-1", _entry(output=big, total_lines=5000))

    path = staging / "eng-1" / session_log.SESSION_LOG_NAME
    raw = path.read_text(encoding="utf-8")
    assert raw.count("\n") == 1  # a single JSON line terminated by \n
    doc = json.loads(raw)
    # The complete output is retrieved intact after parsing.
    assert doc["output"].count("\n") == 5000
    assert "[stdout] line-4999" in doc["output"]


def test_read_paginates_in_order_and_reports_total(staging):
    for i in range(5):
        session_log.record("eng-1", _entry(execution_id=f"exec-{i}"))

    page = session_log.read("eng-1", cursor=0, limit=2)
    assert [e["execution_id"] for e in page["executions"]] == ["exec-0", "exec-1"]
    assert page["next_cursor"] == 2
    assert page["done"] is False
    assert page["total"] == 5

    tail = session_log.read("eng-1", cursor=4)
    assert [e["execution_id"] for e in tail["executions"]] == ["exec-4"]
    assert tail["done"] is True


def test_read_unknown_engagement_is_empty_done(staging):
    page = session_log.read("never-written")
    assert page["executions"] == []
    assert page["done"] is True
    assert page["total"] == 0


def test_read_skips_corrupt_lines(staging):
    session_log.record("eng-1", _entry(execution_id="good-1"))
    path = staging / "eng-1" / session_log.SESSION_LOG_NAME
    with path.open("a", encoding="utf-8") as handle:
        handle.write("this is not json\n")
    session_log.record("eng-1", _entry(execution_id="good-2"))

    page = session_log.read("eng-1")
    ids = [e["execution_id"] for e in page["executions"]]
    assert ids == ["good-1", "good-2"]  # the corrupt line is skipped
    assert page["total"] == 2


# ------------------------------------------------------------------ safe_engagement


@pytest.mark.parametrize("bad", ["", None, 123, "..", "a/b", "a\\b", "x\x00y"])
def test_unsafe_engagement_falls_back_to_unscoped(staging, bad):
    assert session_log.safe_engagement(bad) == session_log.DEFAULT_ENGAGEMENT


def test_record_with_traversal_id_stays_inside_root(staging):
    # A traversal engagement_id does NOT escape: it falls to _unscoped inside the root.
    session_log.record("../escape", _entry(engagement_id="../escape"))

    escaped = staging.parent / "escape" / session_log.SESSION_LOG_NAME
    assert not escaped.exists()
    fallback = staging / session_log.DEFAULT_ENGAGEMENT / session_log.SESSION_LOG_NAME
    assert fallback.is_file()


def test_valid_engagement_is_preserved(staging):
    assert session_log.safe_engagement("engagement-10.0.0.5") == "engagement-10.0.0.5"


# ------------------------------------------------------------------ concurrencia


def test_concurrent_appends_do_not_interleave(staging):
    # 20 threads x 25 records: O_APPEND guarantees whole lines without interleaving.
    def worker(wid: int) -> None:
        for i in range(25):
            session_log.record("eng-1", _entry(execution_id=f"w{wid}-{i}"))

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    path = staging / "eng-1" / session_log.SESSION_LOG_NAME
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 500
    # Each line is valid, complete JSON (none broken by interleaving).
    for line in lines:
        json.loads(line)
