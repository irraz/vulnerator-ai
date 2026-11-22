"""Tests for the server TOOLS (`docker/mcp/vulnerator_mcp_server.py`).

Unlike `test_hermes_api_client`/`test_scope_fold` (SDK-free), this module DOES import
the server, which imports `mcp` (FastMCP). That is why it is marked with
``pytest.importorskip("mcp.server.fastmcp")``: on the dev host without the SDK (or with `mcp` 2.x,
which removes `mcp.server.fastmcp`) these tests are SKIPPED; in the image / venv with `mcp` 1.x
installed they run. Mirror of the "test the shape of the tool response" pattern the reviews ask for.

They cover the shape at TOOL LEVEL (what the MCP client receives), not only the pure decision:
  - Fail-closed / pre-event failure of ``stream_run_events``: BARE envelope ``{"error": {...}}``
    (NOT the batch form), terminal for paging (pins review Finding "unknown-run
    stream error invites a paging spin").
  - ``terminality_error`` carries the FULL envelope ``{"error": {...}}`` (pins review Finding
    "terminality error envelope is inconsistent").
  - The tools are ASYNC and delegate the blocking HTTP call to a thread (pins review Finding
    "synchronous HTTP inside the async tool blocks the event loop"): the test verifies they are
    coroutines and that ``_offload`` runs its argument outside the event loop.
"""

from __future__ import annotations

import inspect
import sys
import threading
from pathlib import Path

import anyio
import pytest

pytest.importorskip("mcp.server.fastmcp")  # without the 1.x SDK (or with mcp 2.x) the module is skipped

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.argv = ["vulnerator_mcp_server"]  # FastMCP must not see pytest's args

import hermes_api_client as hac  # noqa: E402
import vulnerator_mcp_server as srv  # noqa: E402


class _FakeClient:
    """Double for the :8642 client: returns scripted responses and records calls."""

    def __init__(self):
        self.calls = []
        self.get_run_result = {"completed": False, "partial": True}
        self.iter_result = ([], 0, None, hac.STOP_DRAINED)

    def get_run(self, run_id):
        self.calls.append(("get_run", run_id, threading.get_ident()))
        return self.get_run_result

    async def iter_events(self, run_id, *, after_seq=0, max_events=None, wait_seconds=None):
        self.calls.append(("iter_events", run_id, after_seq))
        return self.iter_result


@pytest.fixture()
def fake_client(monkeypatch):
    fc = _FakeClient()
    monkeypatch.setattr(srv, "_client", fc)
    return fc


# ------------------------------------------------------------------ the tools are async


def test_all_run_tools_are_async():
    # The mcp 1.x SDK runs the body of a SYNCHRONOUS tool inline in the event loop; that is why
    # ALL the tools must be coroutines (and delegate the blocking work to a thread).
    for name in ("start_pentest", "get_run_status", "stream_run_events", "steer_run",
                 "stop_run", "health"):
        fn = getattr(srv, name)
        assert inspect.iscoroutinefunction(fn), "%s must be async" % name


def test_offload_runs_off_the_event_loop():
    # _offload must run its function in ANOTHER thread (not the event loop one), so it does not block it.
    loop_thread = {}

    async def _check():
        loop_thread["main"] = threading.get_ident()
        return await srv._offload(lambda: threading.get_ident())

    worker_thread = anyio.run(_check)
    assert worker_thread != loop_thread["main"]


# ------------------------------------------------------------------ stream_run_events: shapes


def test_stream_pre_event_error_returns_bare_envelope(fake_client):
    # Pre-event failure (run_not_found): BARE envelope, NOT the batch form -> terminal for
    # paging (a client iterating over `done` does not retry in a loop).
    envelope = {"error": {"message": "Run not found: run_x", "type": "invalid_request_error",
                          "param": None, "code": "run_not_found"}}
    fake_client.iter_result = ([], 0, envelope, "error")
    out = anyio.run(lambda: srv.stream_run_events("run_x", 0))
    assert out == envelope
    assert "done" not in out and "events" not in out  # NOT the batch form


def test_stream_partial_events_then_error_wraps_under_stream_error(fake_client):
    # If partial events ALREADY arrived before the failure, they are preserved + FULL envelope under
    # stream_error, with done=False.
    partial = [{"event": "message.delta", "seq": 1, "run_id": "run_x"}]
    envelope = {"error": {"message": "boom", "type": "upstream_unreachable",
                          "param": None, "code": "upstream_unreachable"}}
    fake_client.iter_result = (partial, 1, envelope, "error")
    out = anyio.run(lambda: srv.stream_run_events("run_x", 0))
    assert out["events"] == partial
    assert out["next_cursor"] == 1
    assert out["done"] is False
    assert out["stream_error"] == envelope  # FULL envelope, not just the inner object


def test_stream_terminality_error_carries_full_envelope(fake_client):
    # Pins review Finding "terminality error envelope is inconsistent": if the confirmation
    # get_run (after a drain) fails, terminality_error carries the FULL envelope {"error":...},
    # not just the inner object.
    confirm_envelope = {"error": {"message": "cannot reach Hermes", "type": "upstream_unreachable",
                                  "param": None, "code": "upstream_unreachable"}}
    fake_client.iter_result = ([], 0, None, hac.STOP_DRAINED)  # drained without a terminal event
    fake_client.get_run_result = confirm_envelope
    out = anyio.run(lambda: srv.stream_run_events("run_x", 0))
    assert out["done"] is False
    assert out["terminality_error"] == confirm_envelope  # {"error": {...}} FULL
    assert "error" in out["terminality_error"]


def test_stream_terminal_confirm_offloads_get_run(fake_client):
    # The confirmation get_run runs in a worker thread (not in the event loop).
    loop_thread = {}

    async def _run():
        loop_thread["main"] = threading.get_ident()
        return await srv.stream_run_events("run_x", 0)

    fake_client.iter_result = ([], 0, None, hac.STOP_DRAINED)
    fake_client.get_run_result = {"completed": True}
    out = anyio.run(_run)
    assert out["done"] is True
    getrun_calls = [c for c in fake_client.calls if c[0] == "get_run"]
    assert getrun_calls, "a confirmation get_run was expected after the drain"
    assert getrun_calls[0][2] != loop_thread["main"]  # ran outside the event loop


def test_stream_oversized_event_returns_bare_envelope_terminal_for_paging(fake_client):
    # Pins the review 4 blockers at TOOL level: an OVERSIZED event that
    # iter_events reports as an error envelope with events=[] is returned BARE (NOT the batch
    # form), terminal for paging. This way a run.completed with done:false never appears and
    # the payload is never silently lost inside events.
    oversized_env = {"error": {
        "message": "a single SSE event (seq=9, type=run.completed) ... exceeded the ceiling",
        "type": "oversized_event", "param": None, "code": "oversized_event",
        "oversized_event": {"seq": 9, "event": "run.completed",
                            "serialized_bytes": 999_999, "limit_bytes": 524_288},
    }}
    # The client does NOT advance the cursor (next_cursor == after_seq) and sets stop_reason "error".
    fake_client.iter_result = ([], 0, oversized_env, "error")
    out = anyio.run(lambda: srv.stream_run_events("run_x", 0))
    assert out == oversized_env            # BARE envelope verbatim
    assert "done" not in out and "events" not in out  # NOT the batch form
    assert out["error"]["code"] == "oversized_event"
    # The client does NOT confirm terminality from a pre-event error.
    assert not [c for c in fake_client.calls if c[0] == "get_run"]


def test_stream_cap_batch_is_not_done_and_skips_confirm(fake_client):
    # A batch cut by the cap (STOP_CAP) never confirms nor declares done.
    events = [{"event": "message.delta", "seq": 1, "run_id": "run_x"}]
    fake_client.iter_result = (events, 1, None, hac.STOP_CAP)
    out = anyio.run(lambda: srv.stream_run_events("run_x", 0))
    assert out["done"] is False
    assert out["events"] == events and out["next_cursor"] == 1
    assert not [c for c in fake_client.calls if c[0] == "get_run"]  # did NOT confirm
