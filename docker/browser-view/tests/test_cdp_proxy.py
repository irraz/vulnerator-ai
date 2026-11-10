"""Tests de las funciones puras del proxy CDP (sin red)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import cdp_proxy as cp  # noqa: E402


def test_rewrite_request_head_replaces_host():
    head = b"GET /json/version HTTP/1.1\r\nHost: browser-view:9222\r\nAccept: */*\r\n\r\n"
    new, original = cp.rewrite_request_head(head)
    assert b"Host: localhost:9223\r\n" in new
    assert b"browser-view:9222" not in new
    assert original == "browser-view:9222"


def test_rewrite_request_head_case_insensitive_no_host():
    head = b"GET / HTTP/1.1\r\naccept: */*\r\n\r\n"
    new, original = cp.rewrite_request_head(head)
    assert original == "" and new == head


def test_force_close_sets_connection_close_and_strips_keepalive():
    head = b"GET /json HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\n\r\n"
    out = cp.force_close(head)
    assert out.count(b"Connection:") == 1
    assert b"Connection: close\r\n\r\n" in out
    assert b"keep-alive" not in out.lower()


def test_rewrite_json_body_points_ws_back_to_client():
    body = b'{"webSocketDebuggerUrl":"ws://localhost:9223/devtools/browser/abc"}'
    out = cp.rewrite_json_body(body, "browser-view:9222")
    assert b"ws://browser-view:9222/devtools/browser/abc" in out
    assert b"localhost:9223" not in out


def test_rewrite_json_body_also_handles_127_0_0_1():
    body = b'{"url":"ws://127.0.0.1:9223/devtools/page/x"}'
    out = cp.rewrite_json_body(body, "host:9222")
    assert b"ws://host:9222/devtools/page/x" in out


def test_rewrite_json_body_noop_when_same_or_empty():
    body = b'{"x":"ws://localhost:9223/y"}'
    assert cp.rewrite_json_body(body, "") == body
    assert cp.rewrite_json_body(body, "localhost:9223") == body
