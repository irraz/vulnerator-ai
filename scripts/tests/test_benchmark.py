"""Tests for the portable benchmark harness (manifest, runner, criteria, CLI).

They never start the real benchmark (no tokens): the API-facing tests either use
pure functions or run the CLI against a dead port to prove the clean failure.
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, cast

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
BENCH = SCRIPTS / "benchmark"
RUNNER = BENCH / "run_benchmark.py"
MANIFEST = BENCH / "benchmark.json"


def _load_runner():
    spec = importlib.util.spec_from_file_location("run_benchmark", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rb = _load_runner()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _proc(returncode: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(["python3"], returncode, stdout, stderr)


# --------------------------------------------------------------------------- # runner


def test_runner_is_stdlib_only():
    import ast

    tree = ast.parse(RUNNER.read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.add(node.module.split(".")[0])
    third_party = sorted(name for name in imported if name not in sys.stdlib_module_names)
    assert third_party == []


# --------------------------------------------------------------------------- # manifest


def test_manifest_loads_and_validates():
    manifest = rb.load_manifest(MANIFEST)
    assert manifest["benchmark_version"] == 1
    assert isinstance(manifest["tasks"], list)
    assert len(manifest["tasks"]) == 2
    for task in manifest["tasks"]:
        for field in ("id", "lab", "prompt", "target", "criterion", "timeout", "tags", "enabled"):
            assert field in task, f"{task.get('id')} is missing {field}"


def test_manifest_is_plain_json():
    reference = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert rb.load_manifest(MANIFEST) == reference


def test_manifest_sha256_is_stable():
    assert rb.manifest_sha256(MANIFEST) == rb.manifest_sha256(MANIFEST)
    assert len(rb.manifest_sha256(MANIFEST)) == 64


def test_looney_task_is_enabled_with_the_startup_prompt():
    manifest = rb.load_manifest(MANIFEST)
    task = rb.select_task(manifest["tasks"], "looney-tunables-ctf")
    assert task is not None
    assert task["enabled"] is True
    assert task["criterion"] == "flag"
    assert task["lab"] == "looney-tunables-ctf"
    prompt = task["prompt"]
    assert "Target: ubuntu-server-01" in prompt
    assert "escalate privileges to root and read /root/flag.txt" in prompt
    assert "Start the OODA loop." in prompt


def test_php2shell_task_is_disabled_with_the_network_note():
    manifest = rb.load_manifest(MANIFEST)
    task = rb.select_task(manifest["tasks"], "php2shell-lab")
    assert task is not None
    assert task["enabled"] is False
    assert task["criterion"] == "rce_evidence"
    assert "vulnerator-ai_default" in task["note"]


@pytest.mark.parametrize(
    "text",
    [
        "[]",
        '{"benchmark_version": 1, "tasks": []}',
        '{"benchmark_version": 1, "tasks": [{}]}',
        '{"benchmark_version": 1, "tasks": [{"id": "x", "lab": "y", "prompt": "p", '
        '"target": "t", "criterion": "nope", "timeout": 10, "enabled": true}]}',
        '{"benchmark_version": 1, "tasks": [{"id": "x", "lab": "y", "prompt": "p", '
        '"target": "t", "criterion": "flag", "timeout": 0, "enabled": true}]}',
        '{"benchmark_version": 1, "tasks": [{"id": "x", "lab": "y", "prompt": "p", '
        '"target": "t", "criterion": "flag", "timeout": 10, "enabled": "yes-please"}]}',
        '{"benchmark_version": 1, "tasks": [{"id": "x", "lab": "y", "prompt": "p", '
        '"target": "t", "criterion": "flag", "timeout": 10, "enabled": true, '
        '"tags": "nope"}]}',
        '{"benchmark_version": 1, "tasks": [{"id": "a/b", "lab": "y", "prompt": "p", '
        '"target": "t", "criterion": "flag", "timeout": 10, "enabled": true}]}',
        '{"benchmark_version": 1, "tasks": [{"id": "..", "lab": "y", "prompt": "p", '
        '"target": "t", "criterion": "flag", "timeout": 10, "enabled": true}]}',
        '{"benchmark_version": 1, "tasks": [{"id": "x", "lab": "y\\\\z", "prompt": "p", '
        '"target": "t", "criterion": "flag", "timeout": 10, "enabled": true}]}',
    ],
)
def test_manifest_type_errors_raise_manifest_error(text):
    with pytest.raises(rb.ManifestError):
        rb.validate_manifest(json.loads(text))


def test_validate_manifest_rejects_non_mapping():
    with pytest.raises(rb.ManifestError):
        rb.validate_manifest(["not", "a", "mapping"])


def test_load_manifest_reports_invalid_json_cleanly(tmp_path):
    bad = tmp_path / "benchmark.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(rb.ManifestError) as excinfo:
        rb.load_manifest(bad)
    assert "invalid JSON" in str(excinfo.value)


def test_load_manifest_reports_missing_file_cleanly(tmp_path):
    with pytest.raises(rb.ManifestError):
        rb.load_manifest(tmp_path / "absent.json")


# --------------------------------------------------------------------------- # run parser


@pytest.mark.parametrize(
    ("run_obj", "expected"),
    [
        ({"status": "completed"}, True),
        ({"status": "failed"}, True),
        ({"status": "cancelled"}, True),
        ({"status": "interrupted"}, True),
        ({"status": "running"}, False),
        ({"completed": True}, True),
        ({"interrupted": True}, True),
        ({"completed": "true"}, False),
        ({"completed": 1}, False),
        (["not", "a", "mapping"], False),
        (None, False),
    ],
)
def test_is_terminal(run_obj, expected):
    assert rb.is_terminal(run_obj) is expected


def test_run_status_normalizes():
    assert rb.run_status({"status": "COMPLETED"}) == "completed"
    assert rb.run_status({"completed": True}) == "completed"
    assert rb.run_status({"interrupted": True}) == "cancelled"
    assert rb.run_status({"foo": "bar"}) == "unknown"
    assert rb.run_status(None) == "unknown"


def test_count_tool_steps_dedupes_by_call_id():
    events = [
        {"event": "tool.started", "tool_call_id": "c1"},
        {"event": "tool.completed", "tool_call_id": "c1"},
        {"event": "tool.started", "tool_call_id": "c2"},
        {"event": "tool.completed", "tool_call_id": "c2"},
        {"event": "message.delta", "text": "noise"},
        "not-a-mapping",
    ]
    assert rb.count_tool_steps(events) == 2


def test_count_tool_steps_counts_completed_without_call_id():
    events = [
        {"event": "tool.completed"},
        {"event": "tool.completed"},
        {"event": "tool.started"},
    ]
    assert rb.count_tool_steps(events) == 2


def test_count_tool_steps_returns_none_without_tool_events():
    assert rb.count_tool_steps([]) is None
    assert rb.count_tool_steps([{"event": "message.delta", "text": "hi"}]) is None
    assert rb.count_tool_steps(None) is None
    assert rb.count_tool_steps("not-a-list") is None


@pytest.mark.parametrize(
    ("run_obj", "expected"),
    [
        ({"usage": {"total_tokens": 1234}}, 1234),
        ({"usage": {"input_tokens": 100, "output_tokens": 200}}, 300),
        ({"total_tokens": 55}, 55),
        ({"usage": {"input_tokens": "x"}}, None),
        ({"usage": "none"}, None),
        ({}, None),
        (None, None),
    ],
)
def test_extract_tokens(run_obj, expected):
    assert rb.extract_tokens(run_obj) == expected


@pytest.mark.parametrize(
    ("run_obj", "expected"),
    [
        ({"model": "provider/served"}, "provider/served"),
        ({"usage": {"model": "provider/usage-model"}}, "provider/usage-model"),
        ({"model_name": "provider/named"}, "provider/named"),
        ({"model": "  "}, None),
        ({}, None),
        (None, None),
    ],
)
def test_extract_served_model(run_obj, expected):
    assert rb.extract_served_model(run_obj) == expected


def test_extract_served_model_from_events():
    events = [{"event": "run.started", "model": "provider/from-events"}]
    assert rb.extract_served_model({}, events) == "provider/from-events"
    assert rb.extract_served_model({}, []) is None


# --------------------------------------------------------------------------- # criteria


def test_check_flag_criterion_reads_the_run_output():
    ok, detail = rb.check_flag_criterion(
        {"run_id": "run_1", "output": "[CAPTURED] CTF{looney_tunables_success}"}, [], "run_1"
    )
    assert ok is True
    assert "CTF{" in detail


def test_check_flag_criterion_reads_events_of_the_same_run():
    events = [
        {"event": "tool.completed", "run_id": "run_1", "output": "CTF{from_events}"},
    ]
    ok, detail = rb.check_flag_criterion({"run_id": "run_1"}, events, "run_1")
    assert ok is True
    assert "CTF{from_events}" in detail


def test_check_flag_criterion_ignores_other_runs():
    events = [
        {"event": "tool.completed", "run_id": "run_other", "output": "CTF{wrong_run}"},
    ]
    assert rb.check_flag_criterion({"run_id": "run_1"}, events, "run_1")[0] is False
    assert rb.check_flag_criterion(
        {"run_id": "run_other", "output": "CTF{wrong_run}"}, [], "run_1"
    )[0] is False


def test_check_flag_criterion_without_flag_is_false():
    ok, detail = rb.check_flag_criterion({"output": "nothing here"}, [], "run_1")
    assert ok is False
    assert "no CTF" in detail


def test_check_rce_evidence_requires_confirmed_uid_evidence():
    confirmed = {
        "id": "f1",
        "state": "confirmed",
        "evidence": {"command": "id", "output": "uid=33(www-data) gid=33(www-data)"},
    }
    assert rb.check_rce_evidence({}, [confirmed])[0] is True
    assert rb.check_rce_evidence({}, [dict(confirmed, state="partial")])[0] is False
    assert rb.check_rce_evidence(
        {}, [dict(confirmed, evidence={"command": "id", "output": "no"})]
    )[0] is False
    assert rb.check_rce_evidence({}, ["not-a-mapping"])[0] is False
    assert rb.check_rce_evidence({})[0] is False


def test_check_rce_evidence_does_not_read_run_findings():
    """GET /v1/runs/{id} never returns a `findings` field: it must not be read."""
    confirmed = {
        "id": "f1",
        "state": "confirmed",
        "evidence": {"command": "id", "output": "uid=0(root) gid=0(root)"},
    }
    assert rb.check_rce_evidence({"findings": [confirmed]}, [], None)[0] is False


def test_check_rce_evidence_reads_jsonl(tmp_path):
    path = tmp_path / "findings.jsonl"
    path.write_text(
        json.dumps({"id": "f1", "state": "confirmed", "evidence": {"output": "uid=0(root)"}}) + "\n"
        + "not json\n",
        encoding="utf-8",
    )
    ok, detail = rb.check_rce_evidence({}, [], findings_path=path)
    assert ok is True
    assert "f1" in detail


def test_check_rce_evidence_reads_nested_run_output():
    run_obj = {
        "run_id": "run_1",
        "output": {
            "findings": [
                {
                    "id": "f9",
                    "state": "confirmed",
                    "evidence": {"command": "id", "output": "uid=0(root) gid=0(root)"},
                }
            ]
        },
    }
    ok, detail = rb.check_rce_evidence(run_obj, [], None)
    assert ok is True
    assert "f9" in detail


def test_verify_criterion_unknown_is_clean():
    ok, detail = rb.verify_criterion({"criterion": "nope"}, {}, [], "run_1")
    assert ok is False
    assert "unknown criterion" in detail


# --------------------------------------------------------------------------- # lab preflight and reset


def _lab_root(tmp_path: Path, lab: str = "looney-tunables-ctf") -> Path:
    lab_dir = tmp_path / "labs" / lab
    lab_dir.mkdir(parents=True)
    (lab_dir / "run_agent_test.py").write_text("# stub\n", encoding="utf-8")
    (lab_dir / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
    return tmp_path


def test_preflight_missing_lab_dir(tmp_path):
    ok, detail = rb.preflight_lab({"lab": "nope", "criterion": "flag"}, tmp_path)
    assert ok is False
    assert "lab directory not found" in detail


def test_preflight_missing_runner(tmp_path):
    (tmp_path / "labs" / "looney-tunables-ctf").mkdir(parents=True)
    ok, detail = rb.preflight_lab(
        {"lab": "looney-tunables-ctf", "criterion": "flag"}, tmp_path
    )
    assert ok is False
    assert "run_agent_test.py" in detail


def test_preflight_status_failure(tmp_path, monkeypatch):
    _lab_root(tmp_path)
    monkeypatch.setattr(
        rb.subprocess, "run", lambda *a, **k: _proc(1, "", "[!] not running\n")
    )
    ok, detail = rb.preflight_lab(
        {"lab": "looney-tunables-ctf", "criterion": "flag"}, tmp_path
    )
    assert ok is False
    assert "not running" in detail


def test_preflight_flag_criterion_requires_clean_lab(tmp_path, monkeypatch):
    _lab_root(tmp_path)

    def fake_run(cmd, **kwargs):
        if cmd[-1] == "status":
            return _proc(0, "[ok] running\n")
        return _proc(1, "[locked] la flag no es legible\n")

    monkeypatch.setattr(rb.subprocess, "run", fake_run)
    ok, detail = rb.preflight_lab(
        {"lab": "looney-tunables-ctf", "criterion": "flag"}, tmp_path
    )
    assert ok is True
    assert "clean" in detail


def test_preflight_flag_criterion_rejects_dirty_lab(tmp_path, monkeypatch):
    _lab_root(tmp_path)

    def fake_run(cmd, **kwargs):
        if cmd[-1] == "status":
            return _proc(0, "[ok] running\n")
        return _proc(0, "[CAPTURED] CTF{already_escalated}\n")

    monkeypatch.setattr(rb.subprocess, "run", fake_run)
    ok, detail = rb.preflight_lab(
        {"lab": "looney-tunables-ctf", "criterion": "flag"}, tmp_path
    )
    assert ok is False
    assert "not clean" in detail
    assert "BENCH_RESET_LAB" in detail


def test_preflight_skips_clean_check_when_reset_is_enabled(tmp_path, monkeypatch):
    _lab_root(tmp_path)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd[-1])
        if cmd[-1] == "status":
            return _proc(0, "[ok] running\n")
        return _proc(0, "[CAPTURED] CTF{dirty}\n")

    monkeypatch.setattr(rb.subprocess, "run", fake_run)
    ok, _ = rb.preflight_lab(
        {"lab": "looney-tunables-ctf", "criterion": "flag"},
        tmp_path,
        require_clean=False,
    )
    assert ok is True
    assert calls == ["status"]


def test_preflight_other_criterion_needs_only_status(tmp_path, monkeypatch):
    _lab_root(tmp_path, "php2shell-lab")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd[-1])
        return _proc(0, "[ok] running\n")

    monkeypatch.setattr(rb.subprocess, "run", fake_run)
    ok, _ = rb.preflight_lab(
        {"lab": "php2shell-lab", "criterion": "rce_evidence"}, tmp_path
    )
    assert ok is True
    assert calls == ["status"]


def test_reset_lab_runs_down_and_up(tmp_path, monkeypatch):
    _lab_root(tmp_path)
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return _proc(0, "ok\n")

    monkeypatch.setattr(rb.subprocess, "run", fake_run)
    ok, detail = rb.reset_lab(tmp_path, "looney-tunables-ctf")
    assert ok is True
    assert "recreated" in detail
    assert len(calls) == 2
    first, second = calls
    assert first[0][:3] == ["docker", "compose", "-f"]
    assert "down" in first[0]
    assert "up" in second[0] and "-d" in second[0] and "--build" in second[0]
    assert first[1].get("cwd") == str(tmp_path)


def test_reset_lab_missing_compose(tmp_path):
    _lab_root(tmp_path)
    (tmp_path / "labs" / "looney-tunables-ctf" / "docker-compose.yml").unlink()
    ok, detail = rb.reset_lab(tmp_path, "looney-tunables-ctf")
    assert ok is False
    assert "docker-compose.yml" in detail


def test_reset_lab_reports_failure(tmp_path, monkeypatch):
    _lab_root(tmp_path)
    monkeypatch.setattr(rb.subprocess, "run", lambda *a, **k: _proc(1, "", "boom\n"))
    ok, detail = rb.reset_lab(tmp_path, "looney-tunables-ctf")
    assert ok is False
    assert "boom" in detail


# --------------------------------------------------------------------------- # aggregation / output


def test_aggregate_medians_and_success_rate():
    records = [
        {"wall_time_s": 10.0, "steps": 4, "tokens": 100, "success": True},
        {"wall_time_s": 20.0, "steps": 6, "tokens": 200, "success": False},
        {"wall_time_s": 30.0, "steps": 8, "tokens": None, "success": True},
        {"wall_time_s": 40.0, "steps": None, "tokens": None, "success": False},
    ]
    stats = rb.aggregate(records)
    assert stats["runs"] == 4
    assert stats["success_count"] == 2
    assert stats["success_rate"] == pytest.approx(0.5, abs=1e-4)
    assert stats["median_wall_time_s"] == 25.0
    assert stats["median_steps"] == 6
    assert stats["median_tokens"] == 150


def _sample_record(**overrides):
    record = {
        "attempt": 1,
        "run_id": "run_1",
        "status": "completed",
        "success": True,
        "criterion_ok": True,
        "criterion_detail": "captured",
        "steps": 3,
        "wall_time_s": 1.5,
        "tokens": 42,
        "served_model": "provider/served",
        "timed_out": False,
        "stopped": False,
        "error": None,
    }
    record.update(overrides)
    return record


def test_build_result_and_write_results_fixed_schema(tmp_path):
    task = {
        "id": "t",
        "lab": "looney-tunables-ctf",
        "criterion": "flag",
        "target": "ubuntu-server-01",
        "prompt": "do the thing",
    }
    records = [_sample_record()]
    result = rb.build_result(
        task,
        records,
        model="m",
        url="http://x",
        benchmark_version=1,
        started_at="2026-01-01T00:00:00Z",
        manifest_sha256="abc123",
    )
    expected_keys = {
        "schema",
        "benchmark_version",
        "task_id",
        "lab",
        "criterion",
        "target",
        "prompt",
        "model",
        "served_model",
        "api_url",
        "manifest_sha256",
        "started_at",
        "finished_at",
        "runs_requested",
        "success_count",
        "success_rate",
        "median_wall_time_s",
        "median_steps",
        "median_tokens",
        "attempts",
    }
    assert set(result) == expected_keys
    assert result["schema"] == "vulnerator-benchmark-result/1"
    assert result["prompt"] == "do the thing"
    assert result["manifest_sha256"] == "abc123"
    assert result["served_model"] == "provider/served"

    json_path, markdown_path = rb.write_results(result, tmp_path)
    assert json_path.is_file() and markdown_path.is_file()
    assert json.loads(json_path.read_text(encoding="utf-8")) == result
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "# Benchmark result - t" in markdown
    assert "run_1" in markdown


def test_write_results_unique_suffix_and_no_temp_files(tmp_path):
    result = {
        "task_id": "t",
        "benchmark_version": 1,
        "lab": "looney-tunables-ctf",
        "criterion": "flag",
        "target": "ubuntu-server-01",
        "prompt": "p",
        "model": None,
        "served_model": None,
        "api_url": "http://x",
        "manifest_sha256": "abc",
        "runs_requested": 0,
        "success_count": 0,
        "success_rate": 0.0,
        "median_wall_time_s": None,
        "median_steps": None,
        "median_tokens": None,
        "attempts": [],
    }
    first = rb.write_results(result, tmp_path)
    second = rb.write_results(result, tmp_path)
    assert first is not None and second is not None
    assert first[0] != second[0]
    assert len(list(tmp_path.glob("*.json"))) == 2
    assert len(list(tmp_path.glob("*.md"))) == 2
    assert list(tmp_path.glob("*.tmp")) == []


def test_write_results_reports_oserror_without_raising(tmp_path, capsys):
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    assert rb.write_results({"task_id": "t"}, blocker / "results") is None
    err = capsys.readouterr().err
    assert "error: cannot write results" in err
    assert "Traceback" not in err


# --------------------------------------------------------------------------- #
# SSE event fetch (stub server: silent, trickle, multipage, partial failure)
# --------------------------------------------------------------------------- #


def _sse_frame(event: str, seq: int, run_id: Any = None) -> bytes:
    payload = {"event": event, "seq": seq}
    if run_id is not None:
        payload["run_id"] = run_id
    return f"id: {seq}\ndata: {json.dumps(payload)}\n\n".encode("utf-8")


class _SseStubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        server = cast(_SseStubServer, self.server)
        raw = self.headers.get("Last-Event-ID", "")
        try:
            last = int(raw)
        except (TypeError, ValueError):
            last = -1
        server.cursors.append(last)
        chunks = server.responder(last)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            for chunk in chunks:
                self.wfile.write(chunk)
                self.wfile.flush()
                if server.chunk_delay:
                    time.sleep(server.chunk_delay)
            if server.linger:
                time.sleep(server.linger)
        except OSError:
            pass
        finally:
            self.close_connection = True


class _SseStubServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, responder, *, linger=0.0, chunk_delay=0.0):
        super().__init__(("127.0.0.1", 0), _SseStubHandler)
        self.responder = responder
        self.linger = linger
        self.chunk_delay = chunk_delay
        self.cursors: list[int] = []

    def handle_error(self, request, client_address):
        pass


@contextmanager
def _sse_server(responder, **kwargs):
    server = _SseStubServer(responder, **kwargs)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_fetch_events_silent_stream_returns_empty_within_deadline(monkeypatch):
    monkeypatch.setattr(rb, "EVENTS_DEADLINE_S", 0.4)
    monkeypatch.setattr(rb, "EVENTS_TIMEOUT_S", 0.4)

    def responder(_last):
        return [b": open\n\n"]

    started = time.monotonic()
    with _sse_server(responder, linger=10.0) as (base, _server):
        events = rb.fetch_events(base, "k", "run_silent")
    assert events == []
    assert time.monotonic() - started < 3.0


def test_fetch_events_trickle_collects_every_event(monkeypatch):
    monkeypatch.setattr(rb, "EVENTS_DEADLINE_S", 5.0)
    frames = [
        _sse_frame("ooda.observe", 0),
        _sse_frame("tool.started", 1),
        _sse_frame("tool.completed", 2),
        _sse_frame("run.completed", 3),
    ]

    def responder(last):
        return [frame for index, frame in enumerate(frames) if index > last]

    with _sse_server(responder) as (base, server):
        events = rb.fetch_events(base, "k", "run_trickle")
    assert [event["seq"] for event in events] == [0, 1, 2, 3]
    assert server.cursors == [-1]


def test_fetch_events_paginates_with_cursor_until_terminal(monkeypatch):
    monkeypatch.setattr(rb, "EVENTS_DEADLINE_S", 5.0)
    frames = [_sse_frame("tool.started", seq) for seq in range(4)]
    frames.append(_sse_frame("run.completed", 4))

    def responder(last):
        return [frame for index, frame in enumerate(frames) if index > last][:2]

    with _sse_server(responder) as (base, server):
        events = rb.fetch_events(base, "k", "run_pages")
    assert [event["seq"] for event in events] == [0, 1, 2, 3, 4]
    assert server.cursors == [-1, 1, 3]


def test_fetch_events_keeps_collected_events_when_a_page_fails(monkeypatch):
    monkeypatch.setattr(rb, "EVENTS_DEADLINE_S", 5.0)
    page = [_sse_frame("tool.started", 0), _sse_frame("tool.completed", 1)]
    calls = {"count": 0}

    def responder(_last):
        calls["count"] += 1
        if calls["count"] == 1:
            return page
        raise RuntimeError("upstream went away")

    with _sse_server(responder) as (base, _server):
        events = rb.fetch_events(base, "k", "run_partial")
    assert [event["seq"] for event in events] == [0, 1]


def test_fetch_events_deadline_keeps_events_already_collected(monkeypatch):
    monkeypatch.setattr(rb, "EVENTS_DEADLINE_S", 0.6)
    monkeypatch.setattr(rb, "EVENTS_TIMEOUT_S", 0.6)

    def responder(_last):
        return [_sse_frame("tool.started", 0)]

    started = time.monotonic()
    with _sse_server(responder, linger=10.0) as (base, _server):
        events = rb.fetch_events(base, "k", "run_quiet")
    assert [event["seq"] for event in events] == [0]
    assert time.monotonic() - started < 3.0


def test_fetch_events_drops_events_of_another_run(monkeypatch):
    monkeypatch.setattr(rb, "EVENTS_DEADLINE_S", 5.0)

    def responder(_last):
        return [
            _sse_frame("tool.started", 0, run_id="run_mine"),
            _sse_frame("tool.completed", 1, run_id="run_other"),
            _sse_frame("run.completed", 2, run_id="run_mine"),
        ]

    with _sse_server(responder) as (base, _server):
        events = rb.fetch_events(base, "k", "run_mine")
    assert [event["seq"] for event in events] == [0, 2]


# --------------------------------------------------------------------------- # poll_run


def test_poll_run_returns_terminal_without_stopping(monkeypatch):
    calls = []

    def fake_http(method, url, **kwargs):
        calls.append((method, url))
        return {"status": "completed", "run_id": "run_1"}

    monkeypatch.setattr(rb, "_http_json", fake_http)
    run_obj, stopped = rb.poll_run("http://x", "k", "run_1", 5.0)
    assert run_obj["status"] == "completed"
    assert stopped is False
    assert [method for method, _ in calls] == ["GET"]


def test_poll_run_stops_on_timeout(monkeypatch):
    calls = []

    def fake_http(method, url, **kwargs):
        calls.append((method, url))
        if method == "POST":
            return {"status": "cancelled"}
        return {"status": "running"}

    monkeypatch.setattr(rb, "_http_json", fake_http)
    monkeypatch.setattr(rb, "POLL_INTERVAL_S", 0.01)
    run_obj, stopped = rb.poll_run("http://x", "k", "run_1", 0.05)
    assert run_obj["status"] == "running"
    assert stopped is True
    assert any(method == "POST" and url.endswith("/stop") for method, url in calls)


def test_poll_run_survives_a_failed_stop(monkeypatch):
    calls = []

    def fake_http(method, url, **kwargs):
        calls.append((method, url))
        if method == "POST":
            raise rb.ApiError("stop rejected")
        return {"status": "running"}

    monkeypatch.setattr(rb, "_http_json", fake_http)
    monkeypatch.setattr(rb, "POLL_INTERVAL_S", 0.01)
    run_obj, stopped = rb.poll_run("http://x", "k", "run_1", 0.05)
    assert run_obj["status"] == "running"
    assert stopped is False
    assert any(method == "POST" for method, _ in calls)


# --------------------------------------------------------------------------- # run_attempt


def test_run_attempt_records_error_without_raising(monkeypatch):
    def boom(*args, **kwargs):
        raise rb.ApiError("connection refused")

    monkeypatch.setattr(rb, "start_run", boom)
    task = {"prompt": "do it", "timeout": 10, "criterion": "flag"}
    record = rb.run_attempt(task, 1, url="http://x", key="k", repo_root=Path("."))
    assert record["success"] is False
    assert record["status"] == "error"
    assert "connection refused" in record["error"]


def test_run_attempt_records_served_model_steps_and_stop(monkeypatch):
    monkeypatch.setattr(rb, "start_run", lambda *a, **k: "run_1")
    monkeypatch.setattr(
        rb,
        "poll_run",
        lambda *a, **k: (
            {"status": "running", "model": "provider/served", "usage": {"total_tokens": 10}},
            True,
        ),
    )
    monkeypatch.setattr(
        rb, "fetch_events", lambda *a, **k: [{"event": "tool.completed", "tool_call_id": "c1"}]
    )
    monkeypatch.setattr(rb, "verify_criterion", lambda *a, **k: (True, "ok"))
    task = {"prompt": "do it", "timeout": 10, "criterion": "flag"}
    record = rb.run_attempt(task, 1, url="http://x", key="k", repo_root=Path("."))
    assert record["run_id"] == "run_1"
    assert record["stopped"] is True
    assert record["timed_out"] is True
    assert record["steps"] == 1
    assert record["tokens"] == 10
    assert record["served_model"] == "provider/served"
    assert record["success"] is True


# --------------------------------------------------------------------------- # CLI contract


def _run_cli(argv, *, env_extra=None, results_dir=None):
    env = dict(os.environ)
    env.pop("HERMES_API_KEY", None)
    env.pop("BENCH_LAB", None)
    env.pop("BENCH_RUNS", None)
    env.pop("BENCH_RESET_LAB", None)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [sys.executable, str(RUNNER), *argv],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


def test_cli_lists_tasks():
    proc = _run_cli(["--list"])
    assert proc.returncode == 0
    assert "looney-tunables-ctf" in proc.stdout
    assert "php2shell-lab" in proc.stdout


def test_cli_rejects_disabled_task():
    proc = _run_cli(["--task", "php2shell-lab"])
    assert proc.returncode == 1
    assert "disabled" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_cli_fails_cleanly_on_dead_api(tmp_path):
    port = _free_port()
    results_dir = tmp_path / "results"
    proc = _run_cli(
        ["--results-dir", str(results_dir)],
        env_extra={"HERMES_API_URL": f"http://127.0.0.1:{port}", "HERMES_API_KEY": "dummy"},
    )
    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "Traceback" not in combined
    assert "docker compose up -d" in proc.stderr
    assert "curl -s http://localhost:8642/health" in proc.stderr
    assert list(results_dir.glob("*.json")) == []


def test_cli_fails_cleanly_without_api_key(tmp_path, monkeypatch, capsys):
    """REPO_ROOT/.env is neutralised so the test does not depend on the host."""
    monkeypatch.delenv("HERMES_API_KEY", raising=False)
    monkeypatch.delenv("HERMES_API_SERVER_KEY", raising=False)
    monkeypatch.setattr(rb, "REPO_ROOT", tmp_path)
    monkeypatch.setenv("HERMES_API_URL", "http://127.0.0.1:1")
    rc = rb.main(["--results-dir", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 1
    assert "Traceback" not in captured.out + captured.err
    assert "HERMES_API_KEY" in captured.err


def test_cli_rejects_malformed_api_url(tmp_path):
    proc = _run_cli(
        ["--results-dir", str(tmp_path)],
        env_extra={"HERMES_API_URL": "not a url", "HERMES_API_KEY": "dummy"},
    )
    combined = proc.stdout + proc.stderr
    assert proc.returncode == 1
    assert "invalid API URL" in combined
    assert "Traceback" not in combined


def test_cli_rejects_newline_in_api_key(tmp_path):
    proc = _run_cli(
        ["--results-dir", str(tmp_path)],
        env_extra={"HERMES_API_URL": "http://127.0.0.1:1", "HERMES_API_KEY": "bad\nkey"},
    )
    combined = proc.stdout + proc.stderr
    assert proc.returncode == 1
    assert "invalid API key" in combined
    assert "Traceback" not in combined


def _patched_main(monkeypatch, *, reset_calls=None):
    monkeypatch.setenv("HERMES_API_KEY", "dummy")
    monkeypatch.setattr(rb, "health_check", lambda *a, **k: {"status": "ok"})
    monkeypatch.setattr(rb, "preflight_lab", lambda *a, **k: (True, "lab present"))
    monkeypatch.setattr(
        rb,
        "run_attempt",
        lambda *a, **k: _sample_record(attempt=1, run_id="run_1"),
    )
    if reset_calls is not None:
        def fake_reset(*a, **k):
            reset_calls.append((a, k))
            return True, "lab recreated"
        monkeypatch.setattr(rb, "reset_lab", fake_reset)


def test_cli_resets_lab_between_attempts_when_enabled(monkeypatch, tmp_path, capsys):
    calls = []
    _patched_main(monkeypatch, reset_calls=calls)
    monkeypatch.setenv("BENCH_RESET_LAB", "1")
    rc = rb.main(["--runs", "2", "--results-dir", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 0
    assert len(calls) == 2
    assert "lab reset" in captured.out
    assert len(list(tmp_path.glob("*.json"))) == 1


def test_cli_does_not_reset_lab_by_default(monkeypatch, tmp_path):
    calls = []
    _patched_main(monkeypatch, reset_calls=calls)
    rc = rb.main(["--runs", "1", "--results-dir", str(tmp_path)])
    assert rc == 0
    assert calls == []


def test_cli_reset_failure_is_clean(monkeypatch, tmp_path, capsys):
    _patched_main(monkeypatch)
    monkeypatch.setenv("BENCH_RESET_LAB", "1")
    monkeypatch.setattr(rb, "reset_lab", lambda *a, **k: (False, "compose exploded"))
    rc = rb.main(["--runs", "1", "--results-dir", str(tmp_path)])
    captured = capsys.readouterr()
    assert rc == 1
    assert "cannot reset lab" in captured.err
    assert "Traceback" not in captured.out + captured.err


def test_cli_write_failure_is_clean_and_exits_1(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("HERMES_API_KEY", "dummy")
    monkeypatch.setattr(rb, "health_check", lambda *args, **kwargs: {"status": "ok"})
    monkeypatch.setattr(rb, "preflight_lab", lambda *args, **kwargs: (True, "lab present"))
    monkeypatch.setattr(
        rb,
        "run_attempt",
        lambda *args, **kwargs: _sample_record(),
    )
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    rc = rb.main(["--runs", "1", "--results-dir", str(blocker / "results")])
    captured = capsys.readouterr()
    assert rc == 1
    assert "error: cannot write results" in captured.err
    assert "Traceback" not in captured.out + captured.err
