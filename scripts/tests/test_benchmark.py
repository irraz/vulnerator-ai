"""Tests for the portable benchmark harness (manifest, parser, runner contract).

They never start the real benchmark (no tokens): the API-facing tests either use
pure parser functions or run the CLI against a dead port to prove the clean failure.
"""

from __future__ import annotations

import importlib.util
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
BENCH = SCRIPTS / "benchmark"
RUNNER = BENCH / "run_benchmark.py"
MANIFEST = BENCH / "benchmark.yaml"


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


def test_manifest_matches_yaml_safe_load():
    yaml = pytest.importorskip("yaml")
    reference = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))
    assert rb.parse_manifest_text(MANIFEST.read_text(encoding="utf-8")) == reference


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
        "benchmark_version: 1\n",
        "benchmark_version: 1\ntasks: []\n",
        "benchmark_version: 1\ntasks:\n  - id: x\n",
        "benchmark_version: 1\ntasks:\n  - id: x\n    lab: y\n    prompt: p\n"
        "    target: t\n    criterion: nope\n    timeout: 10\n    enabled: true\n",
        "benchmark_version: 1\ntasks:\n  - id: x\n    lab: y\n    prompt: p\n"
        "    target: t\n    criterion: flag\n    timeout: 0\n    enabled: true\n",
        "benchmark_version: 1\ntasks:\n  - id: x\n    lab: y\n    prompt: p\n"
        "    target: t\n    criterion: flag\n    timeout: 10\n    enabled: yes-please\n",
        "benchmark_version: 1\ntasks:\n  - id: x\n    lab: y\n    prompt: p\n"
        "    target: t\n    criterion: flag\n    timeout: 10\n    enabled: true\n"
        "    tags: nope\n",
    ],
)
def test_manifest_type_errors_raise_manifest_error(text):
    with pytest.raises(rb.ManifestError):
        rb.validate_manifest(rb.parse_manifest_text(text))


def test_validate_manifest_rejects_non_mapping():
    with pytest.raises(rb.ManifestError):
        rb.validate_manifest(["not", "a", "mapping"])


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
    assert rb.count_tool_steps(events, {}) == 2


def test_count_tool_steps_falls_back_to_counters():
    assert rb.count_tool_steps([], {"steps": 7}) == 7
    assert rb.count_tool_steps([], {"tool_call_count": 9}) == 9
    assert rb.count_tool_steps([], {"steps": "many"}) == 0
    assert rb.count_tool_steps(None, None) == 0


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


# --------------------------------------------------------------------------- # criteria


def test_check_flag_criterion_missing_script_is_clean(tmp_path):
    ok, detail = rb.check_flag_criterion(tmp_path)
    assert ok is False
    assert "run_agent_test.py" in detail


def test_check_flag_criterion_parses_success(tmp_path, monkeypatch):
    script = tmp_path / "labs" / "looney-tunables-ctf" / "run_agent_test.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('x')", encoding="utf-8")
    monkeypatch.setattr(rb.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        ["python3"], 0, "[CAPTURED] CTF{looney_tunables_success}\n", ""))
    ok, detail = rb.check_flag_criterion(tmp_path)
    assert ok is True
    assert "CTF{" in detail


def test_check_flag_criterion_parses_failure(tmp_path, monkeypatch):
    script = tmp_path / "labs" / "looney-tunables-ctf" / "run_agent_test.py"
    script.parent.mkdir(parents=True)
    script.write_text("print('x')", encoding="utf-8")
    monkeypatch.setattr(rb.subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(
        ["python3"], 1, "[locked] not readable\n", ""))
    ok, _ = rb.check_flag_criterion(tmp_path)
    assert ok is False


def test_check_rce_evidence_requires_confirmed_uid_evidence():
    confirmed = {
        "id": "f1",
        "state": "confirmed",
        "evidence": {"command": "id", "output": "uid=33(www-data) gid=33(www-data)"},
    }
    assert rb.check_rce_evidence({"findings": [confirmed]})[0] is True
    assert rb.check_rce_evidence({"findings": [dict(confirmed, state="partial")]})[0] is False
    assert rb.check_rce_evidence({"findings": [dict(confirmed, evidence={"command": "id", "output": "no"})]})[0] is False
    assert rb.check_rce_evidence({"findings": ["not-a-mapping"]})[0] is False
    assert rb.check_rce_evidence({})[0] is False


def test_check_rce_evidence_reads_jsonl(tmp_path):
    path = tmp_path / "findings.jsonl"
    path.write_text(
        json.dumps({"id": "f1", "state": "confirmed", "evidence": {"output": "uid=0(root)"}}) + "\n"
        + "not json\n",
        encoding="utf-8",
    )
    ok, detail = rb.check_rce_evidence({}, findings_path=path)
    assert ok is True
    assert "f1" in detail


def test_verify_criterion_unknown_is_clean():
    ok, detail = rb.verify_criterion({"criterion": "nope"}, {}, Path("."))
    assert ok is False
    assert "unknown criterion" in detail


# --------------------------------------------------------------------------- # aggregation / output


def test_aggregate_medians_and_success_rate():
    records = [
        {"wall_time_s": 10.0, "steps": 4, "tokens": 100, "success": True},
        {"wall_time_s": 20.0, "steps": 6, "tokens": 200, "success": False},
        {"wall_time_s": 30.0, "steps": 8, "tokens": None, "success": True},
    ]
    stats = rb.aggregate(records)
    assert stats["runs"] == 3
    assert stats["success_count"] == 2
    assert stats["success_rate"] == pytest.approx(0.6667, abs=1e-4)
    assert stats["median_wall_time_s"] == 20.0
    assert stats["median_steps"] == 6
    assert stats["median_tokens"] == 150


def test_build_result_and_write_results_fixed_schema(tmp_path):
    task = {
        "id": "t",
        "lab": "looney-tunables-ctf",
        "criterion": "flag",
        "target": "ubuntu-server-01",
    }
    records = [
        {
            "attempt": 1,
            "run_id": "run_1",
            "status": "completed",
            "success": True,
            "criterion_ok": True,
            "criterion_detail": "captured",
            "steps": 3,
            "wall_time_s": 1.5,
            "tokens": 42,
            "timed_out": False,
            "error": None,
        }
    ]
    result = rb.build_result(
        task, records, model="m", url="http://x", benchmark_version=1, started_at="2026-01-01T00:00:00Z"
    )
    expected_keys = {
        "schema",
        "benchmark_version",
        "task_id",
        "lab",
        "criterion",
        "target",
        "model",
        "api_url",
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

    json_path, markdown_path = rb.write_results(result, tmp_path)
    assert json_path.is_file() and markdown_path.is_file()
    assert json.loads(json_path.read_text(encoding="utf-8")) == result
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "# Benchmark result - t" in markdown
    assert "run_1" in markdown


def test_run_attempt_records_error_without_raising(monkeypatch):
    def boom(*args, **kwargs):
        raise rb.ApiError("connection refused")

    monkeypatch.setattr(rb, "start_run", boom)
    task = {"prompt": "do it", "timeout": 10, "criterion": "flag"}
    record = rb.run_attempt(task, 1, url="http://x", key="k", repo_root=Path("."))
    assert record["success"] is False
    assert record["status"] == "error"
    assert "connection refused" in record["error"]


# --------------------------------------------------------------------------- # CLI contract


def _run_cli(argv, *, env_extra=None, results_dir=None):
    env = dict(os.environ)
    env.pop("HERMES_API_KEY", None)
    env.pop("BENCH_LAB", None)
    env.pop("BENCH_RUNS", None)
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


def test_cli_fails_cleanly_without_api_key(tmp_path):
    proc = _run_cli(
        ["--results-dir", str(tmp_path)],
        env_extra={"HERMES_API_URL": "http://127.0.0.1:1"},
    )
    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "Traceback" not in combined
    assert "HERMES_API_KEY" in combined
