#!/usr/bin/env python3
"""Portable benchmark runner for vulnerator-ai (standard library only).

It assumes the lab and the vulnerator-ai stack are ALREADY running: it never
starts them (except the optional per-attempt lab reset, ``BENCH_RESET_LAB=1``).
For the selected manifest task it drives the Hermes runs API (``POST /v1/runs``,
``GET /v1/runs/{id}``), measures each attempt (steps, wall time, tokens), verifies
the task criterion against that attempt's own run and writes a fixed-schema JSON
result plus a Markdown summary under ``scripts/benchmark/results/``.

The manifest is plain JSON (``benchmark.json``) parsed with the standard library,
so the runner keeps working on a machine that only has Python. If the stack or
the lab is missing, the runner prints the RUNBOOK commands and exits cleanly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = Path(__file__).resolve().parent / "benchmark.json"
RESULTS_DIR = Path(__file__).resolve().parent / "results"

DEFAULT_API_URL = "http://localhost:8642"
DEFAULT_LAB = "looney-tunables-ctf"
DEFAULT_RUNS = 3
POLL_INTERVAL_S = 5.0
HTTP_TIMEOUT_S = 30.0
EVENTS_TIMEOUT_S = 30.0
EVENTS_DEADLINE_S = 60.0
LAB_CMD_TIMEOUT_S = 180.0
LAB_RESET_TIMEOUT_S = 600.0

TERMINAL_STATUSES = frozenset({"completed", "failed", "cancelled", "interrupted"})
TOOL_EVENT_NAMES = frozenset({"tool.started", "tool.completed"})
CRITERIA = frozenset({"flag", "rce_evidence"})
RESULT_SCHEMA = "vulnerator-benchmark-result/1"
FLAG_RE = re.compile(r"CTF\{[^}\s]+\}")

REQUIRED_TASK_FIELDS = ("id", "lab", "prompt", "target", "criterion", "timeout")


class ManifestError(ValueError):
    """The benchmark manifest is missing, unreadable or has the wrong shape."""


class ApiError(RuntimeError):
    """A call to the vulnerator-ai runs API failed or returned an unexpected shape."""


# --------------------------------------------------------------------------- #
# Manifest (plain JSON, standard library only).
# --------------------------------------------------------------------------- #


def validate_manifest(data: Any) -> dict[str, Any]:
    """Validates the manifest shape and field types (fail-closed, no traceback)."""
    if not isinstance(data, dict):
        raise ManifestError("manifest must be a JSON object")
    version = data.get("benchmark_version")
    if not isinstance(version, int) or isinstance(version, bool) or version <= 0:
        raise ManifestError("'benchmark_version' must be a positive integer")
    tasks = data.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise ManifestError("'tasks' must be a non-empty list")

    seen: set[str] = set()
    for index, task in enumerate(tasks):
        if not isinstance(task, dict):
            raise ManifestError(f"tasks[{index}] must be a JSON object")
        for field in REQUIRED_TASK_FIELDS:
            if field not in task:
                raise ManifestError(f"tasks[{index}] is missing {field!r}")
        for field in ("id", "lab", "prompt", "target", "criterion"):
            if not isinstance(task[field], str) or not task[field].strip():
                raise ManifestError(f"tasks[{index}].{field} must be a non-empty string")
        _validate_path_component(task["id"], "id", index)
        _validate_path_component(task["lab"], "lab", index)
        if task["criterion"] not in CRITERIA:
            raise ManifestError(
                f"tasks[{index}].criterion must be one of {sorted(CRITERIA)}, "
                f"got {task['criterion']!r}"
            )
        timeout = task["timeout"]
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            raise ManifestError(f"tasks[{index}].timeout must be a positive number")
        if not isinstance(task.get("enabled"), bool):
            raise ManifestError(f"tasks[{index}].enabled must be a boolean")
        tags = task.get("tags")
        if tags is not None and (
            not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags)
        ):
            raise ManifestError(f"tasks[{index}].tags must be a list of strings")
        note = task.get("note")
        if note is not None and not isinstance(note, str):
            raise ManifestError(f"tasks[{index}].note must be a string")
        if task["id"] in seen:
            raise ManifestError(f"duplicate task id {task['id']!r}")
        seen.add(task["id"])
    return data


def _validate_path_component(value: str, field: str, index: int) -> None:
    """Rejects values that could escape a path (``/``, ``\\``, ``..``, NUL)."""
    if value in (".", "..") or "/" in value or "\\" in value or "\x00" in value:
        raise ManifestError(
            f"tasks[{index}].{field} must be a plain name (no '/', '\\' or '..'): {value!r}"
        )


def load_manifest(path: Path) -> dict[str, Any]:
    """Reads and validates the manifest, raising ManifestError instead of a traceback."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ManifestError(f"cannot read {path}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ManifestError(
            f"invalid JSON in {path}: line {exc.lineno} column {exc.colno}: {exc.msg}"
        ) from exc
    return validate_manifest(data)


def manifest_sha256(path: Path) -> str:
    """SHA-256 of the manifest bytes, recorded in every result for reproducibility."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def select_task(tasks: list[dict[str, Any]], wanted: Any) -> Optional[dict[str, Any]]:
    """Returns the task whose id or lab matches ``wanted`` (exact, stripped)."""
    if not isinstance(wanted, str) or not wanted.strip():
        return None
    wanted = wanted.strip()
    for task in tasks:
        if task.get("id") == wanted or task.get("lab") == wanted:
            return task
    return None


# --------------------------------------------------------------------------- #
# HTTP client for the runs API (stdlib urllib).
# --------------------------------------------------------------------------- #


def _join(url: str, path: str) -> str:
    return url.rstrip("/") + path


def validate_api_config(url: str, key: str) -> Optional[str]:
    """Returns a clean error message for a malformed URL/key, or None when usable."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return f"invalid API URL {url!r}: expected http://host:port or https://host:port"
    if "\r" in key or "\n" in key:
        return "invalid API key: it contains a newline"
    return None


def _http_json(
    method: str,
    url: str,
    *,
    key: Optional[str] = None,
    body: Any = None,
    timeout: float = HTTP_TIMEOUT_S,
) -> Any:
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if key:
        headers["Authorization"] = "Bearer " + key
    try:
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", "replace").strip()
        except Exception:
            detail = ""
        raise ApiError(f"{method} {url} -> HTTP {exc.code} {exc.reason}: {detail}") from exc
    except (urllib.error.URLError, OSError) as exc:
        raise ApiError(f"{method} {url} -> {exc.__class__.__name__}: {exc}") from exc
    except ValueError as exc:
        # A malformed URL or an invalid header (e.g. a newline in the key) raises
        # ValueError before any bytes move; report it as an API error, not a crash.
        raise ApiError(f"{method} {url} -> invalid request: {exc}") from exc
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiError(f"{method} {url} -> invalid JSON: {exc}") from exc


def health_check(url: str, key: str) -> dict[str, Any]:
    """GET /health; returns the payload or raises ApiError."""
    payload = _http_json("GET", _join(url, "/health"), key=key, timeout=10.0)
    if not isinstance(payload, dict):
        raise ApiError("GET /health returned a non-object payload")
    return payload


def start_run(url: str, key: str, prompt: str, model: Optional[str] = None) -> str:
    """POST /v1/runs with the manifest prompt; returns the run_id."""
    body: dict[str, Any] = {"input": prompt}
    if model:
        body["model"] = model
    payload = _http_json("POST", _join(url, "/v1/runs"), key=key, body=body, timeout=60.0)
    if not isinstance(payload, dict):
        raise ApiError("POST /v1/runs returned a non-object payload")
    run_id = payload.get("run_id")
    if not isinstance(run_id, str) or not run_id.strip():
        raise ApiError("POST /v1/runs did not return a string 'run_id'")
    return run_id


def stop_run(url: str, key: str, run_id: str) -> dict[str, Any]:
    """POST /v1/runs/{id}/stop; returns the run object or raises ApiError."""
    target = _join(url, "/v1/runs/" + urllib.parse.quote(run_id, safe="") + "/stop")
    payload = _http_json("POST", target, key=key, timeout=HTTP_TIMEOUT_S)
    if not isinstance(payload, dict):
        raise ApiError(f"POST {target} returned a non-object payload")
    return payload


def run_status(run_obj: Any) -> str:
    """Terminal/normalized status of a run object (never raises)."""
    if not isinstance(run_obj, dict):
        return "unknown"
    status = run_obj.get("status")
    if isinstance(status, str) and status.strip():
        return status.strip().lower()
    if run_obj.get("completed") is True:
        return "completed"
    if run_obj.get("interrupted") is True:
        return "cancelled"
    return "unknown"


def is_terminal(run_obj: Any) -> bool:
    """True when the run reached a terminal state (status string or booleans)."""
    if not isinstance(run_obj, dict):
        return False
    status = run_obj.get("status")
    if isinstance(status, str) and status.strip().lower() in TERMINAL_STATUSES:
        return True
    return run_obj.get("completed") is True or run_obj.get("interrupted") is True


def poll_run(url: str, key: str, run_id: str, timeout: float) -> tuple[dict[str, Any], bool]:
    """Polls GET /v1/runs/{id} until terminal or the task timeout expires.

    Returns ``(run_obj, stopped)``. On timeout the runner asks the API to stop
    the run (``POST /v1/runs/{id}/stop``) and reports ``stopped=True`` when that
    call succeeded, so a timed-out attempt is never silently left running.
    """
    target = _join(url, "/v1/runs/" + urllib.parse.quote(run_id, safe=""))
    deadline = time.monotonic() + timeout
    while True:
        payload = _http_json("GET", target, key=key, timeout=HTTP_TIMEOUT_S)
        if not isinstance(payload, dict):
            raise ApiError(f"GET {target} returned a non-object payload")
        if is_terminal(payload):
            return payload, False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            stopped = False
            try:
                stop_run(url, key, run_id)
                stopped = True
            except ApiError:
                pass
            return payload, stopped
        time.sleep(min(POLL_INTERVAL_S, remaining))


def _event_belongs_to_run(event: dict[str, Any], run_id: str) -> bool:
    """True unless the event carries a different ``run_id`` (missing is tolerated)."""
    owner = event.get("run_id")
    return not isinstance(owner, str) or owner == run_id


def _read_event_page(
    response: Any, after_seq: int, run_id: str
) -> tuple[list[dict[str, Any]], int, bool]:
    """Reads ONE SSE connection into (new events, next cursor, saw terminal).

    The cursor is the SSE ``id:`` wire field or the JSON ``seq`` field, whichever
    is larger; events already delivered (``seq <= after_seq``) are skipped so a
    reconnect cannot duplicate them, and events owned by another run are dropped.
    Malformed frames are ignored, best effort.
    """
    events: list[dict[str, Any]] = []
    cursor = after_seq
    data_lines: list[str] = []
    terminal = False

    def consume() -> None:
        nonlocal cursor, terminal
        if not data_lines:
            return
        raw = "\n".join(data_lines)
        data_lines.clear()
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            return
        if not isinstance(event, dict):
            return
        if not _event_belongs_to_run(event, run_id):
            return
        seq = event.get("seq")
        if isinstance(seq, int) and not isinstance(seq, bool):
            if seq <= after_seq:
                return
            cursor = max(cursor, seq)
        events.append(event)
        if event.get("event") == "run.completed":
            terminal = True

    try:
        for raw_line in response:
            line = raw_line.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith("data:"):
                data_lines.append(line[len("data:"):].lstrip())
            elif line.startswith("id:"):
                value = line[len("id:"):].strip()
                if value.lstrip("+-").isdigit():
                    cursor = max(cursor, int(value))
            elif not line.strip():
                consume()
        consume()
    except (urllib.error.URLError, OSError):
        # A stream cut mid-page keeps the frames already decoded; the caller
        # decides whether to reconnect with the advanced cursor.
        consume()
    return events, cursor, terminal


def fetch_events(url: str, key: str, run_id: str) -> list[dict[str, Any]]:
    """Reads the SSE event backlog of a run; returns the parsed events (best effort).

    Paginates with the ``seq`` cursor sent back as ``Last-Event-ID`` until a
    terminal event arrives or the upstream closes without progress. The whole
    call is bounded by the wall-clock deadline ``EVENTS_DEADLINE_S``, and a
    failure mid-stream keeps the events already collected instead of dropping
    them.
    """
    target = _join(url, "/v1/runs/" + urllib.parse.quote(run_id, safe="") + "/events")
    deadline = time.monotonic() + EVENTS_DEADLINE_S
    events: list[dict[str, Any]] = []
    cursor = -1
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        headers = {"Accept": "text/event-stream", "Last-Event-ID": str(cursor)}
        if key:
            headers["Authorization"] = "Bearer " + key
        request = urllib.request.Request(target, headers=headers, method="GET")
        before = cursor
        try:
            with urllib.request.urlopen(
                request, timeout=min(remaining, EVENTS_TIMEOUT_S)
            ) as response:
                page, page_cursor, terminal = _read_event_page(response, cursor, run_id)
        except (urllib.error.URLError, OSError):
            break
        events.extend(page)
        cursor = page_cursor
        if terminal:
            break
        if cursor == before:
            break
    return events


# --------------------------------------------------------------------------- #
# Measurement extraction (tolerant: the run object is opaque, version-tolerant).
# --------------------------------------------------------------------------- #


def count_tool_steps(events: Any) -> Optional[int]:
    """Counts tool executions from the run's own ``tool.*`` events.

    Returns ``None`` when the backlog exposes no tool event at all: the runner
    never invents a step count from an unrelated counter, so ``median_steps``
    stays ``null`` instead of reporting a wrong number.
    """
    if not isinstance(events, list):
        return None
    call_ids: set[str] = set()
    started = 0
    completed = 0
    for event in events:
        if not isinstance(event, dict):
            continue
        name = event.get("event")
        if not isinstance(name, str):
            name = event.get("type")
        if not isinstance(name, str) or name not in TOOL_EVENT_NAMES:
            continue
        call_id = event.get("tool_call_id")
        if isinstance(call_id, str) and call_id.strip():
            call_ids.add(call_id.strip())
        elif name == "tool.completed":
            completed += 1
        else:
            started += 1
    if call_ids:
        return len(call_ids)
    if completed:
        return completed
    if started:
        return started
    return None


def extract_tokens(run_obj: Any) -> Optional[int]:
    """Total tokens when the run exposes them, else None."""
    if not isinstance(run_obj, dict):
        return None
    usage = run_obj.get("usage")
    if isinstance(usage, dict):
        total = usage.get("total_tokens")
        if isinstance(total, int) and not isinstance(total, bool) and total >= 0:
            return total
        input_tokens = usage.get("input_tokens")
        output_tokens = usage.get("output_tokens")
        if (
            isinstance(input_tokens, int)
            and not isinstance(input_tokens, bool)
            and isinstance(output_tokens, int)
            and not isinstance(output_tokens, bool)
        ):
            return input_tokens + output_tokens
    for key in ("total_tokens", "tokens"):
        value = run_obj.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return value
    return None


def extract_served_model(run_obj: Any, events: Any = None) -> Optional[str]:
    """The model the run actually served (``run_obj['model']``/``usage``), if exposed."""
    if isinstance(run_obj, dict):
        for key in ("model", "model_name", "served_model", "model_used"):
            value = run_obj.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        usage = run_obj.get("usage")
        if isinstance(usage, dict):
            for key in ("model", "model_name"):
                value = usage.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    if isinstance(events, list):
        for event in events:
            if not isinstance(event, dict):
                continue
            for key in ("model", "model_name"):
                value = event.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return None


# --------------------------------------------------------------------------- #
# Criteria.
# --------------------------------------------------------------------------- #


def _blob_text(value: Any) -> str:
    """Plain text of a payload: strings as-is, containers as their JSON form."""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError):
            return ""
    return ""


def run_evidence_text(
    run_obj: Any, events: Any, run_id: str
) -> list[str]:
    """Text blobs produced by THIS run (output + events), for criterion evidence.

    The run object is accepted only when it carries no ``run_id`` or carries the
    same one; events owned by another run are ignored. This is what makes an
    attempt's success independent of the shared lab state.
    """
    blobs: list[str] = []
    if isinstance(run_obj, dict):
        owner = run_obj.get("run_id")
        if not isinstance(owner, str) or owner == run_id:
            for key in ("output", "result", "final_output", "summary", "text", "message"):
                text = _blob_text(run_obj.get(key))
                if text:
                    blobs.append(text)
    if isinstance(events, list):
        for event in events:
            if isinstance(event, dict) and _event_belongs_to_run(event, run_id):
                text = _blob_text(event)
                if text:
                    blobs.append(text)
    return blobs


def check_flag_criterion(
    run_obj: Any, events: Any, run_id: str
) -> tuple[bool, str]:
    """True when THIS run's output/events contain the captured ``CTF{...}`` flag.

    The lab ``check-flag`` probe is only a preflight (it reads the live lab, so it
    cannot evidence an individual attempt: attempt 1 could make attempts 2-3 pass).
    """
    for blob in run_evidence_text(run_obj, events, run_id):
        match = FLAG_RE.search(blob)
        if match:
            return True, f"run {run_id} captured {match.group(0)}"
    return False, f"no CTF{{...}} flag in the output/events of run {run_id}"


def evidence_contains_uid(evidence: Any) -> bool:
    """True when a finding evidence payload contains the `uid=` marker."""
    if isinstance(evidence, str):
        return "uid=" in evidence
    if isinstance(evidence, dict):
        for key in ("output", "command", "raw", "text"):
            value = evidence.get(key)
            if isinstance(value, str) and "uid=" in value:
                return True
        try:
            return "uid=" in json.dumps(evidence, ensure_ascii=False)
        except (TypeError, ValueError):
            return False
    return False


def _read_findings_jsonl(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    findings.append(item)
    except OSError:
        return []
    return findings


def _finding_dicts_from_run(run_obj: Any, events: Any) -> list[dict[str, Any]]:
    """Collects finding-shaped dicts from the run output and its events.

    ``GET /v1/runs/{id}`` never returns a ``findings`` field, so the durable
    store (``BENCH_FINDINGS_PATH``) is the canonical source; the run output and
    the ``record_finding`` tool calls mirrored in the event backlog are a
    best-effort secondary source.
    """
    roots: list[Any] = []
    if isinstance(run_obj, dict):
        for key in ("output", "result", "final_output", "summary", "text"):
            if run_obj.get(key) is not None:
                roots.append(run_obj.get(key))
    if isinstance(events, list):
        roots.extend(event for event in events if isinstance(event, dict))

    findings: list[dict[str, Any]] = []
    seen: set[int] = set()
    stack: list[Any] = list(roots)
    budget = 20000
    while stack and budget > 0:
        current = stack.pop()
        budget -= 1
        if isinstance(current, dict):
            if id(current) in seen:
                continue
            seen.add(id(current))
            if "state" in current and "evidence" in current:
                findings.append(current)
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, str):
            text = current.strip()
            if text.startswith("{") and text.endswith("}"):
                try:
                    parsed = json.loads(text)
                except ValueError:
                    continue
                if isinstance(parsed, dict):
                    stack.append(parsed)
    return findings


def check_rce_evidence(
    run_obj: Any, events: Any = None, findings_path: Optional[Path] = None
) -> tuple[bool, str]:
    """True when a confirmed finding carries evidence containing `uid=`."""
    findings: list[dict[str, Any]] = []
    if findings_path is not None:
        findings.extend(_read_findings_jsonl(findings_path))
    findings.extend(_finding_dicts_from_run(run_obj, events))
    for finding in findings:
        state = finding.get("state")
        if not isinstance(state, str) or state.strip().lower() != "confirmed":
            continue
        if evidence_contains_uid(finding.get("evidence")):
            finding_id = finding.get("id")
            label = finding_id if isinstance(finding_id, str) else "<no id>"
            return True, f"confirmed finding {label!r} has 'uid=' evidence"
    return False, "no confirmed finding with 'uid=' evidence"


def verify_criterion(
    task: dict[str, Any],
    run_obj: Any,
    events: Any,
    run_id: str,
    findings_path: Optional[Path] = None,
) -> tuple[bool, str]:
    """Dispatches the task criterion; never raises."""
    criterion = task.get("criterion")
    if criterion == "flag":
        return check_flag_criterion(run_obj, events, run_id)
    if criterion == "rce_evidence":
        return check_rce_evidence(run_obj, events, findings_path=findings_path)
    return False, f"unknown criterion: {criterion!r}"


# --------------------------------------------------------------------------- #
# Lab preflight and optional reset.
# --------------------------------------------------------------------------- #


def run_lab_command(
    repo_root: Path, lab: str, args: tuple[str, ...], timeout: float
) -> tuple[int, str]:
    """Runs ``labs/<lab>/run_agent_test.py <args>``; returns (exit code, output)."""
    script = repo_root / "labs" / lab / "run_agent_test.py"
    try:
        proc = subprocess.run(
            [sys.executable, str(script), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(repo_root),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, f"could not run {script}: {exc.__class__.__name__}: {exc}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def preflight_lab(
    task: dict[str, Any], repo_root: Path, *, require_clean: bool = True
) -> tuple[bool, str]:
    """Checks that the lab is present and running, for ANY criterion that needs it.

    For the ``flag`` criterion it additionally runs the lab ``check-flag`` as a
    PREFLIGHT ONLY (never as attempt evidence) and requires the lab to be clean:
    a flag already readable as ``agent_user`` means a previous attempt leaked into
    this one, so the benchmark must be reset first.
    """
    lab = task.get("lab")
    if not isinstance(lab, str) or not lab:
        return False, "task has no lab"
    lab_dir = repo_root / "labs" / lab
    if not lab_dir.is_dir():
        return False, f"lab directory not found: {lab_dir}"
    script = lab_dir / "run_agent_test.py"
    if not script.is_file():
        return False, f"lab runner not found: {script}"
    code, output = run_lab_command(repo_root, lab, ("status",), LAB_CMD_TIMEOUT_S)
    if code != 0:
        return False, output.strip() or f"lab status exited {code}"
    if task.get("criterion") == "flag" and require_clean:
        code, output = run_lab_command(repo_root, lab, ("check-flag",), LAB_CMD_TIMEOUT_S)
        text = output.strip()
        if code == 0 or "CTF{" in output:
            return False, (
                "the lab is not clean: the flag is already readable as agent_user "
                f"({text or 'check-flag exited 0'}). Reset it with BENCH_RESET_LAB=1 "
                f"or: docker compose -f labs/{lab}/docker-compose.yml down && "
                f"docker compose -f labs/{lab}/docker-compose.yml up -d --build"
            )
        if code != 1:
            return False, f"could not verify the lab state: {text or f'check-flag exited {code}'}"
    return True, "lab present and clean"


def reset_lab(repo_root: Path, lab: str) -> tuple[bool, str]:
    """Recreates the lab with docker compose (the optional BENCH_RESET_LAB path)."""
    compose = repo_root / "labs" / lab / "docker-compose.yml"
    if not compose.is_file():
        return False, f"lab compose file not found: {compose}"
    for args in (("down",), ("up", "-d", "--build")):
        try:
            proc = subprocess.run(
                ["docker", "compose", "-f", str(compose), *args],
                capture_output=True,
                text=True,
                timeout=LAB_RESET_TIMEOUT_S,
                cwd=str(repo_root),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, (
                f"could not run docker compose {' '.join(args)}: "
                f"{exc.__class__.__name__}: {exc}"
            )
        if proc.returncode != 0:
            output = ((proc.stdout or "") + (proc.stderr or "")).strip()
            return False, f"docker compose {' '.join(args)} exited {proc.returncode}: {output}"
    return True, f"lab {lab} recreated"


# --------------------------------------------------------------------------- #
# Execution.
# --------------------------------------------------------------------------- #


def run_attempt(
    task: dict[str, Any],
    attempt_number: int,
    *,
    url: str,
    key: str,
    repo_root: Path,
    model: Optional[str] = None,
    findings_path: Optional[Path] = None,
) -> dict[str, Any]:
    """Runs one benchmark attempt and returns its fixed-schema record."""
    record: dict[str, Any] = {
        "attempt": attempt_number,
        "run_id": None,
        "status": None,
        "success": False,
        "criterion_ok": False,
        "criterion_detail": None,
        "steps": None,
        "wall_time_s": 0.0,
        "tokens": None,
        "served_model": None,
        "timed_out": False,
        "stopped": False,
        "error": None,
    }
    started = time.monotonic()
    try:
        prompt = task.get("prompt")
        if not isinstance(prompt, str) or not prompt.strip():
            raise ApiError("task has no prompt")
        run_id = start_run(url, key, prompt, model=model)
        record["run_id"] = run_id
        timeout = task.get("timeout")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or timeout <= 0:
            timeout = 1800.0
        run_obj, stopped = poll_run(url, key, run_id, float(timeout))
        record["wall_time_s"] = round(time.monotonic() - started, 3)
        record["status"] = run_status(run_obj)
        record["timed_out"] = not is_terminal(run_obj)
        record["stopped"] = stopped
        events = fetch_events(url, key, run_id)
        record["steps"] = count_tool_steps(events)
        record["tokens"] = extract_tokens(run_obj)
        record["served_model"] = extract_served_model(run_obj, events)
        ok, detail = verify_criterion(
            task, run_obj, events, run_id, findings_path=findings_path
        )
        record["criterion_ok"] = bool(ok)
        record["criterion_detail"] = detail
        record["success"] = bool(ok)
    except ApiError as exc:
        record["wall_time_s"] = round(time.monotonic() - started, 3)
        record["status"] = record["status"] or "error"
        record["error"] = str(exc)
    return record


def aggregate(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Median and success rate over the attempts."""
    wall: list[float] = []
    steps: list[int] = []
    tokens: list[int] = []
    successes = 0
    for record in records:
        value = record.get("wall_time_s")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            wall.append(float(value))
        value = record.get("steps")
        if isinstance(value, int) and not isinstance(value, bool):
            steps.append(value)
        value = record.get("tokens")
        if isinstance(value, int) and not isinstance(value, bool):
            tokens.append(value)
        if record.get("success"):
            successes += 1
    return {
        "runs": len(records),
        "success_count": successes,
        "success_rate": round(successes / len(records), 4) if records else 0.0,
        "median_wall_time_s": round(statistics.median(wall), 3) if wall else None,
        "median_steps": statistics.median(steps) if steps else None,
        "median_tokens": statistics.median(tokens) if tokens else None,
    }


def _served_model_of(records: list[dict[str, Any]]) -> Optional[str]:
    served: Optional[str] = None
    for record in records:
        value = record.get("served_model")
        if isinstance(value, str) and value.strip():
            served = value.strip()
    return served


def build_result(
    task: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    model: Optional[str],
    url: str,
    benchmark_version: int,
    started_at: str,
    manifest_sha256: str,
) -> dict[str, Any]:
    """Builds the fixed-schema result document."""
    stats = aggregate(records)
    return {
        "schema": RESULT_SCHEMA,
        "benchmark_version": benchmark_version,
        "task_id": task.get("id"),
        "lab": task.get("lab"),
        "criterion": task.get("criterion"),
        "target": task.get("target"),
        "prompt": task.get("prompt"),
        "model": model,
        "served_model": _served_model_of(records),
        "api_url": url,
        "manifest_sha256": manifest_sha256,
        "started_at": started_at,
        "finished_at": _utc_now(),
        "runs_requested": stats["runs"],
        "success_count": stats["success_count"],
        "success_rate": stats["success_rate"],
        "median_wall_time_s": stats["median_wall_time_s"],
        "median_steps": stats["median_steps"],
        "median_tokens": stats["median_tokens"],
        "attempts": records,
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _format(value: Any, suffix: str = "") -> str:
    if value is None:
        return "n/a"
    if suffix:
        return f"{value}{suffix}"
    return str(value)


def render_markdown(result: dict[str, Any]) -> str:
    """Renders the Markdown summary of a result document."""
    lines = [
        f"# Benchmark result - {result['task_id']}",
        "",
        f"- Benchmark version: {result['benchmark_version']}",
        f"- Task: {result['task_id']}",
        f"- Lab: {result['lab']}",
        f"- Criterion: {result['criterion']}",
        f"- Target: {result['target']}",
        f"- Model (requested): {result['model'] or 'not recorded'}",
        f"- Model (served): {result['served_model'] or 'not exposed'}",
        f"- Manifest SHA-256: {result['manifest_sha256']}",
        f"- API: {result['api_url']}",
        f"- Runs: {result['runs_requested']}",
        f"- Success rate: {result['success_count']}/{result['runs_requested']} "
        f"({result['success_rate']:.3f})",
        f"- Median wall time: {_format(result['median_wall_time_s'], 's')}",
        f"- Median steps: {_format(result['median_steps'])}",
        f"- Median tokens: {_format(result['median_tokens'])}",
        "",
        "## Attempts",
        "",
        "| # | run_id | status | success | steps | wall_time_s | tokens | stopped | detail |",
        "|---|--------|--------|---------|-------|--------------|--------|---------|--------|",
    ]
    for attempt in result["attempts"]:
        detail = attempt.get("criterion_detail") or attempt.get("error") or ""
        detail = str(detail).replace("|", "/").replace("\n", " ").strip()
        tokens = attempt.get("tokens")
        lines.append(
            "| {attempt} | {run_id} | {status} | {success} | {steps} | {wall} | {tokens} | "
            "{stopped} | {detail} |".format(
                attempt=attempt.get("attempt"),
                run_id=attempt.get("run_id") or "-",
                status=attempt.get("status") or "-",
                success="yes" if attempt.get("success") else "no",
                steps="-" if attempt.get("steps") is None else attempt.get("steps"),
                wall=attempt.get("wall_time_s"),
                tokens="-" if tokens is None else tokens,
                stopped="yes" if attempt.get("stopped") else "no",
                detail=detail,
            )
        )
    return "\n".join(lines) + "\n"


def _atomic_write_pair(
    json_path: Path, json_text: str, markdown_path: Path, markdown_text: str
) -> None:
    """Writes both result files through temporaries, then renames them into place."""
    tmp_json = json_path.with_name(json_path.name + ".tmp")
    tmp_markdown = markdown_path.with_name(markdown_path.name + ".tmp")
    try:
        tmp_json.write_text(json_text, encoding="utf-8")
        tmp_markdown.write_text(markdown_text, encoding="utf-8")
        os.replace(tmp_json, json_path)
        os.replace(tmp_markdown, markdown_path)
    except OSError:
        for tmp in (tmp_json, tmp_markdown):
            try:
                tmp.unlink()
            except OSError:
                pass
        raise


def write_results(
    result: dict[str, Any], results_dir: Path
) -> Optional[tuple[Path, Path]]:
    """Writes the JSON result and the Markdown summary; returns their paths.

    The base name carries a random suffix so two runs in the same second do not
    overwrite each other, and both files are written atomically. Returns None
    (and reports on stderr) when the files cannot be written, so a broken output
    directory never escapes as a traceback.
    """
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"{result['task_id']}-{stamp}-{uuid.uuid4().hex[:8]}"
    json_path = results_dir / f"{base}.json"
    markdown_path = results_dir / f"{base}.md"
    try:
        results_dir.mkdir(parents=True, exist_ok=True)
        _atomic_write_pair(
            json_path,
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            markdown_path,
            render_markdown(result),
        )
    except OSError as exc:
        print(f"error: cannot write results under {results_dir}: {exc}", file=sys.stderr)
        return None
    return json_path, markdown_path


# --------------------------------------------------------------------------- #
# Environment helpers.
# --------------------------------------------------------------------------- #


def _read_env_key(env_path: Path) -> Optional[str]:
    """Reads HERMES_API_SERVER_KEY from the repo .env (best effort)."""
    try:
        text = env_path.read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, sep, value = stripped.partition("=")
        if not sep or key.strip() != "HERMES_API_SERVER_KEY":
            continue
        value = value.strip().strip('"').strip("'")
        return value or None
    return None


def _int_env(name: str, default: int) -> Optional[int]:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return None


def _flag_env(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def print_runbook(task: dict[str, Any], reason: str, repo_root: Path) -> None:
    """Prints the RUNBOOK commands to bring the stack and the lab up."""
    lab = task.get("lab")
    print(f"benchmark not run: {reason}", file=sys.stderr)
    print("See docs/RUNBOOK.md. Minimal commands:", file=sys.stderr)
    print("  # 1) start the vulnerator-ai stack (from the repo root)", file=sys.stderr)
    print("  docker compose up -d --no-build", file=sys.stderr)
    print("  curl -s http://localhost:8642/health", file=sys.stderr)
    if isinstance(lab, str) and lab:
        print("  # 2) start the lab", file=sys.stderr)
        print(f"  cd labs/{lab} && docker compose up -d --build", file=sys.stderr)
        if (repo_root / "labs" / lab / "run_agent_test.py").is_file():
            print(f"  python3 labs/{lab}/run_agent_test.py status", file=sys.stderr)


# --------------------------------------------------------------------------- #
# CLI.
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Portable vulnerator-ai benchmark runner (stdlib only)."
    )
    parser.add_argument(
        "--task",
        default=None,
        help=f"task id or lab (default: BENCH_LAB or {DEFAULT_LAB})",
    )
    parser.add_argument("--runs", type=int, default=None, help="attempts (default: BENCH_RUNS or 3)")
    parser.add_argument("--api-url", default=None, help=f"default: HERMES_API_URL or {DEFAULT_API_URL}")
    parser.add_argument("--api-key", default=None, help="default: HERMES_API_KEY or .env")
    parser.add_argument("--model", default=None, help="default: BENCH_MODEL")
    parser.add_argument("--manifest", default=None, help=f"default: {MANIFEST_PATH}")
    parser.add_argument("--results-dir", default=None, help=f"default: {RESULTS_DIR}")
    parser.add_argument("--list", action="store_true", help="list the manifest tasks and exit")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    manifest_path = Path(args.manifest) if args.manifest else MANIFEST_PATH
    try:
        manifest = load_manifest(manifest_path)
    except ManifestError as exc:
        print(f"error: cannot load manifest {manifest_path}: {exc}", file=sys.stderr)
        return 1

    tasks = manifest["tasks"]
    if args.list:
        for task in tasks:
            print(
                f"{task['id']}\tlab={task['lab']}\tenabled={task['enabled']}\t"
                f"criterion={task['criterion']}"
            )
        return 0

    wanted = args.task or os.environ.get("BENCH_LAB") or DEFAULT_LAB
    task = select_task(tasks, wanted)
    if task is None:
        available = ", ".join(str(item["id"]) for item in tasks)
        print(f"error: unknown task {wanted!r}. Available: {available}", file=sys.stderr)
        return 1
    if task.get("enabled") is not True:
        note = task.get("note")
        suffix = f": {note}" if isinstance(note, str) else ""
        print(f"error: task {task['id']!r} is disabled in {manifest_path}{suffix}", file=sys.stderr)
        return 1

    api_url = args.api_url or os.environ.get("HERMES_API_URL") or DEFAULT_API_URL
    api_key = args.api_key or os.environ.get("HERMES_API_KEY") or _read_env_key(REPO_ROOT / ".env")
    model = args.model or os.environ.get("BENCH_MODEL") or None
    runs = args.runs if args.runs is not None else _int_env("BENCH_RUNS", DEFAULT_RUNS)
    if runs is None or runs <= 0:
        print("error: BENCH_RUNS must be a positive integer", file=sys.stderr)
        return 1
    results_dir = Path(args.results_dir) if args.results_dir else RESULTS_DIR
    findings_path = os.environ.get("BENCH_FINDINGS_PATH") or None
    reset_enabled = _flag_env("BENCH_RESET_LAB", False)

    if not api_key:
        print_runbook(task, "no API key (set HERMES_API_KEY or HERMES_API_SERVER_KEY in .env)", REPO_ROOT)
        return 1
    config_error = validate_api_config(api_url, api_key)
    if config_error:
        print(f"error: {config_error}", file=sys.stderr)
        return 1

    try:
        health_check(api_url, api_key)
    except ApiError as exc:
        print_runbook(task, f"the stack is not reachable at {api_url}: {exc}", REPO_ROOT)
        return 1

    lab_ok, lab_detail = preflight_lab(task, REPO_ROOT, require_clean=not reset_enabled)
    if not lab_ok:
        print_runbook(task, lab_detail, REPO_ROOT)
        return 1

    try:
        manifest_digest = manifest_sha256(manifest_path)
    except OSError as exc:
        print(f"error: cannot hash manifest {manifest_path}: {exc}", file=sys.stderr)
        return 1

    started_at = _utc_now()
    records: list[dict[str, Any]] = []
    for number in range(1, runs + 1):
        if reset_enabled:
            reset_ok, reset_detail = reset_lab(REPO_ROOT, str(task["lab"]))
            if not reset_ok:
                print(f"error: cannot reset lab {task['lab']!r}: {reset_detail}", file=sys.stderr)
                return 1
            print(f"lab reset: {reset_detail}")
        record = run_attempt(
            task,
            number,
            url=api_url,
            key=api_key,
            repo_root=REPO_ROOT,
            model=model,
            findings_path=Path(findings_path) if findings_path else None,
        )
        records.append(record)
        print(
            f"[{number}/{runs}] status={record['status']} success={record['success']} "
            f"steps={record['steps']} wall_time_s={record['wall_time_s']} "
            f"tokens={record['tokens']} stopped={record['stopped']}"
        )

    result = build_result(
        task,
        records,
        model=model,
        url=api_url,
        benchmark_version=manifest["benchmark_version"],
        started_at=started_at,
        manifest_sha256=manifest_digest,
    )
    written = write_results(result, results_dir)
    if written is None:
        return 1
    json_path, markdown_path = written
    stats = aggregate(records)
    print(
        f"success_rate={stats['success_rate']:.3f} "
        f"median_wall_time_s={stats['median_wall_time_s']} "
        f"median_steps={stats['median_steps']} median_tokens={stats['median_tokens']} "
        f"served_model={result['served_model']}"
    )
    print(f"wrote {json_path}")
    print(f"wrote {markdown_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
