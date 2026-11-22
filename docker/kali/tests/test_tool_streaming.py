"""Tests stdlib-only de las primitivas de streaming (`docker/kali/tool_streaming.py`).

They do not import `mcp`/`anyio`: only standard library + pytest. They verify reading
incremental por cursor, orden de `seq`, timeout con muerte del grupo (sin
orphans) and the semantics of an empty page at the end of the cursor.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path

# The module under test lives in docker/kali/ (alongside the MCP server, which is NOT
# imported here because it pulls in `mcp`/`anyio`). We add it to the path explicitly.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tool_streaming  # noqa: E402


def _new_id() -> str:
    return uuid.uuid4().hex


def test_incremental_reads_by_cursor_in_seq_order() -> None:
    """A slow command is read in several pages; the final one reports done and seq order."""
    execution_id = _new_id()
    code = "import sys,time\nfor i in range(5):\n print(i, flush=True); time.sleep(0.2)"
    cmd = [sys.executable, "-c", code]

    done_holder: dict[str, tuple[int, bool, bool]] = {}

    import threading

    def runner() -> None:
        done_holder["result"] = tool_streaming.run_tool_streaming(
            cmd, execution_id, timeout=30
        )

    thread = threading.Thread(target=runner)
    thread.start()

    # Incremental reading: advance the cursor and accumulate pages while it runs.
    cursor = 0
    collected: list[dict] = []
    got_a_partial_page = False
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        page = tool_streaming.read(execution_id, cursor)
        if page["lines"]:
            collected.extend(page["lines"])
            cursor = page["next_cursor"]
            # If it has not finished and we already have output, incrementality is confirmed.
            if not page["done"] and len(collected) < 5:
                got_a_partial_page = True
        if page["done"]:
            # Drenamos cualquier cola pendiente tras done.
            tail = tool_streaming.read(execution_id, cursor)
            collected.extend(tail["lines"])
            cursor = tail["next_cursor"]
            break
        time.sleep(0.1)

    thread.join(timeout=10)

    returncode, timed_out, cancelled = done_holder["result"]
    assert timed_out is False
    assert cancelled is False
    assert returncode == 0

    stdout_lines = [line for line in collected if line["stream"] == "stdout"]
    texts = [line["text"] for line in stdout_lines]
    assert texts == ["0", "1", "2", "3", "4"]

    # seq estrictamente creciente en el orden entregado.
    seqs = [line["seq"] for line in collected]
    assert seqs == sorted(seqs)
    assert len(seqs) == len(set(seqs))

    # At least one partial page was observed (live reading, not only at the end).
    assert got_a_partial_page


def test_timeout_kills_process_group_no_orphans() -> None:
    """A command sleeping past the timeout -> timed_out=True and no live children."""
    execution_id = _new_id()
    # Hijo que a su vez crea un nieto en el mismo grupo; ambos deben morir.
    code = (
        "import os,sys,time,subprocess\n"
        "child = subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
        "print(child.pid, flush=True)\n"
        "time.sleep(60)\n"
    )
    cmd = [sys.executable, "-c", code]

    start = time.monotonic()
    returncode, timed_out, cancelled = tool_streaming.run_tool_streaming(
        cmd, execution_id, timeout=1
    )
    elapsed = time.monotonic() - start

    assert timed_out is True
    # A timeout is NOT a cancellation: they are distinguishable states.
    assert cancelled is False
    # It must not wait 60s: the 1s timeout killed the group with margin.
    assert elapsed < 20

    # The grandchild's PID is in the output; we check it no longer exists.
    page = tool_streaming.read(execution_id, 0)
    grandchild_pid = None
    for line in page["lines"]:
        if line["stream"] == "stdout" and line["text"].strip().isdigit():
            grandchild_pid = int(line["text"].strip())
            break

    assert page["done"] is True

    if grandchild_pid is not None:
        # Give the signal a moment to propagate to the group.
        time.sleep(0.5)
        alive = _pid_alive(grandchild_pid)
        assert alive is False


def _pid_alive(pid: int) -> bool:
    """True if the process exists (signal 0 does not kill, only checks)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def test_request_cancel_kills_process_group_no_orphans() -> None:
    """request_cancel kills the group (no orphans) and marks cancelled=True (≠ timed_out)."""
    execution_id = _new_id()
    # Parent (group leader) with a child in the SAME group; cancel must kill both.
    code = (
        "import os,sys,time,subprocess\n"
        "child = subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
        "print(child.pid, flush=True)\n"
        "time.sleep(60)\n"
    )
    cmd = [sys.executable, "-c", code]

    holder: dict[str, tuple[int, bool, bool]] = {}

    def runner() -> None:
        holder["result"] = tool_streaming.run_tool_streaming(
            cmd, execution_id, timeout=60
        )

    thread = threading.Thread(target=runner)
    thread.start()

    # Wait for the process to be registered (alive) before cancelling.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with tool_streaming._procs_lock:
            registered = execution_id in tool_streaming._procs
        if registered:
            break
        time.sleep(0.02)

    killed = tool_streaming.request_cancel(execution_id)
    thread.join(timeout=15)
    assert not thread.is_alive()

    _returncode, timed_out, cancelled = holder["result"]
    assert cancelled is True
    assert timed_out is False  # cancellation ≠ timeout (distinguishable states)
    assert killed is True

    # The grandchild (its PID is in the output) no longer exists: group dead, no orphans.
    page = tool_streaming.read(execution_id, 0)
    grandchild_pid = None
    for line in page["lines"]:
        if line["stream"] == "stdout" and line["text"].strip().isdigit():
            grandchild_pid = int(line["text"].strip())
            break
    if grandchild_pid is not None:
        time.sleep(0.5)
        assert _pid_alive(grandchild_pid) is False


def test_read_at_tail_returns_empty_page_and_same_cursor() -> None:
    """Read with the cursor at the tail: empty page and unchanged next_cursor."""
    execution_id = _new_id()
    cmd = [sys.executable, "-c", "print('only-line', flush=True)"]
    tool_streaming.run_tool_streaming(cmd, execution_id, timeout=10)

    first = tool_streaming.read(execution_id, 0)
    assert first["lines"]
    tail_cursor = first["next_cursor"]

    second = tool_streaming.read(execution_id, tail_cursor)
    assert second["lines"] == []
    assert second["next_cursor"] == tail_cursor
    assert second["done"] is True


def test_unknown_execution_id_is_empty() -> None:
    """An unknown execution_id does not crash: empty page, not done."""
    page = tool_streaming.read("does-not-exist", 0)
    assert page["lines"] == []
    assert page["next_cursor"] == 0
    assert page["done"] is False


def test_unknown_status_is_unknown() -> None:
    """get_status de un execution_id no registrado devuelve {'status':'unknown'}."""
    assert tool_streaming.get_status("never-started") == {"status": "unknown"}


def test_start_background_returns_before_process_ends() -> None:
    """start_background RETURNS a Thread and status is 'running' right after launch."""
    execution_id = _new_id()
    # Worker lento (duerme antes de imprimir) para que, justo tras lanzar, siga vivo.
    code = "import time;time.sleep(1.0);print('late', flush=True)"
    cmd = [sys.executable, "-c", code]

    def worker() -> dict:
        rc, timed_out, _cancelled = tool_streaming.run_tool_streaming(
            cmd, execution_id, timeout=30
        )
        return {"status": "done", "returncode": rc, "timed_out": timed_out, "value": 42}

    thread = tool_streaming.start_background(execution_id, worker)
    try:
        assert isinstance(thread, threading.Thread)
        # Immediately after launch: still running (the worker sleeps 1s).
        assert tool_streaming.get_status(execution_id) == {"status": "running"}
    finally:
        thread.join(timeout=15)


def test_start_background_transitions_running_to_done() -> None:
    """get_status pasa de 'running' a 'done' con los campos devueltos por el worker."""
    execution_id = _new_id()
    code = "import time;time.sleep(0.4);print('ok', flush=True)"
    cmd = [sys.executable, "-c", code]

    def worker() -> dict:
        rc, timed_out, _cancelled = tool_streaming.run_tool_streaming(
            cmd, execution_id, timeout=30
        )
        return {"status": "done", "returncode": rc, "timed_out": timed_out, "value": 42}

    thread = tool_streaming.start_background(execution_id, worker)
    # Al principio 'running'.
    assert tool_streaming.get_status(execution_id)["status"] == "running"

    thread.join(timeout=15)
    final = tool_streaming.get_status(execution_id)
    assert final["status"] == "done"
    assert final["returncode"] == 0
    assert final["timed_out"] is False
    assert final["value"] == 42

    # The worker's output reached the ring (streaming reused).
    page = tool_streaming.read(execution_id, 0)
    texts = [line["text"] for line in page["lines"] if line["stream"] == "stdout"]
    assert texts == ["ok"]


def test_start_background_worker_raises_marks_failed() -> None:
    """Un worker que lanza -> get_status 'failed' con 'error' (sin reventar el hilo)."""
    execution_id = _new_id()

    def worker() -> dict:
        raise RuntimeError("boom-xyz")

    thread = tool_streaming.start_background(execution_id, worker)
    thread.join(timeout=10)

    status = tool_streaming.get_status(execution_id)
    assert status["status"] == "failed"
    assert "boom-xyz" in status["error"]


# --- Findings pagination (fix for the 1 MiB SSE limit) --------------------


def _small_finding(i: int) -> dict:
    """A minimal small finding for order/count tests."""
    return {"check_id": f"check_{i}", "index": i, "severity": "low"}


def _sized_finding(i: int, payload_bytes: int) -> dict:
    """A finding whose JSON size is around `payload_bytes` (controlled padding)."""
    return {"check_id": f"check_{i}", "index": i, "blob": "x" * payload_bytes}


def test_set_findings_then_read_paginates_in_order() -> None:
    """250 small findings -> pages of 100/100/50, order preserved, done at the end."""
    execution_id = _new_id()
    findings = [_small_finding(i) for i in range(250)]
    tool_streaming.set_findings(execution_id, findings)

    collected: list[dict] = []
    cursor = 0
    pages = 0
    page_sizes: list[int] = []
    while True:
        page = tool_streaming.read_findings(execution_id, cursor)
        pages += 1
        page_sizes.append(len(page["findings"]))
        collected.extend(page["findings"])
        cursor = page["next_cursor"]
        if page["done"]:
            break
        assert pages < 100  # guarda anti-bucle en el propio test

    assert page_sizes == [100, 100, 50]
    assert cursor == 250
    # Order preserved and concatenation == original.
    assert [f["index"] for f in collected] == list(range(250))
    assert collected == findings


def test_read_findings_unknown_execution_id_empty_done() -> None:
    """unknown execution_id -> empty page, next_cursor=cursor, done=True."""
    page = tool_streaming.read_findings("does-not-exist", 0)
    assert page["findings"] == []
    assert page["next_cursor"] == 0
    assert page["done"] is True


def test_read_findings_byte_budget_caps_page() -> None:
    """Findings ~50 KiB -> each page bounded by bytes (<= max) and complete."""
    execution_id = _new_id()
    # ~50 KiB de relleno por finding: el tope de 256 KiB manda sobre el de 100.
    findings = [_sized_finding(i, 50 * 1024) for i in range(20)]
    tool_streaming.set_findings(execution_id, findings)

    collected: list[dict] = []
    cursor = 0
    multipage = False
    guard = 0
    while True:
        page = tool_streaming.read_findings(execution_id, cursor)
        guard += 1
        assert guard < 100
        # No page (with >1 finding) exceeds the byte budget.
        if len(page["findings"]) > 1:
            # The JSON array adds commas/brackets; we compare the sum of items.
            items_bytes = sum(
                len(json.dumps(f).encode("utf-8")) for f in page["findings"]
            )
            assert items_bytes <= tool_streaming.FINDINGS_PAGE_MAX_BYTES
        # The byte cap is reached before the 100 cap -> there are several pages.
        if not page["done"]:
            multipage = True
            assert len(page["findings"]) < 100
        collected.extend(page["findings"])
        cursor = page["next_cursor"]
        if page["done"]:
            break

    assert multipage is True
    assert collected == findings
    assert cursor == 20


def test_read_findings_single_oversized_finding_returned() -> None:
    """A single finding > budget -> page of 1 (anti-starvation), done=True."""
    execution_id = _new_id()
    big = _sized_finding(0, tool_streaming.FINDINGS_PAGE_MAX_BYTES + 10_000)
    tool_streaming.set_findings(execution_id, [big])

    page = tool_streaming.read_findings(execution_id, 0)
    assert len(page["findings"]) == 1
    assert page["findings"][0]["index"] == 0
    assert page["next_cursor"] == 1
    assert page["done"] is True


def test_read_findings_explicit_limit() -> None:
    """limit=10 bounds the page to <=10 findings even if more fit by bytes."""
    execution_id = _new_id()
    findings = [_small_finding(i) for i in range(30)]
    tool_streaming.set_findings(execution_id, findings)

    page = tool_streaming.read_findings(execution_id, 0, limit=10)
    assert len(page["findings"]) == 10
    assert page["next_cursor"] == 10
    assert page["done"] is False


def test_read_findings_cursor_at_tail_empty_done() -> None:
    """cursor at the tail (== total) -> empty page, done=True, no crash."""
    execution_id = _new_id()
    findings = [_small_finding(i) for i in range(5)]
    tool_streaming.set_findings(execution_id, findings)

    page = tool_streaming.read_findings(execution_id, 5)
    assert page["findings"] == []
    assert page["next_cursor"] == 5
    assert page["done"] is True

    # A scan with no findings: the first read is already empty and done.
    empty_id = _new_id()
    tool_streaming.set_findings(empty_id, [])
    first = tool_streaming.read_findings(empty_id, 0)
    assert first["findings"] == []
    assert first["done"] is True


# --- COMPLETE output sink (audit, bypass of the RING_MAXLEN cap) --------


def test_raw_sink_captures_all_lines_beyond_ring_cap(tmp_path) -> None:
    """The sink receives ALL lines; the ring only the last RING_MAXLEN."""
    execution_id = _new_id()
    sink_path = tmp_path / "raw.out"
    total = tool_streaming.RING_MAXLEN + 100  # deliberately exceeds the ring cap

    tool_streaming.open_raw_sink(execution_id, str(sink_path))
    for i in range(total):
        tool_streaming.append(execution_id, "stdout", f"line-{i}")
    tool_streaming.close_raw_sink(execution_id)

    # The sink has ALL lines, in order, intact.
    sink_lines = sink_path.read_text(encoding="utf-8").splitlines()
    assert len(sink_lines) == total
    assert sink_lines[0] == "[stdout] line-0"
    assert sink_lines[-1] == f"[stdout] line-{total - 1}"

    # The ring, in contrast, is capped: only the last RING_MAXLEN (context protection).
    page = tool_streaming.read(execution_id, 0)
    assert len(page["lines"]) == tool_streaming.RING_MAXLEN
    assert page["lines"][0]["text"] == f"line-{total - tool_streaming.RING_MAXLEN}"
    assert page["lines"][-1]["text"] == f"line-{total - 1}"


def test_sink_absent_append_writes_no_file(tmp_path) -> None:
    """Without open_raw_sink, append works the same and creates no sink file."""
    execution_id = _new_id()
    tool_streaming.append(execution_id, "stdout", "no-sink-line")
    page = tool_streaming.read(execution_id, 0)
    assert [line["text"] for line in page["lines"]] == ["no-sink-line"]
    # Nothing was created in tmp (no sink was open).
    assert list(tmp_path.iterdir()) == []


def test_close_raw_sink_unknown_execution_is_noop() -> None:
    """close_raw_sink de un execution_id desconocido no revienta."""
    tool_streaming.close_raw_sink("does-not-exist-sink")  # no debe lanzar


def test_open_raw_sink_bad_path_returns_none_fail_open(tmp_path) -> None:
    """Un path imposible -> open_raw_sink devuelve None (fail-open) sin romper append."""
    execution_id = _new_id()
    bad = tmp_path / "no-such-dir" / "raw.out"  # el dir intermedio no existe
    handle = tool_streaming.open_raw_sink(execution_id, str(bad))
    assert handle is None
    # append sigue funcionando (al ring), solo que sin sink.
    tool_streaming.append(execution_id, "stdout", "still-works")
    page = tool_streaming.read(execution_id, 0)
    assert [line["text"] for line in page["lines"]] == ["still-works"]
