"""Tests stdlib-only de las primitivas de streaming (`docker/kali/tool_streaming.py`).

No importan `mcp`/`anyio`: sólo librería estándar + pytest. Verifican lectura
incremental por cursor, orden de `seq`, timeout con muerte del grupo (sin
huérfanos) y la semántica de una página vacía al final del cursor.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path

# El módulo bajo prueba vive en docker/kali/ (junto al servidor MCP, que NO se
# importa aquí porque arrastra `mcp`/`anyio`). Lo añadimos al path explícitamente.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tool_streaming  # noqa: E402


def _new_id() -> str:
    return uuid.uuid4().hex


def test_incremental_reads_by_cursor_in_seq_order() -> None:
    """Un comando lento se lee en varias páginas; la final reporta done y orden seq."""
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

    # Lectura incremental: avanzamos el cursor y acumulamos páginas mientras corre.
    cursor = 0
    collected: list[dict] = []
    got_a_partial_page = False
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        page = tool_streaming.read(execution_id, cursor)
        if page["lines"]:
            collected.extend(page["lines"])
            cursor = page["next_cursor"]
            # Si todavía no acabó y ya tenemos salida, confirma la incrementalidad.
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

    # Se observó al menos una página parcial (lectura en vivo, no sólo al final).
    assert got_a_partial_page


def test_timeout_kills_process_group_no_orphans() -> None:
    """Un comando que duerme más que el timeout -> timed_out=True y sin hijos vivos."""
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
    # Un timeout NO es una cancelación: son estados distinguibles.
    assert cancelled is False
    # No debe esperar los 60s: el timeout de 1s mató el grupo con margen.
    assert elapsed < 20

    # El PID del nieto quedó en la salida; comprobamos que ya no existe.
    page = tool_streaming.read(execution_id, 0)
    grandchild_pid = None
    for line in page["lines"]:
        if line["stream"] == "stdout" and line["text"].strip().isdigit():
            grandchild_pid = int(line["text"].strip())
            break

    assert page["done"] is True

    if grandchild_pid is not None:
        # Dar un instante a la propagación de la señal al grupo.
        time.sleep(0.5)
        alive = _pid_alive(grandchild_pid)
        assert alive is False


def _pid_alive(pid: int) -> bool:
    """True si el proceso existe (signal 0 no mata, sólo chequea)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def test_request_cancel_kills_process_group_no_orphans() -> None:
    """request_cancel mata el grupo (sin huérfanos) y marca cancelled=True (≠ timed_out)."""
    execution_id = _new_id()
    # Padre (líder de grupo) con un hijo en el MISMO grupo; cancelar debe matar ambos.
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

    # Espera a que el proceso esté registrado (vivo) antes de cancelar.
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
    assert timed_out is False  # cancelación ≠ timeout (estados distinguibles)
    assert killed is True

    # El nieto (su PID quedó en la salida) ya no existe: grupo muerto, sin huérfanos.
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
    """Leer con el cursor en la cola: página vacía y next_cursor sin cambios."""
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
    """Un execution_id desconocido no revienta: página vacía, no done."""
    page = tool_streaming.read("does-not-exist", 0)
    assert page["lines"] == []
    assert page["next_cursor"] == 0
    assert page["done"] is False


def test_unknown_status_is_unknown() -> None:
    """get_status de un execution_id no registrado devuelve {'status':'unknown'}."""
    assert tool_streaming.get_status("never-started") == {"status": "unknown"}


def test_start_background_returns_before_process_ends() -> None:
    """start_background DEVUELVE un Thread y el estado es 'running' nada más lanzar."""
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
        # Inmediatamente tras lanzar: aún corriendo (el worker duerme 1s).
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

    # La salida del worker llegó al ring (streaming reutilizado).
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


# --- Paginación de findings (fix del límite SSE de 1 MiB) --------------------


def _small_finding(i: int) -> dict:
    """Un finding mínimo y pequeño para los tests de orden/conteo."""
    return {"check_id": f"check_{i}", "index": i, "severity": "low"}


def _sized_finding(i: int, payload_bytes: int) -> dict:
    """Un finding cuyo tamaño JSON ronda `payload_bytes` (relleno controlado)."""
    return {"check_id": f"check_{i}", "index": i, "blob": "x" * payload_bytes}


def test_set_findings_then_read_paginates_in_order() -> None:
    """250 findings pequeños -> páginas de 100/100/50, orden preservado, done al final."""
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
    # Orden preservado y concatenación == original.
    assert [f["index"] for f in collected] == list(range(250))
    assert collected == findings


def test_read_findings_unknown_execution_id_empty_done() -> None:
    """execution_id desconocido -> página vacía, next_cursor=cursor, done=True."""
    page = tool_streaming.read_findings("does-not-exist", 0)
    assert page["findings"] == []
    assert page["next_cursor"] == 0
    assert page["done"] is True


def test_read_findings_byte_budget_caps_page() -> None:
    """Findings ~50 KiB -> cada página acotada por bytes (<= máximo) y completa."""
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
        # Ninguna página (con >1 finding) supera el presupuesto de bytes.
        if len(page["findings"]) > 1:
            # El array JSON añade comas/corchetes; comparamos la suma de ítems.
            items_bytes = sum(
                len(json.dumps(f).encode("utf-8")) for f in page["findings"]
            )
            assert items_bytes <= tool_streaming.FINDINGS_PAGE_MAX_BYTES
        # El tope de bytes se alcanza antes que el de 100 -> hay varias páginas.
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
    """Un único finding > presupuesto -> página de 1 (anti-inanición), done=True."""
    execution_id = _new_id()
    big = _sized_finding(0, tool_streaming.FINDINGS_PAGE_MAX_BYTES + 10_000)
    tool_streaming.set_findings(execution_id, [big])

    page = tool_streaming.read_findings(execution_id, 0)
    assert len(page["findings"]) == 1
    assert page["findings"][0]["index"] == 0
    assert page["next_cursor"] == 1
    assert page["done"] is True


def test_read_findings_explicit_limit() -> None:
    """limit=10 acota la página a <=10 findings aunque quepan más por bytes."""
    execution_id = _new_id()
    findings = [_small_finding(i) for i in range(30)]
    tool_streaming.set_findings(execution_id, findings)

    page = tool_streaming.read_findings(execution_id, 0, limit=10)
    assert len(page["findings"]) == 10
    assert page["next_cursor"] == 10
    assert page["done"] is False


def test_read_findings_cursor_at_tail_empty_done() -> None:
    """cursor en la cola (== total) -> página vacía, done=True, sin reventar."""
    execution_id = _new_id()
    findings = [_small_finding(i) for i in range(5)]
    tool_streaming.set_findings(execution_id, findings)

    page = tool_streaming.read_findings(execution_id, 5)
    assert page["findings"] == []
    assert page["next_cursor"] == 5
    assert page["done"] is True

    # Un escaneo sin findings: primera lectura ya es vacía y done.
    empty_id = _new_id()
    tool_streaming.set_findings(empty_id, [])
    first = tool_streaming.read_findings(empty_id, 0)
    assert first["findings"] == []
    assert first["done"] is True


# --- Sink de salida COMPLETA (auditoría, bypass del tope RING_MAXLEN) --------


def test_raw_sink_captures_all_lines_beyond_ring_cap(tmp_path) -> None:
    """El sink recibe TODAS las líneas; el ring solo las últimas RING_MAXLEN."""
    execution_id = _new_id()
    sink_path = tmp_path / "raw.out"
    total = tool_streaming.RING_MAXLEN + 100  # supera el tope del ring a propósito

    tool_streaming.open_raw_sink(execution_id, str(sink_path))
    for i in range(total):
        tool_streaming.append(execution_id, "stdout", f"line-{i}")
    tool_streaming.close_raw_sink(execution_id)

    # El sink tiene TODAS las líneas, en orden, íntegras.
    sink_lines = sink_path.read_text(encoding="utf-8").splitlines()
    assert len(sink_lines) == total
    assert sink_lines[0] == "[stdout] line-0"
    assert sink_lines[-1] == f"[stdout] line-{total - 1}"

    # El ring, en cambio, está capado: solo las últimas RING_MAXLEN (protección de contexto).
    page = tool_streaming.read(execution_id, 0)
    assert len(page["lines"]) == tool_streaming.RING_MAXLEN
    assert page["lines"][0]["text"] == f"line-{total - tool_streaming.RING_MAXLEN}"
    assert page["lines"][-1]["text"] == f"line-{total - 1}"


def test_sink_absent_append_writes_no_file(tmp_path) -> None:
    """Sin open_raw_sink, append funciona igual y no crea ningún fichero de sink."""
    execution_id = _new_id()
    tool_streaming.append(execution_id, "stdout", "no-sink-line")
    page = tool_streaming.read(execution_id, 0)
    assert [line["text"] for line in page["lines"]] == ["no-sink-line"]
    # No se creó nada en el tmp (no había sink abierto).
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
