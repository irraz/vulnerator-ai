"""Primitivas de *streaming* de salida de tools para `kali-mcp` (STDLIB PURA).

Why a separate module (testability):
  `docker/kali/kali_mcp_server.py` imports `mcp`/`anyio` at module top and
  those dependencies are NOT in the dev venv. To cover the logic
  of streaming with unit tests WITHOUT the SDK, all mechanics live here using
  ONLY the standard library (no `mcp`, no `anyio`).

What it provides:
  - A *ring buffer* per `execution_id` (thread-safe) that accumulates output lines
    con un `seq` creciente, para lectura incremental por cursor.
  - `run_tool_streaming(cmd, execution_id, timeout, ...)`: lanza un subproceso,
    dumps its stdout/stderr line by line to the live ring, applies a timeout, and on
    expiry, kills the ENTIRE process GROUP (no orphans).

Security discipline: tool output is UNTRUSTED DATA. Here it is TRANSPORTED
verbatim (split into lines and stored as-is); it is NEVER interpreted or executed
nada derivado de ella.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable

# Maximum ring size per execution. Bounds memory: a long scan with
# much verbosity does not grow without limit; only the last N lines are retained.
RING_MAXLEN = 2000


def _now_iso() -> str:
    """Timestamp ISO-8601 en UTC (sufijo 'Z'), estable para la UI/logs."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class _Execution:
    """State of an execution: circular buffer of lines + seq counter.

    Thread-safe: un lock protege el deque, el contador `_seq` y la bandera `done`,
    porque el/los hilo(s) lector(es) del subproceso escriben mientras el event loop
    (u otro hilo) lee por cursor.
    """

    __slots__ = ("_lines", "_seq", "_done", "_lock", "_sink")

    def __init__(self) -> None:
        self._lines: deque[dict[str, Any]] = deque(maxlen=RING_MAXLEN)
        self._seq = 0
        self._done = False
        self._lock = threading.Lock()
        # OPTIONAL COMPLETE-output sink (audit): a text file handle in append
        # mode. The ring is capped at RING_MAXLEN (LLM context protection); the
        # sink is NOT capped, so it captures FULL stdout/stderr. None = no sink
        # (comportamiento de siempre). Protegido por el MISMO lock que el ring para que
        # stdout/stderr de ambos pumps se serialicen en el mismo orden que en el ring.
        self._sink: Any = None

    def attach_sink(self, handle: Any) -> None:
        """Adjunta (o reemplaza) el file handle del sink de salida completa."""
        with self._lock:
            self._sink = handle

    def detach_sink(self) -> Any:
        """Separa el sink y devuelve su handle (o None) para que el caller lo cierre."""
        with self._lock:
            handle = self._sink
            self._sink = None
            return handle

    def append(self, stream: str, text: str) -> None:
        with self._lock:
            self._seq += 1
            self._lines.append(
                {
                    "seq": self._seq,
                    "ts": _now_iso(),
                    "stream": stream,
                    "text": text,
                }
            )
            # Dumps the SAME line to the complete-output sink (if any), under the lock so as not to affect
            # preservar el orden. Best-effort: un fallo de escritura del sink NUNCA rompe
            # ring capture or command execution.
            if self._sink is not None:
                try:
                    self._sink.write("[%s] %s\n" % (stream, text))
                except Exception:  # noqa: BLE001 - sink best-effort
                    pass

    def mark_done(self) -> None:
        with self._lock:
            self._done = True

    def read(self, cursor: int) -> tuple[list[dict[str, Any]], int, bool]:
        """Returns (lines with seq > cursor, next_cursor, done).

        `next_cursor` es el mayor `seq` entregado; si no hay nada nuevo, se
        returns the same `cursor` (empty page, cursor unchanged).
        """
        with self._lock:
            page = [line for line in self._lines if line["seq"] > cursor]
            next_cursor = page[-1]["seq"] if page else cursor
            return page, next_cursor, self._done


# Global registry of executions. A lock protects dict creation/lookup.
_executions: dict[str, _Execution] = {}
_registry_lock = threading.Lock()

# --- Cancellation registry by execution_id -------------------------------
# Para cancelar un escaneo EN CURSO desde fuera (tool `cancel_scan`), hace falta (a) una
# cooperative signal and (b) a reference to the live process to kill its group. Separate from the
# ring (output) and the status: only the live Popen and a per-execution cancellation Event live here
# execution. It reuses the existing group kill (`_kill_process_group`), NO duplication
# el mecanismo.
_procs: dict[str, "subprocess.Popen"] = {}
_cancels: dict[str, threading.Event] = {}
_procs_lock = threading.Lock()


def _cancel_event(execution_id: str) -> threading.Event:
    """Returns (creating it if needed) the execution's cancellation Event."""
    with _procs_lock:
        event = _cancels.get(execution_id)
        if event is None:
            event = threading.Event()
            _cancels[execution_id] = event
        return event


def request_cancel(execution_id: str) -> bool:
    """Requests cancellation of an execution: sets the Event and kills its process group.

    Idempotent and None-safe: if the execution does not exist or already ended, it sets the Event
    anyway (in case the process is not registered yet) and returns ``False`` (there was no
    proceso vivo que matar). Reutiliza :func:`_kill_process_group` (SIGTERM->SIGKILL
    on the group, no orphans). Returns ``True`` if it killed a live process.
    """
    with _procs_lock:
        event = _cancels.get(execution_id)
        if event is None:
            event = threading.Event()
            _cancels[execution_id] = event
        event.set()
        proc = _procs.get(execution_id)
    if proc is not None and proc.poll() is None:
        _kill_process_group(proc)
        return True
    return False


def _get_execution(execution_id: str) -> _Execution:
    with _registry_lock:
        execution = _executions.get(execution_id)
        if execution is None:
            execution = _Execution()
            _executions[execution_id] = execution
        return execution


def append(execution_id: str, stream: str, text: str) -> None:
    """Adds an output line (`stream`='stdout'|'stderr') to the execution's ring."""
    _get_execution(execution_id).append(stream, text)


def read(execution_id: str, cursor: int = 0) -> dict[str, Any]:
    """Incrementally reads an execution's output starting at `cursor`.

    Returns:
        {"lines": [{seq, ts, stream, text}, ...], "next_cursor": int, "done": bool}
        For an unknown `execution_id` it returns an empty page and done=False.
    """
    with _registry_lock:
        execution = _executions.get(execution_id)
    if execution is None:
        return {"lines": [], "next_cursor": cursor, "done": False}
    lines, next_cursor, done = execution.read(cursor)
    return {"lines": lines, "next_cursor": next_cursor, "done": done}


# --- COMPLETE output sink (durable audit) -----------------------------
# The ring buffer is capped at RING_MAXLEN lines (LLM context protection). For
# audit/reproduction, FULL stdout/stderr is needed: these two functions attach
# a sink file to the execution BEFORE starting the subprocess and close it on completion.
# `_Execution.append` writes each line to the sink IN PARALLEL with the ring (same lock). Other
# llamadores de `run_tool_streaming` que no usen esto no cambian en absoluto (sink = None).


def open_raw_sink(execution_id: str, path: str) -> Any:
    """Attaches a COMPLETE-output sink file to the execution (best-effort).

    Abre ``path`` en modo append de texto y lo adjunta al ``_Execution`` del
    ``execution_id`` (creating it if absent). From here on, each line dumped to the ring
    is ALSO written to the sink, without the ``RING_MAXLEN`` cap. Returns the handle, or ``None``
    if it could not be opened (fail-open: execution continues, just without output audit).
    """
    execution = _get_execution(execution_id)
    try:
        handle = open(path, "a", encoding="utf-8")
    except OSError:
        return None
    execution.attach_sink(handle)
    return handle


def close_raw_sink(execution_id: str) -> None:
    """Detaches and closes (flush included) the execution's sink. No-op if there was none."""
    with _registry_lock:
        execution = _executions.get(execution_id)
    if execution is None:
        return
    handle = execution.detach_sink()
    if handle is not None:
        try:
            handle.flush()
            handle.close()
        except Exception:  # noqa: BLE001 - cierre best-effort
            pass


# --- Background execution status (by execution_id) -----------------
# Thread-safe registry of the STATUS (not the output) of an execution launched in
# the background. Separate from the line ring buffer: the ring carries output
# verbatim (dato NO confiable), mientras que esto guarda el veredicto estructurado
# del worker ({'status': running|done|failed, ...}) para que el cliente lo sondee.
_status: dict[str, dict[str, Any]] = {}
_status_lock = threading.Lock()


def set_status(execution_id: str, **fields: Any) -> None:
    """Fija (reemplaza) el dict de estado de `execution_id` con `fields`."""
    with _status_lock:
        _status[execution_id] = dict(fields)


def get_status(execution_id: str) -> dict[str, Any]:
    """Devuelve el dict de estado guardado, o {'status':'unknown'} si no existe."""
    with _status_lock:
        status = _status.get(execution_id)
        return dict(status) if status is not None else {"status": "unknown"}


# --- Findings store + paginator by execution_id ------------------------
# Like the line ring and the status registry, a scan's findings
# TERMINADO se guardan en memoria indexados por execution_id. A diferencia del
# ring (que crece en vivo y se lee por `seq`), la lista de findings es ESTABLE y
# COMPLETE when the worker finishes; hence pagination by INDEX (0-based), not
# por `seq`.
#
# Motivation (fix for the 1 MiB SSE limit): delivering ALL findings inline in
# a single event of the streamable-http MCP transport breaks when the payload
# real (actual AWS iam+s3 data) exceeds 1,048,576 B. It is split into pages WELL
# below that limit, like the cursor-reading pattern of logs.

# Double per-page budget: BYTE cap (governs: robustness independent of
# size) and COUNT cap. The smaller is chosen. 256 KiB leaves ~2x headroom vs
# 1 MiB even with FastMCP's double serialization (JSON text block +
# `structuredContent` in the same SSE event). If the envelope weighed more than
# estimated, just lower FINDINGS_PAGE_MAX_BYTES (the single tuning point).
FINDINGS_PAGE_MAX_BYTES = 262144
FINDINGS_PAGE_DEFAULT_LIMIT = 100

# Global findings registry per execution (COMPLETE, stable scan list
# terminado). Un lock protege el acceso al dict.
_findings: dict[str, list[dict[str, Any]]] = {}
_findings_lock = threading.Lock()


def set_findings(execution_id: str, findings: list[dict[str, Any]]) -> None:
    """Guarda (reemplaza) la lista COMPLETA de findings de `execution_id`.

    La llama el worker al terminar el escaneo, ANTES de publicar el estado `done`,
    to guarantee that when the client sees `done`, the findings are already
    disponibles para paginar con `read_findings`.
    """
    with _findings_lock:
        _findings[execution_id] = list(findings)


def read_findings(
    execution_id: str, cursor: int = 0, limit: int | None = None
) -> dict[str, Any]:
    """Pages the stored findings of an execution starting at index `cursor`.

    Entrega findings consecutivos desde `cursor` hasta agotar el MENOR de: `limit`
    (o FINDINGS_PAGE_DEFAULT_LIMIT) findings, o FINDINGS_PAGE_MAX_BYTES bytes
    (measured with cumulative `json.dumps`). Anti-starvation guarantee: if a single
    finding exceeds the byte budget, that page of 1 is returned anyway
    (a single OCSF finding is far below 1 MiB; it is the SUM that blows up).

    Args:
        execution_id: execution id (the one returned by `prowler_scan`).
        cursor: 0-based index of the first finding to return; 0 from the beginning.
        limit: cap of findings per page; None uses FINDINGS_PAGE_DEFAULT_LIMIT.

    Returns:
        {"findings": [...page...], "next_cursor": int, "done": bool}.
        unknown `execution_id` or `cursor` at/past the end -> empty page
        con done=True (no revienta).
    """
    with _findings_lock:
        stored = _findings.get(execution_id)
        items = list(stored) if stored is not None else None

    if items is None:
        return {"findings": [], "next_cursor": cursor, "done": True}

    total = len(items)
    start = cursor if cursor > 0 else 0
    if start >= total:
        return {"findings": [], "next_cursor": cursor, "done": True}

    max_count = (
        limit if limit is not None and limit > 0 else FINDINGS_PAGE_DEFAULT_LIMIT
    )

    page: list[dict[str, Any]] = []
    size = 0
    index = start
    while index < total and len(page) < max_count:
        finding = items[index]
        encoded = len(json.dumps(finding).encode("utf-8"))
        # The byte budget governs: if adding this finding exceeded the cap
        # and the page already has at least one, the page is closed here. If the page
        # is empty, it is added anyway (anti-starvation).
        if page and size + encoded > FINDINGS_PAGE_MAX_BYTES:
            break
        page.append(finding)
        size += encoded
        index += 1

    return {"findings": page, "next_cursor": index, "done": index >= total}


def start_background(
    execution_id: str, worker: Callable[[], dict[str, Any]]
) -> threading.Thread:
    """Lanza `worker()` en un hilo demonio y registra su estado por `execution_id`.

    Sets the initial state {'status':'running'} BEFORE starting the thread (so a
    sondeo inmediato ve 'running', nunca 'unknown'), corre `worker()` (callable sin
    args que devuelve el dict de estado final) y, al terminar, guarda ese dict como
    estado final. Si `worker` lanza, guarda {'status':'failed','error':str(exc)}.
    Devuelve el `Thread` (ya arrancado) por si el caller quiere `join`.
    """
    set_status(execution_id, status="running")

    def _runner() -> None:
        try:
            result = worker()
            set_status(execution_id, **result)
        except Exception as exc:  # noqa: BLE001 - cualquier fallo -> estado failed
            set_status(execution_id, status="failed", error=str(exc))

    thread = threading.Thread(target=_runner, daemon=True)
    thread.start()
    return thread


def _pump(pipe: Any, execution: _Execution, stream: str) -> None:
    """Reader thread: dumps `pipe` line by line to the ring until EOF."""
    try:
        for raw in iter(pipe.readline, ""):
            if raw == "":
                break
            execution.append(stream, raw.rstrip("\n"))
    finally:
        try:
            pipe.close()
        except Exception:  # noqa: BLE001 - cierre best-effort
            pass


def _kill_process_group(proc: subprocess.Popen) -> None:
    """Mata el GRUPO de procesos del subproceso (SIGTERM, luego SIGKILL).

    The subprocess is launched with `start_new_session=True`, so it is leader of its
    own group; killing the whole group avoids orphans even if Prowler spawns children.
    """
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            continue


def run_tool_streaming(
    cmd: list[str],
    execution_id: str,
    timeout: int,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> tuple[int, bool, bool]:
    """Ejecuta `cmd` volcando su salida en vivo al ring de `execution_id`.

    stdout y stderr se leen por separado (cada uno en su hilo) y se etiquetan como
    'stdout'/'stderr' in the ring. On completion (or timeout expiry) the execution
    se marca `done`.

    Args:
        cmd: comando y argumentos (lista; sin shell).
        execution_id: execution identifier (key of the ring buffer).
        timeout: maximum seconds before killing the process group.
        env: entorno del subproceso (None = heredar el del proceso actual).
        cwd: directorio de trabajo del subproceso.

    Returns:
        (returncode, timed_out, cancelled). En timeout `timed_out=True`; en
        external cancellation (`request_cancel`) gives `cancelled=True`. `returncode` is that of the
        process after killing the group (may be negative = signal). `cancelled` has
        semantic priority over `timed_out` for the caller.
    """
    execution = _get_execution(execution_id)
    cancel_event = _cancel_event(execution_id)  # asegura el Event antes del Popen
    proc = subprocess.Popen(  # noqa: S603 - cmd controlado por el caller, sin shell
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,  # line-buffered: la salida llega al ring a medida que ocurre
        env=env,
        cwd=cwd,
        start_new_session=True,  # own group -> killpg without orphans
    )
    # Registra el proceso vivo para que `request_cancel` pueda matar su grupo.
    with _procs_lock:
        _procs[execution_id] = proc

    readers = [
        threading.Thread(target=_pump, args=(proc.stdout, execution, "stdout"), daemon=True),
        threading.Thread(target=_pump, args=(proc.stderr, execution, "stderr"), daemon=True),
    ]
    for reader in readers:
        reader.start()

    timed_out = False
    cancelled = False
    deadline = time.monotonic() + timeout
    try:
        while True:
            # External cancellation: kills the group and exits (priority over timeout).
            if cancel_event.is_set():
                _kill_process_group(proc)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _kill_process_group(proc)
                break
            try:
                proc.wait(timeout=min(remaining, 0.5))
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        # Asegura que no quede el grupo vivo pase lo que pase.
        if proc.poll() is None:
            _kill_process_group(proc)
        for reader in readers:
            reader.join(timeout=5)
        execution.mark_done()
        # `request_cancel` may have killed the process directly (proc.wait() returned due to
        # el kill, no por el Event): consultar el Event es la fuente de verdad de la
        # cancellation, regardless of which branch closed the loop.
        cancelled = cancel_event.is_set()
        with _procs_lock:
            _procs.pop(execution_id, None)
            _cancels.pop(execution_id, None)

    returncode = proc.returncode if proc.returncode is not None else -1
    return returncode, timed_out, cancelled
