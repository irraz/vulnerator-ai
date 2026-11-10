"""Primitivas de *streaming* de salida de tools para `kali-mcp` (STDLIB PURA).

Por qué un módulo separado (testeabilidad):
  `docker/kali/kali_mcp_server.py` importa `mcp`/`anyio` en el top del módulo y
  esas dependencias NO están en el venv de desarrollo. Para poder cubrir la lógica
  de streaming con tests unitarios SIN el SDK, toda la mecánica vive aquí usando
  SOLO la librería estándar (sin `mcp`, sin `anyio`).

Qué provee:
  - Un *ring buffer* por `execution_id` (thread-safe) que acumula líneas de salida
    con un `seq` creciente, para lectura incremental por cursor.
  - `run_tool_streaming(cmd, execution_id, timeout, ...)`: lanza un subproceso,
    vuelca su stdout/stderr línea a línea al ring en vivo, aplica un timeout y, al
    expirar, mata el GRUPO de procesos completo (sin huérfanos).

Disciplina de seguridad: la salida de la tool es DATO NO CONFIABLE. Aquí se TRANSPORTA
verbatim (se trocea en líneas y se guarda tal cual); NUNCA se interpreta ni se ejecuta
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

# Tamaño máximo del ring por ejecución. Acota la memoria: un escaneo largo con
# mucho verbose no crece sin límite; sólo se retienen las últimas N líneas.
RING_MAXLEN = 2000


def _now_iso() -> str:
    """Timestamp ISO-8601 en UTC (sufijo 'Z'), estable para la UI/logs."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class _Execution:
    """Estado de una ejecución: buffer circular de líneas + contador de seq.

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
        # Sink OPCIONAL de salida COMPLETA (auditoría): un file handle de texto en modo
        # append. El ring está capado a RING_MAXLEN (protección de contexto del LLM); el
        # sink NO está capado, así captura el stdout/stderr ÍNTEGRO. None = sin sink
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
            # Vuelca la MISMA línea al sink de salida completa (si hay), bajo el lock para
            # preservar el orden. Best-effort: un fallo de escritura del sink NUNCA rompe
            # la captura al ring ni la ejecución del comando.
            if self._sink is not None:
                try:
                    self._sink.write("[%s] %s\n" % (stream, text))
                except Exception:  # noqa: BLE001 - sink best-effort
                    pass

    def mark_done(self) -> None:
        with self._lock:
            self._done = True

    def read(self, cursor: int) -> tuple[list[dict[str, Any]], int, bool]:
        """Devuelve (líneas con seq > cursor, next_cursor, done).

        `next_cursor` es el mayor `seq` entregado; si no hay nada nuevo, se
        devuelve el mismo `cursor` (página vacía, cursor sin cambios).
        """
        with self._lock:
            page = [line for line in self._lines if line["seq"] > cursor]
            next_cursor = page[-1]["seq"] if page else cursor
            return page, next_cursor, self._done


# Registro global de ejecuciones. Un lock protege la creación/lookup del dict.
_executions: dict[str, _Execution] = {}
_registry_lock = threading.Lock()

# --- Registro de cancelación por execution_id -------------------------------
# Para cancelar un escaneo EN CURSO desde fuera (tool `cancel_scan`), hace falta (a) una
# señal cooperativa y (b) una referencia al proceso vivo para matar su grupo. Separado del
# ring (salida) y del estado: aquí sólo viven el Popen vivo y un Event de cancelación por
# ejecución. Reutiliza el kill de grupo que ya existe (`_kill_process_group`), NO duplica
# el mecanismo.
_procs: dict[str, "subprocess.Popen"] = {}
_cancels: dict[str, threading.Event] = {}
_procs_lock = threading.Lock()


def _cancel_event(execution_id: str) -> threading.Event:
    """Devuelve (creándolo si hace falta) el Event de cancelación de la ejecución."""
    with _procs_lock:
        event = _cancels.get(execution_id)
        if event is None:
            event = threading.Event()
            _cancels[execution_id] = event
        return event


def request_cancel(execution_id: str) -> bool:
    """Solicita cancelar una ejecución: marca el Event y mata su grupo de proceso.

    Idempotente y None-safe: si la ejecución no existe o ya terminó, marca el Event
    igualmente (por si el proceso aún no se registró) y devuelve ``False`` (no había
    proceso vivo que matar). Reutiliza :func:`_kill_process_group` (SIGTERM->SIGKILL
    sobre el grupo, sin huérfanos). Devuelve ``True`` si mató un proceso vivo.
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
    """Añade una línea de salida (`stream`='stdout'|'stderr') al ring de la ejecución."""
    _get_execution(execution_id).append(stream, text)


def read(execution_id: str, cursor: int = 0) -> dict[str, Any]:
    """Lee incrementalmente la salida de una ejecución a partir de `cursor`.

    Returns:
        {"lines": [{seq, ts, stream, text}, ...], "next_cursor": int, "done": bool}
        Para un `execution_id` desconocido devuelve página vacía y done=False.
    """
    with _registry_lock:
        execution = _executions.get(execution_id)
    if execution is None:
        return {"lines": [], "next_cursor": cursor, "done": False}
    lines, next_cursor, done = execution.read(cursor)
    return {"lines": lines, "next_cursor": next_cursor, "done": done}


# --- Sink de salida COMPLETA (auditoría durable) -----------------------------
# El ring buffer está capado a RING_MAXLEN líneas (protección de contexto del LLM). Para
# auditoría/reproducción hace falta el stdout/stderr ÍNTEGRO: estas dos funciones adjuntan
# un fichero sink a la ejecución ANTES de arrancar el subproceso y lo cierran al terminar.
# `_Execution.append` escribe cada línea al sink EN PARALELO al ring (mismo lock). Otros
# llamadores de `run_tool_streaming` que no usen esto no cambian en absoluto (sink = None).


def open_raw_sink(execution_id: str, path: str) -> Any:
    """Adjunta un fichero sink de salida COMPLETA a la ejecución (best-effort).

    Abre ``path`` en modo append de texto y lo adjunta al ``_Execution`` del
    ``execution_id`` (creándolo si no existe). A partir de aquí cada línea volcada al ring
    se escribe TAMBIÉN al sink, sin el tope ``RING_MAXLEN``. Devuelve el handle, o ``None``
    si no se pudo abrir (fail-open: la ejecución sigue, solo sin auditoría de salida).
    """
    execution = _get_execution(execution_id)
    try:
        handle = open(path, "a", encoding="utf-8")
    except OSError:
        return None
    execution.attach_sink(handle)
    return handle


def close_raw_sink(execution_id: str) -> None:
    """Separa y cierra (flush incluido) el sink de la ejecución. No-op si no había sink."""
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


# --- Estado de ejecución en segundo plano (por execution_id) -----------------
# Registro thread-safe del ESTADO (no de la salida) de una ejecución lanzada en
# background. Separado del ring buffer de líneas: el ring transporta la salida
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


# --- Almacén + paginador de findings por execution_id ------------------------
# Igual que el ring de líneas y el registro de estado, los findings de un escaneo
# TERMINADO se guardan en memoria indexados por execution_id. A diferencia del
# ring (que crece en vivo y se lee por `seq`), la lista de findings es ESTABLE y
# COMPLETA cuando el worker termina; por eso se pagina por ÍNDICE (0-based), no
# por `seq`.
#
# Motivación (fix del límite SSE de 1 MiB): entregar TODOS los findings inline en
# un único evento del transporte MCP streamable-http revienta cuando el payload
# real (datos AWS reales iam+s3) supera 1 048 576 B. Se trocea en páginas MUY por
# debajo de ese límite, igual que el patrón de lectura por cursor de los logs.

# Doble presupuesto por página: tope de BYTES (manda: robustez independiente del
# tamaño) y tope de CONTEO. Se elige el menor. 256 KiB deja holgura ~2x frente a
# 1 MiB aun con la doble serialización de FastMCP (bloque de texto JSON +
# `structuredContent` en el mismo evento SSE). Si el envoltorio pesara más de lo
# estimado, basta bajar FINDINGS_PAGE_MAX_BYTES (único punto de ajuste).
FINDINGS_PAGE_MAX_BYTES = 262144
FINDINGS_PAGE_DEFAULT_LIMIT = 100

# Registro global de findings por ejecución (lista COMPLETA y estable del escaneo
# terminado). Un lock protege el acceso al dict.
_findings: dict[str, list[dict[str, Any]]] = {}
_findings_lock = threading.Lock()


def set_findings(execution_id: str, findings: list[dict[str, Any]]) -> None:
    """Guarda (reemplaza) la lista COMPLETA de findings de `execution_id`.

    La llama el worker al terminar el escaneo, ANTES de publicar el estado `done`,
    para garantizar que cuando el cliente vea `done` los findings ya estén
    disponibles para paginar con `read_findings`.
    """
    with _findings_lock:
        _findings[execution_id] = list(findings)


def read_findings(
    execution_id: str, cursor: int = 0, limit: int | None = None
) -> dict[str, Any]:
    """Pagina los findings guardados de una ejecución a partir del índice `cursor`.

    Entrega findings consecutivos desde `cursor` hasta agotar el MENOR de: `limit`
    (o FINDINGS_PAGE_DEFAULT_LIMIT) findings, o FINDINGS_PAGE_MAX_BYTES bytes
    (medidos con `json.dumps` acumulado). Garantía anti-inanición: si un solo
    finding supera el presupuesto de bytes, se devuelve igualmente esa página de 1
    (un finding OCSF individual está muy lejos de 1 MiB; lo que explota es la SUMA).

    Args:
        execution_id: id de la ejecución (el devuelto por `prowler_scan`).
        cursor: índice 0-based del primer finding a devolver; 0 desde el principio.
        limit: tope de findings por página; None usa FINDINGS_PAGE_DEFAULT_LIMIT.

    Returns:
        {"findings": [...página...], "next_cursor": int, "done": bool}.
        `execution_id` desconocido o `cursor` en/más allá del final -> página vacía
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
        # El presupuesto de bytes manda: si añadir este finding desbordara el tope
        # y la página ya tiene al menos uno, se cierra la página aquí. Si la página
        # está vacía se añade igualmente (anti-inanición).
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

    Marca el estado inicial {'status':'running'} ANTES de arrancar el hilo (así un
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
    """Hilo lector: vuelca `pipe` línea a línea al ring hasta EOF."""
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

    El subproceso se lanza con `start_new_session=True`, así que es líder de su
    propio grupo; matar el grupo entero evita huérfanos aunque Prowler lance hijos.
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
) -> tuple[int, bool]:
    """Ejecuta `cmd` volcando su salida en vivo al ring de `execution_id`.

    stdout y stderr se leen por separado (cada uno en su hilo) y se etiquetan como
    'stdout'/'stderr' en el ring. Al terminar (o al expirar el timeout) la ejecución
    se marca `done`.

    Args:
        cmd: comando y argumentos (lista; sin shell).
        execution_id: identificador de la ejecución (clave del ring buffer).
        timeout: segundos máximos antes de matar el grupo de procesos.
        env: entorno del subproceso (None = heredar el del proceso actual).
        cwd: directorio de trabajo del subproceso.

    Returns:
        (returncode, timed_out, cancelled). En timeout `timed_out=True`; en
        cancelación externa (`request_cancel`) `cancelled=True`. `returncode` es el del
        proceso tras matar el grupo (puede ser negativo = señal). `cancelled` tiene
        prioridad semántica sobre `timed_out` para el caller.
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
        start_new_session=True,  # grupo propio -> killpg sin huérfanos
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
            # Cancelación externa: mata el grupo y sale (prioridad sobre el timeout).
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
        # `request_cancel` pudo matar el proceso directamente (proc.wait() retornó por
        # el kill, no por el Event): consultar el Event es la fuente de verdad de la
        # cancelación, independientemente de qué rama cerró el bucle.
        cancelled = cancel_event.is_set()
        with _procs_lock:
            _procs.pop(execution_id, None)
            _cancels.pop(execution_id, None)

    returncode = proc.returncode if proc.returncode is not None else -1
    return returncode, timed_out, cancelled
