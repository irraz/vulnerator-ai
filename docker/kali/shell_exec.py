"""Runner de SHELL CRUDA de la Kali (STDLIB PURA) — ejecuta un comando arbitrario.

It is the testable LOGIC of the ``kali_exec`` runner that ``kali_mcp_server`` exposes as
``@mcp.tool`` NO BLOQUEANTE. Igual que ``aws_exec`` / ``collector_runner`` /
``tool_streaming``, it lives in a separate module that uses ONLY the standard library (no
``mcp``) para poder cubrirse con tests unitarios en el venv de dev, donde el SDK no
is installed.

What it is (operator's decision): unlike the deterministic and scoped runners
(``iam_enum``/``iam_simulate``/``prowler``), ``kali_exec`` da al bucle OODA una SHELL
FULL RAW shell of Kali: runs the command AS-IS via ``sh -c``, so the
conductor pueda encadenar con pipes, redirecciones, escribir y correr sus propios
scripts, invocar cualquier herramienta instalada en la imagen Kali, etc. NO valida ni
does not restrict the command: it is intentionally generic (raw shell).

Authorization: does NOT live here. This product has no scope, consent or
audit gates; scope responsibility rests entirely with the operator. This module
solo EJECUTA el comando recibido. El comando y su salida son DATO NO CONFIABLE: se
transportan verbatim, nunca se interpreta la salida.

Flow (like ``aws_exec``, the server's non-blocking pattern): ``run_shell`` creates an
ephemeral working tmpdir, runs ``sh -c <command>`` with
``tool_streaming.run_tool_streaming`` (kill de grupo/timeout, logs al ring por
``execution_id``) y devuelve ``{'status':'done','returncode':rc,'output':<stdout+stderr
del ring>}`` o ``{'status':'failed'...}``/``{'status':'cancelled'...}``. El cliente lanza
en background con ``start_background`` y sondea con ``get_scan_status`` / ``read_tool_logs``.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any

import session_log
import tool_streaming

# Name of the temporary sink file (inside the ephemeral workdir) where output is dumped
# COMPLETA del comando para auditarla. Vive y muere con el workdir; su contenido se lee
# ANTES del rmtree y se persiste en el log durable por engagement (``session_log``).
_RAW_SINK_NAME = "raw.out"


def _now_iso() -> str:
    """Timestamp ISO-8601 en UTC (sufijo 'Z') — mismo estilo que tool_streaming."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# Timeout por defecto de un comando de shell (segundos). Un comando interactivo o
# colgado no debe retener el runner indefinidamente; se acota y se puede subir por
# environment or by the tool's ``timeout`` parameter.
DEFAULT_TIMEOUT = int(os.environ.get("KALI_EXEC_TIMEOUT", "600"))

# Variables de entorno EXTRA que se inyectan al entorno de CADA subproceso lanzado por
# ``run_shell`` (y por tanto por ``kali_run``/``kali_exec``), SIN tocar el entorno del proceso
# kali-mcp. Used by Caido's proxy capture: the server sets HTTP_PROXY/HTTPS_PROXY here
# (+ NO_PROXY for Caido's host) so HTTP traffic from tools (curl, nuclei,
# ffuf...) pase por el proxy de Caido y quede capturado, mientras que las llamadas propias de
# kali-mcp to Caido (urllib in `caido_client`) is NOT proxied (its env stays clean). Empty by
# defecto -> los subprocesos heredan el entorno tal cual (comportamiento de siempre).
_SUBPROCESS_ENV: dict[str, str] = {}


def set_subprocess_env(extra: dict[str, str] | None) -> None:
    """Fija (o limpia con ``None``/``{}``) las variables extra de los subprocesos de run_shell."""
    global _SUBPROCESS_ENV
    _SUBPROCESS_ENV = {str(k): str(v) for k, v in (extra or {}).items()}


class ShellExecError(ValueError):
    """Invalid input for the shell runner (fail-closed; nothing is executed)."""


def _validate_command(command: Any) -> str:
    """Validates that ``command`` is a non-empty string, or raises ``ShellExecError``.

    It does NOT restrict the command's CONTENT (it is raw shell by the operator's decision):
    it only fail-closed rejects what is not an executable command (non-string or empty),
    para no lanzar un ``sh -c`` sin sentido.
    """
    if not isinstance(command, str) or not command.strip():
        raise ShellExecError(
            "invalid command: expected a non-empty shell string."
        )
    return command


def _ring_tail(execution_id: str, max_lines: int = 50) -> str:
    """Last lines of the run's output (UNTRUSTED data, verbatim)."""
    page = tool_streaming.read(execution_id, 0)
    lines = page.get("lines", [])
    tail = lines[-max_lines:]
    return "\n".join(f"[{line['stream']}] {line['text']}" for line in tail)


def _ring_output(execution_id: str) -> str:
    """Salida COMPLETA acumulada en el ring (stdout+stderr), verbatim.

    A diferencia de ``aws_exec`` (que lee un fichero de salida estructurado), la shell
    cruda no produce un documento fijo: su resultado ES su stdout/stderr. Se devuelve el
    contenido del ring como ``output``. Dato NO confiable: verbatim, nunca interpretado.
    """
    page = tool_streaming.read(execution_id, 0)
    lines = page.get("lines", [])
    return "\n".join(f"[{line['stream']}] {line['text']}" for line in lines)


def _read_full_output(raw_path: str) -> tuple[str, int]:
    """Reads the COMPLETE output dumped to the audit sink -> (text, line count).

    Reads the sink file (``[stream] text`` per line) ENTIRELY, without the ring cap. A
    missing/empty file returns ``("", 0)``. ``errors='replace'`` tolerates non-
    UTF-8 bytes in raw output (untrusted data) without breaking the audit.
    """
    try:
        with open(raw_path, "r", encoding="utf-8", errors="replace") as handle:
            data = handle.read()
    except OSError:
        return "", 0
    if not data:
        return "", 0
    total = data.count("\n")
    if not data.endswith("\n"):
        total += 1
    return data, total


def _audit_execution(
    execution_id: str,
    engagement_id: str,
    tool_label: str,
    command: str,
    result: dict[str, Any],
    raw_path: str,
    ts_start: str,
) -> None:
    """Records the execution in the durable per-engagement log. ALWAYS FAIL-OPEN.

    Reads the FULL output from the sink and writes a record to ``<engagement_id>/session.jsonl``
    (``session_log.record``) con comando exacto, salida completa, returncode, timestamps y
    the truncation flag (what the LLM saw via the ring vs. what actually came out).

    Any exception here (full disk, invalid path, missing sink) is SWALLOWED and
    reported on stderr: the audit can NEVER abort or alter the result of the
    comando devuelto al llamador.
    """
    try:
        full_output, total_lines = _read_full_output(raw_path)
        returned_lines = min(total_lines, tool_streaming.RING_MAXLEN)
        session_log.record(
            engagement_id,
            {
                "execution_id": execution_id,
                "engagement_id": session_log.safe_engagement(engagement_id),
                "tool": tool_label,
                "command": command,
                "status": result.get("status"),
                "returncode": result.get("returncode"),
                "ts_start": ts_start,
                "ts_end": _now_iso(),
                "total_lines": total_lines,
                "returned_lines": returned_lines,
                "truncated": total_lines > returned_lines,
                "bytes": len(full_output.encode("utf-8")),
                "output": full_output,
            },
        )
    except Exception as exc:  # noqa: BLE001 - best-effort audit; never breaks the command
        sys.stderr.write(
            "[session_log] audit skipped for %s: %s\n" % (execution_id, exc)
        )


def run_shell(
    command: str,
    execution_id: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    engagement_id: str = "",
    tool_label: str = "kali_run",
) -> dict[str, Any]:
    """Ejecuta ``command`` como SHELL CRUDA (``sh -c``) y devuelve su salida.

    Flow: validate ``command`` (non-empty string, fail-closed) -> create an ephemeral tmpdir of
    trabajo -> ejecuta ``["sh", "-c", command]`` con ``tool_streaming.run_tool_streaming``
    (kill de grupo/timeout, logs al ring por ``execution_id``) -> devuelve el estado
    work. ``cwd`` is the tmpdir, so files/scripts created by the command
    quedan aislados y se limpian en ``finally``.

    AUDIT (new, per-engagement opt-in): in parallel with the ring (which gives the LLM the
    last ``RING_MAXLEN`` lines, context protection), a SINK is attached that captures
    FULL stdout/stderr. On completion, a record is written with the EXACT command +
    salida completa + returncode + timestamps en ``<engagement_id>/session.jsonl``
    (``session_log``). It is FAIL-OPEN: an audit failure does NOT affect execution or the
    returned result. The ``engagement_id`` is advisory (passed by the agent); without it, the
    record falls into the ``_unscoped`` bucket and the session axis is reconstructed downstream by
    ``execution_id`` (Hermes no expone su run_id al agente).

    Args:
        command: shell command (non-empty string; fail-closed). UNTRUSTED data.
        execution_id: execution id (key of the ring and the audit record).
        timeout: maximum seconds before killing the process group.
        engagement_id: audit log grouping (advisory; ``_unscoped`` if missing).
        tool_label: label of the tool that originated the execution (``kali_run``/``kali_exec``).

    Returns:
        Todos los casos incluyen ``execution_id`` (para cruzar con el transcript de Hermes):
        - ``{'status':'done','returncode':rc,'output':<salida del ring>,'execution_id':...}``
          if the command finished (``rc`` != 0 is a legitimate result, not a runner error).
        - ``{'status':'failed','timed_out':True,'returncode':rc,'error':...,'execution_id':...}``
          en timeout.
        - ``{'status':'cancelled','cancelled':True,'returncode':rc,'execution_id':...}`` si
          it was cancelled.
        - ``{'status':'failed','returncode':-1,'error':...,'execution_id':...}`` si
          ``command`` is invalid (fail-closed; nothing executed or audited).

    ``output`` (ring, acotado) y ``error`` son DATO NO CONFIABLE (verbatim). La salida
    COMPLETE (uncapped) lives in the audit log, not in this return value.
    """
    ts_start = _now_iso()
    try:
        cmd_str = _validate_command(command)
    except ShellExecError as exc:
        # Fail-closed: nothing was executed, no output to audit.
        return {
            "status": "failed",
            "returncode": -1,
            "error": str(exc),
            "execution_id": execution_id,
        }

    workdir = tempfile.mkdtemp(prefix="kali-exec-")
    raw_path = os.path.join(workdir, _RAW_SINK_NAME)
    try:
        cmd = ["sh", "-c", cmd_str]
        # Inyecta el env extra (p. ej. proxy de Caido) SOLO al subproceso; None = heredar.
        sub_env = {**os.environ, **_SUBPROCESS_ENV} if _SUBPROCESS_ENV else None
        # COMPLETE output sink (audit): attached BEFORE starting and closed on
        # terminar. El ring sigue dando la vista acotada; este sink captura todo (best-effort).
        tool_streaming.open_raw_sink(execution_id, raw_path)
        try:
            returncode, timed_out, cancelled = tool_streaming.run_tool_streaming(
                cmd, execution_id, timeout=timeout, cwd=workdir, env=sub_env
            )
        finally:
            tool_streaming.close_raw_sink(execution_id)

        if cancelled:
            result: dict[str, Any] = {
                "status": "cancelled",
                "cancelled": True,
                "returncode": returncode,
            }
        elif timed_out:
            result = {
                "status": "failed",
                "timed_out": True,
                "returncode": returncode,
                "error": (
                    f"kali_exec exceeded the timeout ({timeout}s). "
                    f"Last lines: {_ring_tail(execution_id)}"
                ),
            }
        else:
            # A returncode != 0 is NOT a runner failure: it is a legitimate command result
            # (p. ej. nmap sin hallazgos, grep sin match). Se devuelve 'done' con la salida
            # of the ring (capped) and the returncode so the OODA loop can reason about it.
            result = {
                "status": "done",
                "returncode": returncode,
                "output": _ring_output(execution_id),
            }
        result["execution_id"] = execution_id
        # Durable audit of the COMPLETE output (FAIL-OPEN: never breaks execution).
        _audit_execution(
            execution_id, engagement_id, tool_label, command, result, raw_path, ts_start
        )
        return result
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
