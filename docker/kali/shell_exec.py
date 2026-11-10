"""Runner de SHELL CRUDA de la Kali (STDLIB PURA) — ejecuta un comando arbitrario.

Es la LÓGICA testeable del runner ``kali_exec`` que expone ``kali_mcp_server`` como
``@mcp.tool`` NO BLOQUEANTE. Igual que ``aws_exec`` / ``collector_runner`` /
``tool_streaming``, vive en un módulo aparte que usa SOLO la librería estándar (sin
``mcp``) para poder cubrirse con tests unitarios en el venv de dev, donde el SDK no
está instalado.

Qué es (decisión del operador): a diferencia de los runners deterministas y acotados
(``iam_enum``/``iam_simulate``/``prowler``), ``kali_exec`` da al bucle OODA una SHELL
CRUDA COMPLETA de la Kali: ejecuta el comando TAL CUAL vía ``sh -c``, de modo que el
conductor pueda encadenar con pipes, redirecciones, escribir y correr sus propios
scripts, invocar cualquier herramienta instalada en la imagen Kali, etc. NO valida ni
restringe el comando: es intencionadamente genérico (shell cruda).

Autorización: NO vive aquí. Este producto no tiene gates de scope, consentimiento ni
auditoría; la responsabilidad del alcance recae enteramente en el operador. Este módulo
solo EJECUTA el comando recibido. El comando y su salida son DATO NO CONFIABLE: se
transportan verbatim, nunca se interpreta la salida.

Flujo (igual que ``aws_exec``, patrón no-bloqueante del servidor): ``run_shell`` crea un
tmpdir de trabajo efímero, ejecuta ``sh -c <command>`` con
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

# Nombre del fichero sink temporal (dentro del workdir efímero) donde se vuelca la salida
# COMPLETA del comando para auditarla. Vive y muere con el workdir; su contenido se lee
# ANTES del rmtree y se persiste en el log durable por engagement (``session_log``).
_RAW_SINK_NAME = "raw.out"


def _now_iso() -> str:
    """Timestamp ISO-8601 en UTC (sufijo 'Z') — mismo estilo que tool_streaming."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# Timeout por defecto de un comando de shell (segundos). Un comando interactivo o
# colgado no debe retener el runner indefinidamente; se acota y se puede subir por
# entorno o por el parámetro ``timeout`` de la tool.
DEFAULT_TIMEOUT = int(os.environ.get("KALI_EXEC_TIMEOUT", "600"))

# Variables de entorno EXTRA que se inyectan al entorno de CADA subproceso lanzado por
# ``run_shell`` (y por tanto por ``kali_run``/``kali_exec``), SIN tocar el entorno del proceso
# kali-mcp. Lo usa la captura por proxy de Caido: el servidor pone aquí HTTP_PROXY/HTTPS_PROXY
# (+ NO_PROXY al host de Caido) para que el tráfico HTTP de las herramientas (curl, nuclei,
# ffuf...) pase por el proxy de Caido y quede capturado, mientras que las llamadas propias de
# kali-mcp a Caido (urllib en `caido_client`) NO se proxyean (su env queda limpio). Vacío por
# defecto -> los subprocesos heredan el entorno tal cual (comportamiento de siempre).
_SUBPROCESS_ENV: dict[str, str] = {}


def set_subprocess_env(extra: dict[str, str] | None) -> None:
    """Fija (o limpia con ``None``/``{}``) las variables extra de los subprocesos de run_shell."""
    global _SUBPROCESS_ENV
    _SUBPROCESS_ENV = {str(k): str(v) for k, v in (extra or {}).items()}


class ShellExecError(ValueError):
    """Entrada inválida para el runner de shell (fail-closed; no se ejecuta nada)."""


def _validate_command(command: Any) -> str:
    """Valida que ``command`` sea un string no vacío, o lanza ``ShellExecError``.

    NO restringe el CONTENIDO del comando (es shell cruda por decisión del operador):
    solo rechaza fail-closed lo que no es un comando ejecutable (no-string o vacío),
    para no lanzar un ``sh -c`` sin sentido.
    """
    if not isinstance(command, str) or not command.strip():
        raise ShellExecError(
            "command inválido: se espera una cadena de shell no vacía."
        )
    return command


def _ring_tail(execution_id: str, max_lines: int = 50) -> str:
    """Últimas líneas de salida de la ejecución (dato NO confiable, verbatim)."""
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
    """Lee la salida COMPLETA volcada al sink de auditoría -> (texto, nº de líneas).

    Lee el fichero sink (``[stream] text`` por línea) ENTERO, sin el tope del ring. Un
    fichero inexistente/vacío devuelve ``("", 0)``. ``errors='replace'`` tolera bytes no
    UTF-8 en la salida cruda (dato no confiable) sin reventar la auditoría.
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
    """Registra la ejecución en el log durable por engagement. FAIL-OPEN SIEMPRE.

    Lee la salida ÍNTEGRA del sink y escribe un registro en ``<engagement_id>/session.jsonl``
    (``session_log.record``) con comando exacto, salida completa, returncode, timestamps y
    el flag de truncado (lo que el LLM vio por el ring vs. lo que realmente salió).

    Cualquier excepción aquí (disco lleno, ruta inválida, sink ausente) se TRAGA y se
    reporta por stderr: la auditoría NUNCA puede abortar ni alterar el resultado del
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
    except Exception as exc:  # noqa: BLE001 - auditoría best-effort; nunca rompe el comando
        sys.stderr.write(
            "[session_log] auditoría omitida para %s: %s\n" % (execution_id, exc)
        )


def run_shell(
    command: str,
    execution_id: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    engagement_id: str = "",
    tool_label: str = "kali_run",
) -> dict[str, Any]:
    """Ejecuta ``command`` como SHELL CRUDA (``sh -c``) y devuelve su salida.

    Flujo: valida ``command`` (string no vacío, fail-closed) -> crea un tmpdir efímero de
    trabajo -> ejecuta ``["sh", "-c", command]`` con ``tool_streaming.run_tool_streaming``
    (kill de grupo/timeout, logs al ring por ``execution_id``) -> devuelve el estado
    terminal. ``cwd`` es el tmpdir, así que los ficheros/scripts que el comando cree
    quedan aislados y se limpian en ``finally``.

    AUDITORÍA (nuevo, opt-in por engagement): en paralelo al ring (que da al LLM las
    últimas ``RING_MAXLEN`` líneas, protección de contexto), se adjunta un SINK que captura
    el stdout/stderr ÍNTEGRO. Al terminar, se escribe un registro con el comando EXACTO +
    salida completa + returncode + timestamps en ``<engagement_id>/session.jsonl``
    (``session_log``). Es FAIL-OPEN: un fallo de la auditoría NO afecta a la ejecución ni al
    resultado devuelto. El ``engagement_id`` es advisory (lo pasa el agente); sin él, el
    registro cae al bucket ``_unscoped`` y el eje de sesión se reconstruye aguas abajo por
    ``execution_id`` (Hermes no expone su run_id al agente).

    Args:
        command: comando de shell (string no vacío; fail-closed). Dato NO confiable.
        execution_id: id de la ejecución (clave del ring y del registro de auditoría).
        timeout: segundos máximos antes de matar el grupo de procesos.
        engagement_id: agrupación del log de auditoría (advisory; ``_unscoped`` si falta).
        tool_label: etiqueta de la tool que originó la ejecución (``kali_run``/``kali_exec``).

    Returns:
        Todos los casos incluyen ``execution_id`` (para cruzar con el transcript de Hermes):
        - ``{'status':'done','returncode':rc,'output':<salida del ring>,'execution_id':...}``
          si el comando terminó (``rc`` != 0 es resultado legítimo, no error del runner).
        - ``{'status':'failed','timed_out':True,'returncode':rc,'error':...,'execution_id':...}``
          en timeout.
        - ``{'status':'cancelled','cancelled':True,'returncode':rc,'execution_id':...}`` si
          se canceló.
        - ``{'status':'failed','returncode':-1,'error':...,'execution_id':...}`` si
          ``command`` es inválido (fail-closed; no se ejecuta ni se audita).

    ``output`` (ring, acotado) y ``error`` son DATO NO CONFIABLE (verbatim). La salida
    COMPLETA (sin acotar) vive en el log de auditoría, no en este retorno.
    """
    ts_start = _now_iso()
    try:
        cmd_str = _validate_command(command)
    except ShellExecError as exc:
        # Fail-closed: nada se ejecutó, no hay salida que auditar.
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
        # Sink de salida COMPLETA (auditoría): se engancha ANTES de arrancar y se cierra al
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
                    f"kali_exec excedió el timeout ({timeout}s). "
                    f"Últimas líneas: {_ring_tail(execution_id)}"
                ),
            }
        else:
            # Un returncode != 0 NO es fallo del runner: es resultado legítimo del comando
            # (p. ej. nmap sin hallazgos, grep sin match). Se devuelve 'done' con la salida
            # del ring (acotada) y el returncode para que el bucle OODA razone sobre él.
            result = {
                "status": "done",
                "returncode": returncode,
                "output": _ring_output(execution_id),
            }
        result["execution_id"] = execution_id
        # Auditoría durable de la salida COMPLETA (FAIL-OPEN: nunca rompe la ejecución).
        _audit_execution(
            execution_id, engagement_id, tool_label, command, result, raw_path, ts_start
        )
        return result
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
