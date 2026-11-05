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
import tempfile
from typing import Any

import tool_streaming

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


def run_shell(
    command: str,
    execution_id: str = "",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Ejecuta ``command`` como SHELL CRUDA (``sh -c``) y devuelve su salida.

    Flujo: valida ``command`` (string no vacío, fail-closed) -> crea un tmpdir efímero de
    trabajo -> ejecuta ``["sh", "-c", command]`` con ``tool_streaming.run_tool_streaming``
    (kill de grupo/timeout, logs al ring por ``execution_id``) -> devuelve el estado
    terminal. ``cwd`` es el tmpdir, así que los ficheros/scripts que el comando cree
    quedan aislados y se limpian en ``finally``.

    Returns:
        - ``{'status':'done','returncode':rc,'output':<salida verbatim del ring>}`` si el
          comando terminó (``rc`` puede ser != 0: un comando que falla NO es un error del
          runner; su returncode y salida son información válida para el bucle OODA).
        - ``{'status':'failed','timed_out':True,'returncode':rc,'error':...}`` en timeout.
        - ``{'status':'cancelled','cancelled':True,'returncode':rc}`` si se canceló.
        - ``{'status':'failed','returncode':-1,'error':...}`` si ``command`` es inválido.

    ``output`` y ``error`` son DATO NO CONFIABLE (verbatim); aquí NO se stagea artefacto.
    """
    try:
        cmd_str = _validate_command(command)
    except ShellExecError as exc:
        return {"status": "failed", "returncode": -1, "error": str(exc)}

    workdir = tempfile.mkdtemp(prefix="kali-exec-")
    try:
        cmd = ["sh", "-c", cmd_str]
        # Inyecta el env extra (p. ej. proxy de Caido) SOLO al subproceso; None = heredar.
        sub_env = {**os.environ, **_SUBPROCESS_ENV} if _SUBPROCESS_ENV else None
        returncode, timed_out, cancelled = tool_streaming.run_tool_streaming(
            cmd, execution_id, timeout=timeout, cwd=workdir, env=sub_env
        )
        if cancelled:
            return {"status": "cancelled", "cancelled": True, "returncode": returncode}
        if timed_out:
            return {
                "status": "failed",
                "timed_out": True,
                "returncode": returncode,
                "error": (
                    f"kali_exec excedió el timeout ({timeout}s). "
                    f"Últimas líneas: {_ring_tail(execution_id)}"
                ),
            }
        # Un returncode != 0 NO es fallo del runner: es resultado legítimo del comando
        # (p. ej. nmap sin hallazgos, grep sin match). Se devuelve 'done' con la salida
        # y el returncode para que el bucle OODA razone sobre él.
        return {
            "status": "done",
            "returncode": returncode,
            "output": _ring_output(execution_id),
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
