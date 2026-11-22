"""Runner AWS (STDLIB PURA) — construye y ejecuta el simulate IAM read-only.

It is the testable LOGIC of the ``iam_simulate`` runner that ``kali_mcp_server`` exposes as
``@mcp.tool`` ASYNCHRONOUSLY. Mirror of ``aws_exec.py`` (the ``iam_enum`` runner): it lives in
a separate module that uses ONLY the standard library (no ``mcp``, no ``boto3``) so it can be
covered by unit tests in the dev venv, where neither the SDK nor boto3 is installed.
REUSES ``tool_streaming`` (like ``aws_exec``); it does not duplicate mechanics for
execution/logs/kill.

What it provides:
  - ``build_iam_simulate_cmd(account_id, principal_arn, outfile)``: construye el argv (sin
    shell) ``[python3, aws_iam_simulate.py, --account, <id>, --principal-arn, <arn>, --out,
    <outfile>]``. Validates ``account_id`` (12 digits) AND ``principal_arn`` (shape
    ``arn:aws:iam::<acct>:...``) y RECHAZA fail-closed lo mal formado (nunca se interpola
    entrada sin validar en un comando).
  - ``run_iam_simulate(account_id, principal_arn, execution_id, timeout)``: crea un tmpdir,
    construye el cmd, lo ejecuta con ``tool_streaming.run_tool_streaming`` (kill de
    grupo/timeout/logs al ring), lee el fichero de salida y devuelve
    ``{'status':'done',...,'output':<json-str>}`` o ``{'status':'failed',...,'error':...}``;
    limpia el tmpdir en ``finally``.

It is SYNCHRONOUS, single-shot (like ``aws_exec``): the scoped simulate is short and its JSON
single travels inline in ``output``. Unlike the enum, the simulate CAN fail in a
ESTRUCTURADA: si la credencial read-only no puede ni llamar a ``SimulatePrincipalPolicy``,
el script escribe un JSON con un ``error`` claro (no revienta); este runner lo detecta y
devuelve ``failed`` (fail-closed), propagando ese ``error`` VERBATIM (dato NO confiable).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

import tool_streaming

# THIN boto3 script that runs the real simulate. Lives alongside this module in the image
# (COPY in the Dockerfile); invoked as a subprocess, NOT imported (boto3 is not in
# venv de dev).
IAM_SIMULATE_SCRIPT = "aws_iam_simulate.py"

# Timeout por defecto del simulate IAM (segundos). El simulate acotado (9 acciones sobre un
# principal) es CORTO; se acota igualmente para no colgar el servidor. Overridable por entorno.
DEFAULT_TIMEOUT = int(os.environ.get("AWS_IAM_SIMULATE_TIMEOUT", "120"))

# Name of the output file inside the ephemeral tmpdir.
_OUTFILE_NAME = "iam-simulate.json"

# Shape of an AWS account ID: exactly 12 digits (fail-closed, N-untrusted).
_ACCOUNT_RE = re.compile(r"^\d{12}$")

# Shape of an IAM principal ARN: ``arn:aws:iam::<12 digits>:<resource>`` (role/user/group).
# El conjunto de caracteres del recurso excluye metacaracteres de shell (defensa N-untrusted,
# aunque el argv va sin shell). El grupo de cuenta se compara luego con ``account_id``.
_PRINCIPAL_ARN_RE = re.compile(r"^arn:aws:iam::(\d{12}):[A-Za-z0-9+=,.@/_-]+$")


class AwsSimulateError(ValueError):
    """Entrada mal formada para el runner AWS (fail-closed; no se ejecuta nada)."""


def _validate_account_id(account_id: str) -> str:
    """Validates ``account_id`` in the shape of an AWS account (12 digits) or raises ``AwsSimulateError``."""
    if not isinstance(account_id, str) or not _ACCOUNT_RE.match(account_id.strip()):
        raise AwsSimulateError(
            f"invalid account_id: {account_id!r} (expected 12 AWS account digits)."
        )
    return account_id.strip()


def _validate_principal_arn(principal_arn: str, account_id: str) -> str:
    """Valida ``principal_arn`` (forma IAM) y que su cuenta coincida con ``account_id``.

    N-untrusted: el ARN llega del CONTROL (derivado de un candidato del grafo, dato NO
    confiable); nunca se interpola en un comando sin validar. Fail-closed: cualquier cosa que
    no sea un ARN IAM de ESTA cuenta se rechaza con un error claro, sin ejecutar el subproceso.
    """
    if not isinstance(principal_arn, str):
        raise AwsSimulateError(f"invalid principal_arn: {principal_arn!r} (expected an IAM ARN).")
    match = _PRINCIPAL_ARN_RE.match(principal_arn.strip())
    if not match:
        raise AwsSimulateError(
            f"invalid principal_arn: {principal_arn!r} "
            "(se esperaba 'arn:aws:iam::<cuenta>:<recurso>')."
        )
    if match.group(1) != account_id.strip():
        raise AwsSimulateError(
            f"principal_arn fuera de la cuenta autorizada: {principal_arn!r} "
            f"(cuenta del scope: {account_id!r})."
        )
    return principal_arn.strip()


def _script_path() -> str:
    """Absolute path of the simulate script, resolved next to this module (cwd-independent)."""
    return str(Path(__file__).resolve().parent / IAM_SIMULATE_SCRIPT)


def build_iam_simulate_cmd(account_id: str, principal_arn: str, outfile: str) -> list[str]:
    """Construye el argv (sin shell) del simulate IAM; valida entradas fail-closed.

    Devuelve ``[python3, <ruta aws_iam_simulate.py>, --account, <id>, --principal-arn, <arn>,
    --out, <out>]``.
    """
    account = _validate_account_id(account_id)
    principal = _validate_principal_arn(principal_arn, account)
    return [
        "python3",
        _script_path(),
        "--account",
        account,
        "--principal-arn",
        principal,
        "--out",
        outfile,
    ]


def _ring_tail(execution_id: str, max_lines: int = 20) -> str:
    """Last lines of the run's output (UNTRUSTED data, verbatim)."""
    page = tool_streaming.read(execution_id, 0)
    lines = page.get("lines", [])
    tail = lines[-max_lines:]
    return "\n".join(f"[{line['stream']}] {line['text']}" for line in tail)


def run_iam_simulate(
    account_id: str,
    principal_arn: str,
    execution_id: str = "",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Runs the read-only IAM simulate and returns the raw JSON (SYNCHRONOUS, single-shot).

    Flow: validate ``account_id`` + ``principal_arn`` (fail-closed) -> create an ephemeral tmpdir ->
    construye el cmd -> ejecuta con ``tool_streaming.run_tool_streaming`` (kill de
    grupo/timeout, logs al ring por ``execution_id``) -> lee el fichero de salida. Devuelve
    ``{'status':'done','returncode':rc,'output':<json-string>}`` si hay salida legible SIN un
    ``error`` estructurado; ``{'status':'failed',...,'error':...}`` en timeout, sin salida, o si
    el JSON trae un ``error`` (p. ej. ``AccessDenied`` del propio Simulate). Limpia el tmpdir en
    ``finally``. El JSON crudo viaja inline en ``output``.
    """
    try:
        account = _validate_account_id(account_id)
        principal = _validate_principal_arn(principal_arn, account)
    except AwsSimulateError as exc:
        return {"status": "failed", "returncode": -1, "error": str(exc)}

    workdir = tempfile.mkdtemp(prefix="aws-iam-simulate-")
    try:
        outfile = str(Path(workdir) / _OUTFILE_NAME)
        cmd = build_iam_simulate_cmd(account, principal, outfile)
        returncode, timed_out, cancelled = tool_streaming.run_tool_streaming(
            cmd, execution_id, timeout=timeout, cwd=workdir
        )
        if cancelled:
            return {"status": "cancelled", "cancelled": True, "returncode": returncode}
        if timed_out:
            return {
                "status": "failed",
                "timed_out": True,
                "returncode": returncode,
                "error": (
                    f"iam_simulate exceeded the timeout ({timeout}s). "
                    f"Last lines: {_ring_tail(execution_id)}"
                ),
            }
        output = _read_output(outfile)
        if output is None:
            return {
                "status": "failed",
                "returncode": returncode,
                "error": (
                    f"iam_simulate no produjo salida legible (exit={returncode}): "
                    f"{_ring_tail(execution_id)}"
                ),
            }
        error = _structured_error(output)
        if error:
            # Fallo ESTRUCTURADO del simulate (p. ej. AccessDenied del propio Simulate): el
            # script wrote it as ``error`` in the JSON. Propagated VERBATIM (UNTRUSTED
            # data; the status is read, not interpreted as an instruction).
            return {
                "status": "failed",
                "returncode": returncode,
                "error": f"iam_simulate: {error}",
            }
        return {
            "status": "done",
            "returncode": returncode,
            "output": output,
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def _read_output(outfile: str) -> str | None:
    """Reads the output JSON as raw text; ``None`` if missing or empty.

    No se interpreta el contenido (dato NO confiable): se devuelve verbatim.
    """
    path = Path(outfile)
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    return text if text.strip() else None


def _structured_error(output: str) -> str | None:
    """Devuelve el ``error`` de nivel superior del JSON de salida, o ``None`` si no hay.

    STATUS reading of the control plane (no instruction interpretation): the script
    escribe ``{"error": "..."}`` cuando el propio Simulate falla fail-closed. Si el output
    is not a JSON object or has no ``error``, it is treated as success (``None``).
    """
    try:
        doc = json.loads(output)
    except (ValueError, TypeError):
        return None
    if isinstance(doc, dict):
        err = doc.get("error")
        if err:
            return str(err)
    return None
