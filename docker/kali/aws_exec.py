"""Runner AWS (STDLIB PURA) — construye y ejecuta el enum IAM read-only.

It is the testable LOGIC of the ``iam_enum`` runner that ``kali_mcp_server`` exposes as
``@mcp.tool`` SYNCHRONOUSLY. Like ``collector_runner`` / ``tool_streaming``, it lives in a
separate module that uses ONLY the standard library (no ``mcp``, no ``boto3``) so it can be
covered by unit tests in the dev venv, where neither the SDK nor boto3 is installed.

What it provides:
  - ``build_iam_enum_cmd(account_id, params, outfile)``: construye el argv (sin shell)
    ``[python3, aws_iam_enum.py, --account, <id>, --out, <outfile>]``. Valida ``account_id``
    in the shape of an AWS account (12 digits) and REJECTS malformed input fail-closed (never
    interpola entrada sin validar en un comando).
  - ``run_iam_enum(account_id, params, execution_id, timeout)``: crea un tmpdir, construye
    el cmd, lo ejecuta con ``tool_streaming.run_tool_streaming`` (kill de grupo/timeout/logs
    al ring), lee el fichero de salida y devuelve ``{'status':'done',...,'output':<json-str>}``
    or ``{'status':'failed',...,'error':<diagnostic>}``; cleans up the tmpdir in ``finally``.

It is SYNCHRONOUS, single-shot (unlike the async collector): the scoped IAM enum is
short and its single JSON travels inline in ``output``; no artifact is staged here.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

import tool_streaming

# THIN boto3 script that runs the real enum. Lives alongside this module in the image
# (COPY in the Dockerfile); invoked as a subprocess, NOT imported (boto3 is not in
# el venv de dev).
IAM_ENUM_SCRIPT = "aws_iam_enum.py"

# Default timeout for the IAM enum (seconds). The scoped enum is short; still it is bounded
# para no colgar el servidor. Overridable por entorno.
DEFAULT_TIMEOUT = int(os.environ.get("AWS_IAM_ENUM_TIMEOUT", "300"))

# Name of the output file inside the ephemeral tmpdir.
_OUTFILE_NAME = "iam-enum.json"

# Shape of an AWS account ID: exactly 12 digits (fail-closed, N-untrusted).
_ACCOUNT_RE = re.compile(r"^\d{12}$")


class AwsExecError(ValueError):
    """Entrada mal formada para el runner AWS (fail-closed; no se ejecuta nada)."""


def _validate_account_id(account_id: str) -> str:
    """Validates ``account_id`` in the shape of an AWS account (12 digits) or raises ``AwsExecError``.

    N-untrusted: el ``account_id`` llega del CONTROL (potencialmente no confiable); nunca se
    interpolates into a command without validation. Fail-closed: anything that is not 12 digits
    se rechaza con un error claro, sin ejecutar el subproceso.
    """
    if not isinstance(account_id, str) or not _ACCOUNT_RE.match(account_id.strip()):
        raise AwsExecError(
            f"invalid account_id: {account_id!r} (expected 12 AWS account digits)."
        )
    return account_id.strip()


def _script_path() -> str:
    """Absolute path of the enum script, resolved next to this module (cwd-independent)."""
    return str(Path(__file__).resolve().parent / IAM_ENUM_SCRIPT)


def build_iam_enum_cmd(account_id: str, params: Any, outfile: str) -> list[str]:
    """Construye el argv (sin shell) del enum IAM; valida ``account_id`` fail-closed.

    ``params`` se acepta por contrato (reservado para acotaciones futuras); hoy no altera
    el comando. Devuelve ``[python3, <ruta aws_iam_enum.py>, --account, <id>, --out, <out>]``.
    """
    account = _validate_account_id(account_id)
    return [
        "python3",
        _script_path(),
        "--account",
        account,
        "--out",
        outfile,
    ]


def _ring_tail(execution_id: str, max_lines: int = 20) -> str:
    """Last lines of the run's output (UNTRUSTED data, verbatim)."""
    page = tool_streaming.read(execution_id, 0)
    lines = page.get("lines", [])
    tail = lines[-max_lines:]
    return "\n".join(f"[{line['stream']}] {line['text']}" for line in tail)


def run_iam_enum(
    account_id: str,
    params: Any = "",
    execution_id: str = "",
    timeout: int = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Runs the read-only IAM enum and returns the raw JSON (SYNCHRONOUS, single-shot).

    Flow: validate ``account_id`` (fail-closed) -> create an ephemeral tmpdir -> build the
    cmd -> ejecuta con ``tool_streaming.run_tool_streaming`` (kill de grupo/timeout, logs al
    ring por ``execution_id``) -> lee el fichero de salida. Devuelve
    ``{'status':'done','returncode':rc,'output':<json-string>}`` si hay salida legible, o
    ``{'status':'failed','returncode':rc,'error':<diagnostic with ring tail>}`` in
    timeout/sin salida. Limpia el tmpdir en ``finally``. El JSON crudo viaja inline en
    ``output``; no artifact is staged here.
    """
    try:
        account = _validate_account_id(account_id)
    except AwsExecError as exc:
        return {"status": "failed", "returncode": -1, "error": str(exc)}

    workdir = tempfile.mkdtemp(prefix="aws-iam-enum-")
    try:
        outfile = str(Path(workdir) / _OUTFILE_NAME)
        cmd = build_iam_enum_cmd(account, params, outfile)
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
                    f"iam_enum exceeded the timeout ({timeout}s). "
                    f"Last lines: {_ring_tail(execution_id)}"
                ),
            }
        output = _read_output(outfile)
        if output is None:
            return {
                "status": "failed",
                "returncode": returncode,
                "error": (
                    f"iam_enum no produjo salida legible (exit={returncode}): "
                    f"{_ring_tail(execution_id)}"
                ),
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
