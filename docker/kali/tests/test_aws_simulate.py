"""Tests stdlib-only del runner AWS del simulate (`aws_simulate.py`).

Espejo de ``test_aws_exec``: ejercitan la LÓGICA del runner SIN boto3 ni el script real
(``aws_iam_simulate.py`` no se importa: boto3 no está en el venv de dev; se valida con
``ast.parse``). Fijan que:
  - ``build_iam_simulate_cmd`` produce el argv esperado (sin shell) y RECHAZA fail-closed un
    ``account_id`` o un ``principal_arn`` mal formados (incluido un ARN de OTRA cuenta);
  - ``run_iam_simulate`` con un ``run_tool_streaming`` de FIXTURE (escribe un JSON de simulate)
    devuelve ``done`` con ``output`` legible;
  - sin salida legible -> ``failed``; account/arn inválidos -> ``failed`` sin ejecutar nada;
    timeout -> ``failed``; cancelación -> ``cancelled``; AccessDenied ESTRUCTURADO (``error`` en
    el JSON) -> ``failed`` claro con el error verbatim.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aws_simulate  # noqa: E402

ACCOUNT = "123456789012"
PRINCIPAL = f"arn:aws:iam::{ACCOUNT}:role/app-role"


# --------------------------------------------------------------- build_iam_simulate_cmd


def test_build_iam_simulate_cmd_shape_no_shell():
    cmd = aws_simulate.build_iam_simulate_cmd(ACCOUNT, PRINCIPAL, "/tmp/out.json")
    assert cmd[0] == "python3"
    assert cmd[1].endswith("aws_iam_simulate.py")
    assert cmd[cmd.index("--account") + 1] == ACCOUNT
    assert cmd[cmd.index("--principal-arn") + 1] == PRINCIPAL
    assert cmd[cmd.index("--out") + 1] == "/tmp/out.json"
    # Sin shell: argv como lista, cada token separado (no una cadena interpolada).
    assert all(isinstance(tok, str) for tok in cmd)


@pytest.mark.parametrize(
    "bad",
    ["", "123", "12345678901", "1234567890123", "12345678901a", "../etc", "1; rm -rf /"],  # pragma: allowlist secret
)
def test_build_iam_simulate_cmd_rejects_malformed_account(bad):
    with pytest.raises(aws_simulate.AwsSimulateError):
        aws_simulate.build_iam_simulate_cmd(bad, PRINCIPAL, "/tmp/out.json")


@pytest.mark.parametrize(
    "bad_arn",
    [
        "",
        "not-an-arn",
        "arn:aws:s3:::bucket",
        "arn:aws:iam::123:role/x",  # cuenta no de 12 dígitos
        "arn:aws:iam::123456789012:role/x;rm -rf /",  # metacaracteres de shell
    ],
)
def test_build_iam_simulate_cmd_rejects_malformed_arn(bad_arn):
    with pytest.raises(aws_simulate.AwsSimulateError):
        aws_simulate.build_iam_simulate_cmd(ACCOUNT, bad_arn, "/tmp/out.json")


def test_build_iam_simulate_cmd_rejects_cross_account_arn():
    # ARN bien formado pero de OTRA cuenta: fuera de la cuenta autorizada (N-untrusted).
    foreign = "arn:aws:iam::999999999999:role/app-role"
    with pytest.raises(aws_simulate.AwsSimulateError):
        aws_simulate.build_iam_simulate_cmd(ACCOUNT, foreign, "/tmp/out.json")


def test_build_iam_simulate_cmd_trims_inputs():
    cmd = aws_simulate.build_iam_simulate_cmd(f"  {ACCOUNT}  ", f"  {PRINCIPAL}  ", "/tmp/out.json")
    assert cmd[cmd.index("--account") + 1] == ACCOUNT
    assert cmd[cmd.index("--principal-arn") + 1] == PRINCIPAL


# --------------------------------------------------------------- run_iam_simulate


def _fake_runner(write_output):
    """Fake de ``run_tool_streaming``: escribe la salida de fixture y devuelve éxito."""

    def _run(cmd, execution_id, timeout=0, env=None, cwd=None):
        write_output(cmd)
        return (0, False, False)

    return _run


def test_run_iam_simulate_done_with_readable_output(monkeypatch):
    document = {
        "account": ACCOUNT,
        "principal_arn": PRINCIPAL,
        "actions": ["sts:AssumeRole", "iam:PassRole"],
        "simulation": {"iam:PassRole": "allowed", "sts:AssumeRole": "implicitDeny"},
    }

    def _write(cmd):
        outfile = cmd[cmd.index("--out") + 1]
        Path(outfile).write_text(json.dumps(document), encoding="utf-8")

    monkeypatch.setattr(
        aws_simulate.tool_streaming, "run_tool_streaming", _fake_runner(_write)
    )

    result = aws_simulate.run_iam_simulate(ACCOUNT, PRINCIPAL, "exec-ok")
    assert result["status"] == "done"
    assert result["returncode"] == 0
    # El 'output' es el JSON crudo verbatim (viaja inline, no se stagea aquí).
    assert json.loads(result["output"]) == document


def test_run_iam_simulate_failed_when_no_output(monkeypatch):
    # Runner que NO escribe nada en outfile -> no hay salida legible.
    monkeypatch.setattr(
        aws_simulate.tool_streaming,
        "run_tool_streaming",
        _fake_runner(lambda cmd: None),
    )
    result = aws_simulate.run_iam_simulate(ACCOUNT, PRINCIPAL, "exec-nooutput")
    assert result["status"] == "failed"
    assert "no produjo salida legible" in result["error"]


def test_run_iam_simulate_access_denied_structured_error_is_failed(monkeypatch):
    # El script THIN escribe un JSON con 'error' (AccessDenied del propio Simulate, fail-closed).
    document = {
        "account": ACCOUNT,
        "principal_arn": PRINCIPAL,
        "error": "SimulatePrincipalPolicy no disponible: AccessDenied",
        "simulation": {},
    }

    def _write(cmd):
        outfile = cmd[cmd.index("--out") + 1]
        Path(outfile).write_text(json.dumps(document), encoding="utf-8")

    monkeypatch.setattr(
        aws_simulate.tool_streaming, "run_tool_streaming", _fake_runner(_write)
    )
    result = aws_simulate.run_iam_simulate(ACCOUNT, PRINCIPAL, "exec-denied")
    assert result["status"] == "failed"
    # El error del simulate se propaga VERBATIM (dato NO confiable).
    assert "AccessDenied" in result["error"]


def test_run_iam_simulate_rejects_bad_account_without_running(monkeypatch):
    called = {"ran": False}

    def _should_not_run(*args, **kwargs):
        called["ran"] = True
        return (0, False, False)

    monkeypatch.setattr(aws_simulate.tool_streaming, "run_tool_streaming", _should_not_run)
    result = aws_simulate.run_iam_simulate("not-an-account", PRINCIPAL, "exec-bad")
    assert result["status"] == "failed"
    assert called["ran"] is False  # fail-closed: no se ejecutó el subproceso
    assert "account_id inválido" in result["error"]


def test_run_iam_simulate_rejects_bad_arn_without_running(monkeypatch):
    called = {"ran": False}

    def _should_not_run(*args, **kwargs):
        called["ran"] = True
        return (0, False, False)

    monkeypatch.setattr(aws_simulate.tool_streaming, "run_tool_streaming", _should_not_run)
    result = aws_simulate.run_iam_simulate(ACCOUNT, "not-an-arn", "exec-badarn")
    assert result["status"] == "failed"
    assert called["ran"] is False  # fail-closed: no se ejecutó el subproceso
    assert "principal_arn inválido" in result["error"]


def test_run_iam_simulate_timeout_reports_failed(monkeypatch):
    def _timeout(cmd, execution_id, timeout=0, env=None, cwd=None):
        return (-1, True, False)  # timed_out=True

    monkeypatch.setattr(aws_simulate.tool_streaming, "run_tool_streaming", _timeout)
    result = aws_simulate.run_iam_simulate(ACCOUNT, PRINCIPAL, "exec-timeout")
    assert result["status"] == "failed"
    assert result["timed_out"] is True
    assert "timeout" in result["error"].lower()


def test_run_iam_simulate_cancelled(monkeypatch):
    def _cancelled(cmd, execution_id, timeout=0, env=None, cwd=None):
        return (-1, False, True)  # cancelled=True

    monkeypatch.setattr(aws_simulate.tool_streaming, "run_tool_streaming", _cancelled)
    result = aws_simulate.run_iam_simulate(ACCOUNT, PRINCIPAL, "exec-cancel")
    assert result["status"] == "cancelled"
    assert result["cancelled"] is True


# --------------------------------------------------------------- thin script (ast.parse)


def test_thin_simulate_script_parses():
    """``aws_iam_simulate.py`` es THIN (no se importa: boto3 ausente); se valida con ast.parse."""
    script = Path(aws_simulate._script_path())
    assert script.is_file()
    ast.parse(script.read_text(encoding="utf-8"))
