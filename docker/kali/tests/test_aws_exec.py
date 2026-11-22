"""Tests stdlib-only del runner AWS del enum (`aws_exec.py`).

They exercise the runner's LOGIC without boto3 or the real script (``aws_iam_enum.py`` is not
imported: boto3 is not in the dev venv). They assert that:
  - ``build_iam_enum_cmd`` produce el argv esperado (sin shell) y RECHAZA fail-closed un
    ``account_id`` mal formado;
  - ``run_iam_enum`` con un ``run_tool_streaming`` de FIXTURE (escribe un JSON en outfile)
    devuelve ``done`` con ``output`` legible (el JSON crudo);
  - no readable output -> ``failed`` with diagnostic; invalid account_id -> ``failed`` without
    ejecutar nada; timeout -> ``failed``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import aws_exec  # noqa: E402


# --------------------------------------------------------------- build_iam_enum_cmd


def test_build_iam_enum_cmd_shape_no_shell():
    cmd = aws_exec.build_iam_enum_cmd("123456789012", "", "/tmp/out.json")
    assert cmd[0] == "python3"
    assert cmd[1].endswith("aws_iam_enum.py")
    assert cmd[cmd.index("--account") + 1] == "123456789012"
    assert cmd[cmd.index("--out") + 1] == "/tmp/out.json"
    # Sin shell: argv como lista, cada token separado (no una cadena interpolada).
    assert all(isinstance(tok, str) for tok in cmd)


@pytest.mark.parametrize(
    "bad",
    ["", "123", "12345678901", "1234567890123", "12345678901a", "../etc", "1; rm -rf /"],  # pragma: allowlist secret
)
def test_build_iam_enum_cmd_rejects_malformed_account(bad):
    with pytest.raises(aws_exec.AwsExecError):
        aws_exec.build_iam_enum_cmd(bad, "", "/tmp/out.json")


def test_build_iam_enum_cmd_trims_account():
    cmd = aws_exec.build_iam_enum_cmd("  123456789012  ", "", "/tmp/out.json")
    assert cmd[cmd.index("--account") + 1] == "123456789012"


# --------------------------------------------------------------- run_iam_enum


def _fake_runner(write_output):
    """Fake of ``run_tool_streaming``: writes fixture output and returns success."""

    def _run(cmd, execution_id, timeout=0, env=None, cwd=None):
        write_output(cmd)
        return (0, False, False)

    return _run


def test_run_iam_enum_done_with_readable_output(monkeypatch):
    document = {"account": "123456789012", "iam": {"roles": [], "counts": {"roles": 0}}}

    def _write(cmd):
        outfile = cmd[cmd.index("--out") + 1]
        Path(outfile).write_text(json.dumps(document), encoding="utf-8")

    monkeypatch.setattr(
        aws_exec.tool_streaming, "run_tool_streaming", _fake_runner(_write)
    )

    result = aws_exec.run_iam_enum("123456789012", "", "exec-ok")
    assert result["status"] == "done"
    assert result["returncode"] == 0
    # The 'output' is the raw JSON verbatim (travels inline, not staged here).
    assert json.loads(result["output"]) == document


def test_run_iam_enum_failed_when_no_output(monkeypatch):
    # Runner que NO escribe nada en outfile -> no hay salida legible.
    monkeypatch.setattr(
        aws_exec.tool_streaming,
        "run_tool_streaming",
        _fake_runner(lambda cmd: None),
    )
    result = aws_exec.run_iam_enum("123456789012", "", "exec-nooutput")
    assert result["status"] == "failed"
    assert "no produjo salida legible" in result["error"]


def test_run_iam_enum_rejects_bad_account_without_running(monkeypatch):
    called = {"ran": False}

    def _should_not_run(*args, **kwargs):
        called["ran"] = True
        return (0, False, False)

    monkeypatch.setattr(aws_exec.tool_streaming, "run_tool_streaming", _should_not_run)
    result = aws_exec.run_iam_enum("not-an-account", "", "exec-bad")
    assert result["status"] == "failed"
    assert called["ran"] is False  # fail-closed: no subprocess was run
    assert "invalid account_id" in result["error"]


def test_run_iam_enum_timeout_reports_failed(monkeypatch):
    def _timeout(cmd, execution_id, timeout=0, env=None, cwd=None):
        return (-1, True, False)  # timed_out=True

    monkeypatch.setattr(aws_exec.tool_streaming, "run_tool_streaming", _timeout)
    result = aws_exec.run_iam_enum("123456789012", "", "exec-timeout")
    assert result["status"] == "failed"
    assert result["timed_out"] is True
    assert "timeout" in result["error"].lower()


def test_run_iam_enum_cancelled(monkeypatch):
    def _cancelled(cmd, execution_id, timeout=0, env=None, cwd=None):
        return (-1, False, True)  # cancelled=True

    monkeypatch.setattr(aws_exec.tool_streaming, "run_tool_streaming", _cancelled)
    result = aws_exec.run_iam_enum("123456789012", "", "exec-cancel")
    assert result["status"] == "cancelled"
    assert result["cancelled"] is True
