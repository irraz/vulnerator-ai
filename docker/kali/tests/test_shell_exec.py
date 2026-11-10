"""Tests stdlib-only del runner de SHELL CRUDA (`shell_exec.py`).

Ejercitan la LÓGICA del runner SIN ejecutar comandos reales (``run_tool_streaming`` se
sustituye por un fake). Fijan que:
  - ``run_shell`` con un runner de fixture devuelve ``done`` con ``output`` = salida del ring;
  - un ``command`` inválido (no-string / vacío) -> ``failed`` SIN ejecutar nada (fail-closed);
  - timeout -> ``failed`` con diagnóstico; cancelación -> ``cancelled``;
  - un ``returncode`` != 0 es ``done`` (resultado legítimo del comando, no fallo del runner);
  - el comando se pasa a ``sh -c`` verbatim (shell cruda, no se restringe el contenido).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import session_log  # noqa: E402
import shell_exec  # noqa: E402
import tool_streaming  # noqa: E402


@pytest.fixture(autouse=True)
def _staging(tmp_path, monkeypatch):
    """Apunta la raíz del staging (log de auditoría) a un tmp dir por test.

    Autouse: TODAS las llamadas a ``run_shell`` auditan en tmp, de forma determinista (sin
    tocar ``/artifacts`` real). Los tests existentes no asertan sobre el log, pero así su
    escritura de auditoría es inocua y reproducible.
    """
    monkeypatch.setenv("KALI_ARTIFACTS_DIR", str(tmp_path))
    return tmp_path


def _fake_runner(returncode=0, timed_out=False, cancelled=False, lines=None):
    """Fake de ``run_tool_streaming``: registra el cmd, vuelca ``lines`` al ring y retorna.

    ``lines`` es una lista de (stream, text) que se escribe al ring del ``execution_id`` para
    que ``_ring_output`` las recoja como salida del comando.
    """
    captured = {"cmd": None}

    def _run(cmd, execution_id, timeout=0, env=None, cwd=None):
        captured["cmd"] = cmd
        for stream, text in lines or []:
            tool_streaming.append(execution_id, stream, text)
        return (returncode, timed_out, cancelled)

    return _run, captured


def test_run_shell_passes_command_to_sh_c_verbatim(monkeypatch):
    runner, captured = _fake_runner(lines=[("stdout", "hello")])
    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", runner)

    result = shell_exec.run_shell("echo hello | tr a-z A-Z", "exec-sh-1")
    assert result["status"] == "done"
    assert result["returncode"] == 0
    # Shell cruda: el comando va TAL CUAL a `sh -c` (no se restringe pipes/encadenado).
    assert captured["cmd"] == ["sh", "-c", "echo hello | tr a-z A-Z"]
    # output = salida acumulada del ring (verbatim).
    assert "hello" in result["output"]


def test_run_shell_nonzero_returncode_is_done_not_failed(monkeypatch):
    # Un comando que termina con rc!=0 (p. ej. grep sin match) NO es fallo del runner.
    runner, _ = _fake_runner(returncode=1, lines=[("stderr", "no match")])
    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", runner)

    result = shell_exec.run_shell("grep nope /etc/hosts", "exec-sh-rc")
    assert result["status"] == "done"
    assert result["returncode"] == 1
    assert "no match" in result["output"]


@pytest.mark.parametrize("bad", ["", "   ", None, 123, ["ls"]])
def test_run_shell_rejects_invalid_command_without_running(monkeypatch, bad):
    called = {"ran": False}

    def _should_not_run(*args, **kwargs):
        called["ran"] = True
        return (0, False, False)

    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", _should_not_run)
    result = shell_exec.run_shell(bad, "exec-sh-bad")
    assert result["status"] == "failed"
    assert called["ran"] is False  # fail-closed: no se lanzó `sh -c`
    assert "command inválido" in result["error"]


def test_run_shell_timeout_reports_failed(monkeypatch):
    runner, _ = _fake_runner(returncode=-1, timed_out=True)
    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", runner)

    result = shell_exec.run_shell("sleep 999", "exec-sh-timeout", timeout=5)
    assert result["status"] == "failed"
    assert result["timed_out"] is True
    assert "timeout" in result["error"].lower()


def test_run_shell_cancelled(monkeypatch):
    runner, _ = _fake_runner(returncode=-1, cancelled=True)
    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", runner)

    result = shell_exec.run_shell("sleep 999", "exec-sh-cancel")
    assert result["status"] == "cancelled"
    assert result["cancelled"] is True


# --- Auditoría durable (session_log): salida COMPLETA, fail-open, execution_id ----------


def _read_session_log(staging, engagement_id):
    path = Path(staging) / engagement_id / session_log.SESSION_LOG_NAME
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def test_run_shell_includes_execution_id_in_result(monkeypatch):
    runner, _ = _fake_runner(lines=[("stdout", "hi")])
    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", runner)

    result = shell_exec.run_shell("echo hi", "exec-id-1", engagement_id="eng-x")
    assert result["execution_id"] == "exec-id-1"


def test_run_shell_writes_audit_record_with_command_and_output(_staging, monkeypatch):
    runner, _ = _fake_runner(returncode=0, lines=[("stdout", "uid=0(root)")])
    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", runner)

    shell_exec.run_shell("id", "exec-audit-1", engagement_id="eng-test", tool_label="kali_run")

    records = _read_session_log(_staging, "eng-test")
    assert len(records) == 1
    rec = records[0]
    assert rec["execution_id"] == "exec-audit-1"
    assert rec["engagement_id"] == "eng-test"
    assert rec["tool"] == "kali_run"
    assert rec["command"] == "id"
    assert rec["status"] == "done"
    assert rec["returncode"] == 0
    assert "uid=0(root)" in rec["output"]
    assert rec["ts_start"].endswith("Z")
    assert rec["ts_end"].endswith("Z")


def test_audit_captures_full_output_beyond_ring_cap(_staging, monkeypatch):
    # El fake vuelca MÁS líneas que el tope del ring: el ring (lo que ve el LLM) se capa,
    # pero el registro de auditoría debe tener la salida ÍNTEGRA.
    total = tool_streaming.RING_MAXLEN + 50
    lines = [("stdout", f"line-{i}") for i in range(total)]
    runner, _ = _fake_runner(returncode=0, lines=lines)
    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", runner)

    result = shell_exec.run_shell("big", "exec-big-1", engagement_id="eng-big")

    # Lo que ve el LLM (ring) está capado.
    assert result["output"].count("\n") + 1 == tool_streaming.RING_MAXLEN

    # El registro de auditoría tiene TODAS las líneas y marca el truncado.
    rec = _read_session_log(_staging, "eng-big")[0]
    assert rec["total_lines"] == total
    assert rec["returned_lines"] == tool_streaming.RING_MAXLEN
    assert rec["truncated"] is True
    assert "[stdout] line-0" in rec["output"]
    assert f"[stdout] line-{total - 1}" in rec["output"]


def test_empty_engagement_id_falls_back_to_unscoped(_staging, monkeypatch):
    runner, _ = _fake_runner(lines=[("stdout", "x")])
    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", runner)

    shell_exec.run_shell("echo x", "exec-unscoped-1")  # sin engagement_id

    rec = _read_session_log(_staging, session_log.DEFAULT_ENGAGEMENT)[0]
    assert rec["execution_id"] == "exec-unscoped-1"
    assert rec["engagement_id"] == session_log.DEFAULT_ENGAGEMENT


def test_audit_failure_is_fail_open_does_not_break_command(monkeypatch):
    # Si la escritura de auditoría revienta, el comando IGUAL devuelve su resultado normal.
    runner, _ = _fake_runner(returncode=0, lines=[("stdout", "ok")])
    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", runner)

    def _boom(*args, **kwargs):
        raise RuntimeError("disk full / whatever")

    monkeypatch.setattr(shell_exec.session_log, "record", _boom)

    result = shell_exec.run_shell("echo ok", "exec-failopen-1", engagement_id="eng-y")
    assert result["status"] == "done"
    assert result["returncode"] == 0
    assert "ok" in result["output"]
    assert result["execution_id"] == "exec-failopen-1"


def test_invalid_command_not_audited_but_returns_execution_id(_staging, monkeypatch):
    # Comando inválido: fail-closed, no se ejecuta ni se audita, pero devuelve execution_id.
    def _should_not_run(*args, **kwargs):
        raise AssertionError("no debe ejecutarse")

    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", _should_not_run)
    result = shell_exec.run_shell("", "exec-invalid-1", engagement_id="eng-z")
    assert result["status"] == "failed"
    assert result["execution_id"] == "exec-invalid-1"
    # No se creó ningún log para ese engagement (no hubo ejecución que auditar).
    assert not (Path(_staging) / "eng-z" / session_log.SESSION_LOG_NAME).exists()
