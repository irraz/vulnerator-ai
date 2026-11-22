"""Tests de la tool BLOQUEANTE ``kali_run`` (STDLIB PURA, SIN importar el servidor).

Hard environment constraint: the local venv has ``mcp`` 2.x but
``kali_mcp_server.py`` requires ``mcp<2`` (FastMCP 1.x), so ``import kali_mcp_server``
FAILS. That is why these tests do NOT import the server: they validate (a) the blocking LOGIC via
``shell_exec.run_shell`` (que es lo que ``kali_run`` llama SINCRONAMENTE) y (b) la forma
of the server by reading its SOURCE TEXT (open().read() + assertions), never importing it.

They follow the pattern of ``tests/test_shell_exec.py``: ``sys.path.insert`` of the parent, import of
``shell_exec``/``tool_streaming`` y monkeypatch de ``run_tool_streaming`` con un fake que
dumps lines to the ring.
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest

_PARENT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PARENT))

import shell_exec  # noqa: E402
import tool_streaming  # noqa: E402

# Ruta del servidor cuyo TEXTO (no import) se inspecciona en los tests de forma.
_SERVER_PATH = _PARENT / "kali_mcp_server.py"


def _fake_runner(returncode=0, timed_out=False, cancelled=False, lines=None):
    """Fake de ``run_tool_streaming``: vuelca ``lines`` al ring y retorna el estado.

    ``lines`` es una lista de (stream, text) que se escribe al ring del ``execution_id``
    para que ``run_shell`` las recoja como salida del comando.
    """

    def _run(cmd, execution_id, timeout=0, env=None, cwd=None):
        for stream, text in lines or []:
            tool_streaming.append(execution_id, stream, text)
        return (returncode, timed_out, cancelled)

    return _run


def test_blocking_call_returns_full_output_in_one_call(monkeypatch):
    # kali_run es BLOQUEANTE: llama run_shell SINCRONAMENTE (con un execution_id uuid) y
    # obtiene el dict terminal con la salida completa del ring en UNA sola llamada.
    runner = _fake_runner(returncode=0, lines=[("stdout", "line-1"), ("stdout", "line-2")])
    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", runner)

    result = shell_exec.run_shell("nmap -sV localhost", uuid.uuid4().hex, 600)
    assert result["status"] == "done"
    assert result["returncode"] == 0
    assert "line-1" in result["output"]
    assert "line-2" in result["output"]


@pytest.mark.parametrize("bad", ["", "   ", None, 123])
def test_invalid_command_fails_without_running(monkeypatch, bad):
    called = {"ran": False}

    def _should_not_run(*args, **kwargs):
        called["ran"] = True
        return (0, False, False)

    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", _should_not_run)
    result = shell_exec.run_shell(bad, uuid.uuid4().hex, 600)
    assert result["status"] == "failed"
    assert result["returncode"] == -1
    assert called["ran"] is False  # fail-closed: nothing was executed


def test_server_text_declares_kali_run_blocking_and_keeps_all_tools():
    # The server's SHAPE is validated by its TEXT (NO import: mcp<2 is not in the venv).
    source = _SERVER_PATH.read_text(encoding="utf-8")

    # (1) kali_run existe y referencia el runner compartido run_shell.
    assert "def kali_run" in source
    assert "shell_exec.run_shell" in source

    # (2) kali_run aparece listada entre las tools de server_info.
    assert "KALI_RUN_TOOL_NAME" in source
    assert 'KALI_RUN_TOOL_NAME = "kali_run"' in source

    # (3) kali_run's body is BLOCKING: it does NOT CALL start_background (the mention
    # en el docstring explica justo que NO lo usa, por eso se busca la LLAMADA concreta).
    body_start = source.index("def kali_run")
    body = source[body_start : source.index("def _start_artifacts_http")]
    assert "tool_streaming.start_background(" not in body
    assert "shell_exec.run_shell" in body

    # (4) server_info STILL lists the existing tools (none was removed).
    for name in (
        "PROWLER_TOOL_NAME",
        "START_COLLECTION_TOOL_NAME",
        "IAM_ENUM_TOOL_NAME",
        "IAM_SIMULATE_TOOL_NAME",
        "KALI_EXEC_TOOL_NAME",
    ):
        assert name in source


def test_server_text_wires_scope_guard_into_runners():
    # Validated by TEXT (NO import: mcp<2 is not in the venv) that the scope-guard was
    # cableado en kali_run/kali_exec con los args nuevos y el gate ANTES de ejecutar.
    source = _SERVER_PATH.read_text(encoding="utf-8")

    # (1) The server imports the guard module (pure STDLIB) and invokes it.
    assert "import scope_guard" in source
    assert "scope_guard.evaluate" in source
    assert "scope_guard.load_scope" in source

    # (2) Ambos runners aceptan los nuevos args opcionales targets/engagement_id.
    for runner in ("def kali_run", "def kali_exec"):
        body_start = source.index(runner)
        # signature inside the function header (up to the closing parenthesis).
        header = source[body_start : source.index(")", body_start) + 1]
        assert "targets" in header
        assert "engagement_id" in header

    # (3) Ambos runners pasan por el gate ANTES de ejecutar (helper compartido).
    assert source.count("_scope_gate(command, targets, engagement_id)") == 2

    # (4) kali_run devuelve el error de scope SIN ejecutar: el gate aparece antes de
    # shell_exec.run_shell en su cuerpo.
    run_start = source.index("def kali_run")
    run_body = source[run_start : source.index("def record_finding")]
    # rindex: the real CALL to run_shell (the last mention; the first is in the docstring).
    assert run_body.index("_scope_gate(") < run_body.rindex("shell_exec.run_shell")

    # (5) kali_exec devuelve el error de scope SIN arrancar el background: el gate aparece
    # antes de start_background en su cuerpo.
    exec_start = source.index("def kali_exec")
    exec_body = source[exec_start : source.index("def kali_run")]
    # rindex: the real CALL to start_background (the last; the first is in the docstring).
    assert exec_body.index("_scope_gate(") < exec_body.rindex("tool_streaming.start_background")

    # (6) The violation is logged in the findings store (auditable evidence).
    assert 'title": "SCOPE_VIOLATION"' in source or '"SCOPE_VIOLATION"' in source
    assert "finding_store.append" in source


@pytest.fixture(autouse=True)
def _staging_kali_run(tmp_path, monkeypatch):
    """Redirects the audit log to a tmp dir (run_shell audits; must not touch /artifacts)."""
    monkeypatch.setenv("KALI_ARTIFACTS_DIR", str(tmp_path))
    return tmp_path


def test_run_shell_returns_execution_id_for_kali_run_semantics(monkeypatch):
    # kali_run devuelve TAL CUAL el dict de run_shell, que ahora SIEMPRE incluye execution_id
    # (key to cross-check with Hermes' transcript and the per-engagement audit log).
    runner = _fake_runner(returncode=0, lines=[("stdout", "x")])
    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", runner)

    eid = uuid.uuid4().hex
    result = shell_exec.run_shell("echo x", eid, 600, engagement_id="eng-1", tool_label="kali_run")
    assert result["execution_id"] == eid


def test_server_text_wires_audit_into_runners():
    # Validated by TEXT (NO import: mcp<2 is not in the venv) that both runners pass
    # engagement_id + the tool label to run_shell (durable per-engagement audit).
    source = _SERVER_PATH.read_text(encoding="utf-8")

    # (1) Ambos runners propagan engagement_id al runner compartido (>=2: kali_run y kali_exec).
    assert source.count("engagement_id=engagement_id") >= 2

    # (2) Each runner labels its execution with its own tool name.
    assert "tool_label=KALI_RUN_TOOL_NAME" in source
    assert "tool_label=KALI_EXEC_TOOL_NAME" in source

    # (3) kali_run devuelve directamente el resultado de run_shell (no lo re-envuelve ni le
    # removes the execution_id): the real call to run_shell is preceded by `return`.
    run_start = source.index("def kali_run")
    run_body = source[run_start : source.index("def record_finding")]
    assert "return shell_exec.run_shell(" in run_body
