"""Tests de la tool BLOQUEANTE ``kali_run`` (STDLIB PURA, SIN importar el servidor).

Restricción dura del entorno: en el venv local hay ``mcp`` 2.x pero
``kali_mcp_server.py`` exige ``mcp<2`` (FastMCP 1.x), así que ``import kali_mcp_server``
FALLA. Por eso estos tests NO importan el servidor: validan (a) la LÓGICA bloqueante vía
``shell_exec.run_shell`` (que es lo que ``kali_run`` llama SINCRONAMENTE) y (b) la forma
del servidor leyendo su TEXTO fuente (open().read() + aserciones), nunca importándolo.

Siguen el patrón de ``tests/test_shell_exec.py``: ``sys.path.insert`` del padre, import de
``shell_exec``/``tool_streaming`` y monkeypatch de ``run_tool_streaming`` con un fake que
vuelca líneas al ring.
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
    assert called["ran"] is False  # fail-closed: no se ejecutó nada


def test_server_text_declares_kali_run_blocking_and_keeps_all_tools():
    # Se valida la FORMA del servidor por su TEXTO (NO import: mcp<2 no está en el venv).
    source = _SERVER_PATH.read_text(encoding="utf-8")

    # (1) kali_run existe y referencia el runner compartido run_shell.
    assert "def kali_run" in source
    assert "shell_exec.run_shell" in source

    # (2) kali_run aparece listada entre las tools de server_info.
    assert "KALI_RUN_TOOL_NAME" in source
    assert 'KALI_RUN_TOOL_NAME = "kali_run"' in source

    # (3) El cuerpo de kali_run es BLOQUEANTE: NO LLAMA a start_background (la mención
    # en el docstring explica justo que NO lo usa, por eso se busca la LLAMADA concreta).
    body_start = source.index("def kali_run")
    body = source[body_start : source.index("def _start_artifacts_http")]
    assert "tool_streaming.start_background(" not in body
    assert "shell_exec.run_shell" in body

    # (4) server_info SIGUE listando las tools existentes (no se quitó ninguna).
    for name in (
        "PROWLER_TOOL_NAME",
        "START_COLLECTION_TOOL_NAME",
        "IAM_ENUM_TOOL_NAME",
        "IAM_SIMULATE_TOOL_NAME",
        "KALI_EXEC_TOOL_NAME",
    ):
        assert name in source


def test_server_text_wires_scope_guard_into_runners():
    # Se valida por TEXTO (NO import: mcp<2 no está en el venv) que el scope-guard quedó
    # cableado en kali_run/kali_exec con los args nuevos y el gate ANTES de ejecutar.
    source = _SERVER_PATH.read_text(encoding="utf-8")

    # (1) El servidor importa el módulo del guard (STDLIB puro) y lo invoca.
    assert "import scope_guard" in source
    assert "scope_guard.evaluate" in source
    assert "scope_guard.load_scope" in source

    # (2) Ambos runners aceptan los nuevos args opcionales targets/engagement_id.
    for runner in ("def kali_run", "def kali_exec"):
        body_start = source.index(runner)
        # firma dentro del encabezado de la función (hasta el cierre del paréntesis).
        header = source[body_start : source.index(")", body_start) + 1]
        assert "targets" in header
        assert "engagement_id" in header

    # (3) Ambos runners pasan por el gate ANTES de ejecutar (helper compartido).
    assert source.count("_scope_gate(command, targets, engagement_id)") == 2

    # (4) kali_run devuelve el error de scope SIN ejecutar: el gate aparece antes de
    # shell_exec.run_shell en su cuerpo.
    run_start = source.index("def kali_run")
    run_body = source[run_start : source.index("def record_finding")]
    # rindex: la LLAMADA real a run_shell (la última mención; la primera está en el docstring).
    assert run_body.index("_scope_gate(") < run_body.rindex("shell_exec.run_shell")

    # (5) kali_exec devuelve el error de scope SIN arrancar el background: el gate aparece
    # antes de start_background en su cuerpo.
    exec_start = source.index("def kali_exec")
    exec_body = source[exec_start : source.index("def kali_run")]
    # rindex: la LLAMADA real a start_background (la última; la primera está en el docstring).
    assert exec_body.index("_scope_gate(") < exec_body.rindex("tool_streaming.start_background")

    # (6) La violación se loguea en el store de findings (evidencia auditable).
    assert 'title": "SCOPE_VIOLATION"' in source or '"SCOPE_VIOLATION"' in source
    assert "finding_store.append" in source


@pytest.fixture(autouse=True)
def _staging_kali_run(tmp_path, monkeypatch):
    """Redirige el log de auditoría a un tmp dir (run_shell audita; no debe tocar /artifacts)."""
    monkeypatch.setenv("KALI_ARTIFACTS_DIR", str(tmp_path))
    return tmp_path


def test_run_shell_returns_execution_id_for_kali_run_semantics(monkeypatch):
    # kali_run devuelve TAL CUAL el dict de run_shell, que ahora SIEMPRE incluye execution_id
    # (clave para cruzar con el transcript de Hermes y el log de auditoría por engagement).
    runner = _fake_runner(returncode=0, lines=[("stdout", "x")])
    monkeypatch.setattr(shell_exec.tool_streaming, "run_tool_streaming", runner)

    eid = uuid.uuid4().hex
    result = shell_exec.run_shell("echo x", eid, 600, engagement_id="eng-1", tool_label="kali_run")
    assert result["execution_id"] == eid


def test_server_text_wires_audit_into_runners():
    # Se valida por TEXTO (NO import: mcp<2 no está en el venv) que ambos runners pasan
    # engagement_id + la etiqueta de tool a run_shell (auditoría durable por engagement).
    source = _SERVER_PATH.read_text(encoding="utf-8")

    # (1) Ambos runners propagan engagement_id al runner compartido (>=2: kali_run y kali_exec).
    assert source.count("engagement_id=engagement_id") >= 2

    # (2) Cada runner etiqueta su ejecución con su propio nombre de tool.
    assert "tool_label=KALI_RUN_TOOL_NAME" in source
    assert "tool_label=KALI_EXEC_TOOL_NAME" in source

    # (3) kali_run devuelve directamente el resultado de run_shell (no lo re-envuelve ni le
    # quita el execution_id): la llamada real a run_shell está precedida por `return`.
    run_start = source.index("def kali_run")
    run_body = source[run_start : source.index("def record_finding")]
    assert "return shell_exec.run_shell(" in run_body
