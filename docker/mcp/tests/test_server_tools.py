"""Tests de las TOOLS del servidor (`docker/mcp/vulnerator_mcp_server.py`).

A diferencia de `test_hermes_api_client`/`test_scope_fold` (SDK-free), este módulo SÍ importa
el servidor, que importa `mcp` (FastMCP). Por eso se marca con
``pytest.importorskip("mcp.server.fastmcp")``: en el host de dev sin el SDK (o con `mcp` 2.x,
que elimina `mcp.server.fastmcp`) estos tests se OMITEN; en la imagen / venv con `mcp` 1.x
instalado corren. Mirror del patrón "testear el shape de la respuesta de la tool" que piden los reviews.

Cubren el shape a NIVEL DE TOOL (lo que el cliente MCP recibe), no solo la decisión pura:
  - Fail-closed / fallo pre-evento de ``stream_run_events``: sobre DESNUDO ``{"error": {...}}``
    (NO la forma de batch), terminal para la paginación (fija review Finding "unknown-run
    stream error invites a paging spin").
  - ``terminality_error`` lleva el sobre COMPLETO ``{"error": {...}}`` (fija review Finding
    "terminality error envelope is inconsistent").
  - Las tools son ASYNC y delegan la llamada HTTP bloqueante en un hilo (fija review Finding
    "synchronous HTTP inside the async tool blocks the event loop"): se verifica que son
    corutinas y que ``_offload`` corre su argumento fuera del event loop.
"""

from __future__ import annotations

import inspect
import sys
import threading
from pathlib import Path

import anyio
import pytest

pytest.importorskip("mcp.server.fastmcp")  # sin el SDK 1.x (o con mcp 2.x) se omite el módulo

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.argv = ["vulnerator_mcp_server"]  # FastMCP no debe ver los args de pytest

import hermes_api_client as hac  # noqa: E402
import vulnerator_mcp_server as srv  # noqa: E402


class _FakeClient:
    """Doble del cliente :8642: devuelve respuestas programadas y registra llamadas."""

    def __init__(self):
        self.calls = []
        self.get_run_result = {"completed": False, "partial": True}
        self.iter_result = ([], 0, None, hac.STOP_DRAINED)

    def get_run(self, run_id):
        self.calls.append(("get_run", run_id, threading.get_ident()))
        return self.get_run_result

    async def iter_events(self, run_id, *, after_seq=0, max_events=None, wait_seconds=None):
        self.calls.append(("iter_events", run_id, after_seq))
        return self.iter_result


@pytest.fixture()
def fake_client(monkeypatch):
    fc = _FakeClient()
    monkeypatch.setattr(srv, "_client", fc)
    return fc


# ------------------------------------------------------------------ las tools son async


def test_all_run_tools_are_async():
    # El SDK mcp 1.x corre el cuerpo de una tool SÍNCRONA inline en el event loop; por eso
    # TODAS las tools deben ser corutinas (y delegar lo bloqueante a un hilo).
    for name in ("start_pentest", "get_run_status", "stream_run_events", "steer_run",
                 "stop_run", "health"):
        fn = getattr(srv, name)
        assert inspect.iscoroutinefunction(fn), "%s debe ser async" % name


def test_offload_runs_off_the_event_loop():
    # _offload debe ejecutar su función en OTRO hilo (no el del event loop), para no bloquearlo.
    loop_thread = {}

    async def _check():
        loop_thread["main"] = threading.get_ident()
        return await srv._offload(lambda: threading.get_ident())

    worker_thread = anyio.run(_check)
    assert worker_thread != loop_thread["main"]


# ------------------------------------------------------------------ stream_run_events: shapes


def test_stream_pre_event_error_returns_bare_envelope(fake_client):
    # Fallo pre-evento (run_not_found): sobre DESNUDO, NO la forma de batch -> terminal para
    # la paginación (un cliente que itere sobre `done` no reintenta en bucle).
    envelope = {"error": {"message": "Run not found: run_x", "type": "invalid_request_error",
                          "param": None, "code": "run_not_found"}}
    fake_client.iter_result = ([], 0, envelope, "error")
    out = anyio.run(lambda: srv.stream_run_events("run_x", 0))
    assert out == envelope
    assert "done" not in out and "events" not in out  # NO es la forma de batch


def test_stream_partial_events_then_error_wraps_under_stream_error(fake_client):
    # Si YA llegaron eventos parciales antes del fallo, se preservan + sobre COMPLETO bajo
    # stream_error, con done=False.
    partial = [{"event": "message.delta", "seq": 1, "run_id": "run_x"}]
    envelope = {"error": {"message": "boom", "type": "upstream_unreachable",
                          "param": None, "code": "upstream_unreachable"}}
    fake_client.iter_result = (partial, 1, envelope, "error")
    out = anyio.run(lambda: srv.stream_run_events("run_x", 0))
    assert out["events"] == partial
    assert out["next_cursor"] == 1
    assert out["done"] is False
    assert out["stream_error"] == envelope  # sobre COMPLETO, no solo el interior


def test_stream_terminality_error_carries_full_envelope(fake_client):
    # Fija review Finding "terminality error envelope is inconsistent": si la confirmación
    # get_run (tras un drenado) falla, terminality_error lleva el sobre COMPLETO {"error":...},
    # no solo el objeto interior.
    confirm_envelope = {"error": {"message": "cannot reach Hermes", "type": "upstream_unreachable",
                                  "param": None, "code": "upstream_unreachable"}}
    fake_client.iter_result = ([], 0, None, hac.STOP_DRAINED)  # drenado sin evento terminal
    fake_client.get_run_result = confirm_envelope
    out = anyio.run(lambda: srv.stream_run_events("run_x", 0))
    assert out["done"] is False
    assert out["terminality_error"] == confirm_envelope  # {"error": {...}} COMPLETO
    assert "error" in out["terminality_error"]


def test_stream_terminal_confirm_offloads_get_run(fake_client):
    # El get_run de confirmación corre en un hilo worker (no en el event loop).
    loop_thread = {}

    async def _run():
        loop_thread["main"] = threading.get_ident()
        return await srv.stream_run_events("run_x", 0)

    fake_client.iter_result = ([], 0, None, hac.STOP_DRAINED)
    fake_client.get_run_result = {"completed": True}
    out = anyio.run(_run)
    assert out["done"] is True
    getrun_calls = [c for c in fake_client.calls if c[0] == "get_run"]
    assert getrun_calls, "se esperaba una confirmación get_run tras el drenado"
    assert getrun_calls[0][2] != loop_thread["main"]  # corrió fuera del event loop


def test_stream_oversized_event_returns_bare_envelope_terminal_for_paging(fake_client):
    # Fija los blocking de la revisión 4 a NIVEL de tool: un evento SOBREDIMENSIONADO que
    # iter_events señala como sobre de error con events=[] se devuelve DESNUDO (NO la forma de
    # batch), terminal para la paginación. Así nunca aparece un run.completed con done:false ni
    # se pierde el payload silenciosamente dentro de events.
    oversized_env = {"error": {
        "message": "a single SSE event (seq=9, type=run.completed) ... exceeded the ceiling",
        "type": "oversized_event", "param": None, "code": "oversized_event",
        "oversized_event": {"seq": 9, "event": "run.completed",
                            "serialized_bytes": 999_999, "limit_bytes": 524_288},
    }}
    # El cliente NO avanza el cursor (next_cursor == after_seq) y marca stop_reason "error".
    fake_client.iter_result = ([], 0, oversized_env, "error")
    out = anyio.run(lambda: srv.stream_run_events("run_x", 0))
    assert out == oversized_env            # sobre DESNUDO verbatim
    assert "done" not in out and "events" not in out  # NO es la forma de batch
    assert out["error"]["code"] == "oversized_event"
    # El cliente NO confirma terminalidad a partir de un error pre-evento.
    assert not [c for c in fake_client.calls if c[0] == "get_run"]


def test_stream_cap_batch_is_not_done_and_skips_confirm(fake_client):
    # Un batch cortado por tope (STOP_CAP) nunca confirma ni declara done.
    events = [{"event": "message.delta", "seq": 1, "run_id": "run_x"}]
    fake_client.iter_result = (events, 1, None, hac.STOP_CAP)
    out = anyio.run(lambda: srv.stream_run_events("run_x", 0))
    assert out["done"] is False
    assert out["events"] == events and out["next_cursor"] == 1
    assert not [c for c in fake_client.calls if c[0] == "get_run"]  # NO confirmó
