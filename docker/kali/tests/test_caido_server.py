"""Tests de COMPORTAMIENTO de las tools de Caido del servidor (sin red, sin Docker, sin `mcp`).

``kali_mcp_server`` exige el SDK ``mcp<2``; aquí se importa con un STUB mínimo de
``mcp.server.fastmcp.FastMCP`` (decorador identidad), de modo que las funciones ``caido_*`` se
ejecutan de verdad y se comprueba lo que importa: con ``scope.json`` activo ``caido_request`` NO
llega a enviar tráfico, ``caido_graphql`` rechaza mutaciones de envío, y ``server_info`` expone el
estado de Caido. ``caido_client.send_request``/``graphql`` se sustituyen por espías.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

_PARENT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PARENT))

import caido_client  # noqa: E402


class _StubFastMCP:
    """Sustituto de FastMCP: ``@mcp.tool(...)``/``@mcp.tool()`` devuelven la función tal cual."""

    def __init__(self, *a, **k):
        self.tools = {}

    def tool(self, name=None, **k):
        def deco(fn):
            self.tools[name or fn.__name__] = fn
            return fn

        return deco

    def run(self, *a, **k):  # pragma: no cover - no se arranca el servidor
        raise AssertionError("el servidor no debe arrancar en tests")


@pytest.fixture()
def server(monkeypatch):
    """``kali_mcp_server`` importado con el SDK ``mcp`` sustituido por un stub (aislado)."""
    fastmcp = types.ModuleType("mcp.server.fastmcp")
    fastmcp.FastMCP = _StubFastMCP
    for name, mod in (
        ("mcp", types.ModuleType("mcp")),
        ("mcp.server", types.ModuleType("mcp.server")),
        ("mcp.server.fastmcp", fastmcp),
    ):
        monkeypatch.setitem(sys.modules, name, mod)
    spec = importlib.util.spec_from_file_location(
        "_kali_mcp_server_under_test", _PARENT / "kali_mcp_server.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    # Las violaciones de scope se loguean en /artifacts: se captura en vez de escribir a disco.
    violations = []
    monkeypatch.setattr(
        mod, "_log_scope_violation", lambda *a, **k: violations.append(a)
    )
    mod._violations = violations
    return mod


@pytest.fixture()
def scope_on(tmp_path, monkeypatch):
    f = tmp_path / "scope.json"
    f.write_text(
        json.dumps(
            {
                "enabled": True,
                "allow": [{"host": "juice-shop"}],
                "deny": [],
                "ports": [3000],
            }
        )
    )
    monkeypatch.setenv("SCOPE_FILE", str(f))
    monkeypatch.delenv("SCOPE_ENFORCE", raising=False)


@pytest.fixture()
def scope_off(tmp_path, monkeypatch):
    monkeypatch.setenv("SCOPE_FILE", str(tmp_path / "no-existe.json"))


@pytest.fixture()
def spy(monkeypatch):
    calls = {"send": [], "graphql": []}

    def fake_send(url, **kw):
        calls["send"].append((url, kw))
        return {"status": "done", "response": {"status_code": 200}}

    def fake_graphql(query, variables=None, **kw):
        calls["graphql"].append(query)
        return {"status": "ok", "data": {}}

    monkeypatch.setattr(caido_client, "send_request", fake_send)
    monkeypatch.setattr(caido_client, "graphql", fake_graphql)
    monkeypatch.setattr(
        caido_client,
        "ensure_session",
        lambda **kw: {"status": "ok", "token": "t", "project_id": "p"},
    )
    return calls


# --- caido_request ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://example.net/",  # host fuera de allow
        "http://juice-shop:9999/",  # puerto fuera de ports
        "http://juice-shop@attacker.example:3000/",  # userinfo: el destino real es attacker.example
        "http://attacker.example./",  # punto final
    ],
)
def test_caido_request_fuera_de_scope_no_envia_trafico(server, scope_on, spy, url):
    out = server.caido_request(url, engagement_id="e1")
    assert out["status"] == "failed" and out["scope_violation"] is True
    assert spy["send"] == []  # NUNCA se llamó a send_request
    assert server._violations, "la violación debe registrarse como evidencia"


def test_caido_request_en_scope_envia_y_declara_el_destino_validado(
    server, scope_on, spy
):
    out = server.caido_request(
        "http://juice-shop:3000/rest/products/search?q=a", method="GET"
    )
    assert out["status"] == "done"
    assert len(spy["send"]) == 1 and spy["send"][0][0].startswith(
        "http://juice-shop:3000/"
    )


def test_caido_request_ipv4_mapped_ipv6_no_evade_el_deny(
    server, tmp_path, monkeypatch, spy
):
    f = tmp_path / "s.json"
    f.write_text(
        json.dumps(
            {
                "enabled": True,
                "allow": [{"cidr": "0.0.0.0/0"}, {"cidr": "::/0"}],
                "deny": [{"cidr": "169.254.0.0/16"}],
            }
        )
    )
    monkeypatch.setenv("SCOPE_FILE", str(f))
    for url in (
        "http://169.254.169.254/",
        "http://[::ffff:169.254.169.254]/",
        "http://[::ffff:a9fe:a9fe]/",
    ):
        out = server.caido_request(url)
        assert out.get("scope_violation") is True, url
    assert spy["send"] == []


def test_caido_request_url_invalida_devuelve_failed_sin_lanzar(server, scope_off, spy):
    for bad in ("http://h:99999/", "http://[::1/", ""):
        assert server.caido_request(bad)["status"] == "failed"
    assert spy["send"] == []


def test_caido_request_sin_scope_pasa_a_send_request(server, scope_off, spy):
    assert server.caido_request("http://cualquiera.example/")["status"] == "done"
    assert len(spy["send"]) == 1


# --- caido_graphql ----------------------------------------------------------------------

_SEND = 'mutation{ startReplayTask(sessionId:"1"){ task{id} } }'


@pytest.mark.parametrize(
    "doc",
    [
        _SEND,
        "mutation{ sendRequest(x:1){id} }",  # nombre desconocido: lo cubren los verbos
        "mutation{ runWorkflow(id:1){ok} }",
        "mutation($i:X!){ createReplaySession(input:$i){ session{id} } }",
    ],
)
def test_caido_graphql_rechaza_mutaciones_de_envio_con_scope_activo(
    server, scope_on, spy, doc
):
    out = server.caido_graphql(doc)
    assert out["status"] == "failed" and out["scope_violation"] is True
    assert "caido_request" in out["error"]
    assert spy["graphql"] == []


def test_caido_graphql_permite_lecturas_y_mutaciones_inocuas_con_scope_activo(
    server, scope_on, spy
):
    for doc in (
        "query{ projects{ id name } }",
        "query{ x{ connectionInfo{ host } } }",  # lectura que nombra connectionInfo
        'mutation{ selectProject(id:"1"){ currentProject{ __typename } } }',
    ):
        assert server.caido_graphql(doc)["status"] == "ok", doc
    assert len(spy["graphql"]) == 3


def test_caido_graphql_sin_scope_es_passthrough_total(server, scope_off, spy):
    assert server.caido_graphql(_SEND)["status"] == "ok"
    assert spy["graphql"] == [_SEND]


def test_caido_graphql_con_scope_corrupto_falla_cerrado(
    server, tmp_path, monkeypatch, spy
):
    f = tmp_path / "roto.json"
    f.write_text("{no es json")
    monkeypatch.setenv("SCOPE_FILE", str(f))
    out = server.caido_graphql(_SEND)
    assert out["scope_violation"] is True and spy["graphql"] == []


# --- caido_history / server_info --------------------------------------------------------


def test_caido_history_delega_y_devuelve_la_forma_documentada(server, monkeypatch):
    seen = {}

    def fake_search(httpql="", limit=50, **kw):
        seen.update(httpql=httpql, limit=limit)
        return {"status": "done", "count": 1, "entries": [{"id": "1"}]}

    monkeypatch.setattr(caido_client, "search_history", fake_search)
    out = server.caido_history("resp.code.eq:401", 5)
    assert out == {"status": "done", "count": 1, "entries": [{"id": "1"}]}
    assert seen == {"httpql": "resp.code.eq:401", "limit": 5}


def test_server_info_expone_estado_de_caido_y_las_tres_tools(server, monkeypatch):
    monkeypatch.delenv("CAIDO_PAT", raising=False)
    monkeypatch.delenv("CAIDO_ACCESS_TOKEN", raising=False)
    info = server.server_info()
    assert set(info["caido"]) == {
        "url",
        "token_present",
        "guest_login",
        "proxy_capture",
    }
    assert info["caido"]["token_present"] is False
    assert isinstance(info["caido"]["guest_login"], bool)
    assert info["caido"]["proxy_capture"] is False
    assert {
        "caido_graphql",
        "caido_request",
        "caido_history",
        "caido_automate",
        "caido_intercept",
        "caido_proxy",
    } <= set(server.mcp.tools)


# --- caido_automate (scope-gated) -------------------------------------------------------


def test_caido_automate_fuera_de_scope_no_lanza_fuzz(server, scope_on, monkeypatch):
    import caido_automate

    called = []
    monkeypatch.setattr(
        caido_automate,
        "run_automate",
        lambda *a, **k: called.append(1) or {"status": "done"},
    )
    out = server.caido_automate(
        "http://example.net/?q=§", payloads=["a", "b"], engagement_id="e"
    )
    assert out["status"] == "failed" and out["scope_violation"] is True
    assert called == []  # el motor Automate nunca se invocó


def test_caido_automate_en_scope_delega_con_destino_validado(
    server, scope_on, monkeypatch
):
    import caido_automate

    seen = {}

    def fake(url, **kw):
        seen["url"] = url
        seen["payloads"] = kw.get("payloads")
        return {"status": "done", "count": 2, "results": []}

    monkeypatch.setattr(caido_automate, "run_automate", fake)
    out = server.caido_automate(
        "http://juice-shop:3000/rest/search?q=§",
        payloads=["x", "y"],
        strategy="SEQUENTIAL",
    )
    assert out["status"] == "done"
    assert seen["url"].startswith("http://juice-shop:3000/") and seen["payloads"] == [
        "x",
        "y",
    ]


def test_caido_automate_url_invalida_falla_sin_tocar_motor(
    server, scope_off, monkeypatch
):
    import caido_automate

    monkeypatch.setattr(
        caido_automate,
        "run_automate",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no")),
    )
    assert server.caido_automate("http://[::1/", payloads=["a"])["status"] == "failed"


# --- caido_intercept (dispatcher) -------------------------------------------------------


def test_caido_intercept_despacha_cada_accion(server, monkeypatch):
    import caido_intercept

    calls = []
    for name in (
        "set_intercept",
        "intercept_status",
        "list_queue",
        "get_entry_raw",
        "forward",
        "drop",
        "pause",
        "resume",
    ):
        monkeypatch.setattr(
            caido_intercept,
            name,
            (lambda n: (lambda *a, **k: calls.append(n) or {"status": "done"}))(name),
        )
    assert server.caido_intercept("set", request_enabled=True)["status"] == "done"
    assert server.caido_intercept("status")["status"] == "done"
    assert server.caido_intercept("queue", limit=5)["status"] == "done"
    assert server.caido_intercept("get", entry_id="1")["status"] == "done"
    assert (
        server.caido_intercept("forward", entry_id="1", raw="edited")["status"]
        == "done"
    )
    assert server.caido_intercept("drop", entry_id="1")["status"] == "done"
    assert server.caido_intercept("pause")["status"] == "done"
    assert server.caido_intercept("resume")["status"] == "done"
    assert calls == [
        "set_intercept",
        "intercept_status",
        "list_queue",
        "get_entry_raw",
        "forward",
        "drop",
        "pause",
        "resume",
    ]


def test_caido_intercept_accion_desconocida_y_id_faltante(server, monkeypatch):
    import caido_intercept

    monkeypatch.setattr(caido_intercept, "forward", lambda *a, **k: {"status": "done"})
    assert server.caido_intercept("nonsense")["status"] == "failed"
    # forward sin entry_id -> fail-closed sin llamar
    assert server.caido_intercept("forward")["status"] == "failed"
    assert server.caido_intercept("get")["status"] == "failed"


# --- caido_proxy ------------------------------------------------------------------------


def test_caido_proxy_enable_status_disable(server, monkeypatch):
    import caido_proxy
    import shell_exec

    monkeypatch.setattr(
        caido_proxy,
        "enable_capture",
        lambda **k: {
            "status": "done",
            "ca_path": "/x/caido.crt",
            "env": {
                "HTTP_PROXY": "http://caido:8080",
                "HTTPS_PROXY": "http://caido:8080",
            },
        },
    )
    monkeypatch.setattr(
        caido_client, "resolve_url_safe", lambda *a, **k: "http://caido:8080"
    )
    shell_exec.set_subprocess_env({})
    assert server.caido_proxy("status")["enabled"] is False
    en = server.caido_proxy("enable")
    assert en["status"] == "done"
    # el env del proxy se inyectó a los subprocesos, con NO_PROXY al host de Caido
    assert shell_exec._SUBPROCESS_ENV.get("HTTP_PROXY") == "http://caido:8080"
    assert shell_exec._SUBPROCESS_ENV.get("NO_PROXY") == "caido"
    st = server.caido_proxy("status")
    assert st["enabled"] is True and st["proxy"] == "http://caido:8080"
    assert server.caido_proxy("disable")["enabled"] is False
    assert shell_exec._SUBPROCESS_ENV == {}


def test_caido_proxy_enable_falla_no_inyecta(server, monkeypatch):
    import caido_proxy
    import shell_exec

    shell_exec.set_subprocess_env({})
    monkeypatch.setattr(
        caido_proxy,
        "enable_capture",
        lambda **k: {"status": "unreachable", "error": "down"},
    )
    out = server.caido_proxy("enable")
    assert out["status"] == "unreachable" and shell_exec._SUBPROCESS_ENV == {}
