"""Tests stdlib-only del cliente de Caido (`docker/kali/caido_client.py`).

No importan `mcp`/`anyio` ni salen a la red (sólo algún test abre un socket en loopback): cubren SÓLO las funciones PURAS (builders de
payload, normalización de respuesta, parsing de URL, resolución de endpoint/token) y la
mecánica fail-closed de `graphql` cuando falta el token (ahí no hay I/O). El patrón calca
``tests/test_scope_guard.py`` / ``tests/test_finding_store.py``.

El orquestador `graphql` con red real se valida aparte, EN VIVO, contra un Caido + Juice
Shop levantados en local (la verificación end-to-end que exige "no se finge"); aquí sólo se
cubre su rama sin-token (sin red) y la clasificación de respuestas ya parseadas.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# El módulo bajo prueba vive en docker/kali/ (el servidor MCP NO se importa: arrastra
# `mcp`/`anyio`). Se añade el padre al path explícitamente.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import caido_client  # noqa: E402

# --- resolve_url / resolve_url_safe ----------------------------------------------------


def test_resolve_url_normaliza_y_quita_barra_final():
    assert caido_client.resolve_url("http://caido:8080/") == "http://caido:8080"


def test_resolve_url_anade_esquema_por_defecto():
    assert caido_client.resolve_url("caido:8080") == "http://caido:8080"


def test_resolve_url_vacia_lanza(monkeypatch):
    monkeypatch.setattr(caido_client, "DEFAULT_URL", "")
    with pytest.raises(caido_client.CaidoError):
        caido_client.resolve_url("")


def test_resolve_url_safe_no_lanza(monkeypatch):
    monkeypatch.setattr(caido_client, "DEFAULT_URL", "")
    assert caido_client.resolve_url_safe("") == ""


def test_graphql_endpoint_concatena_path():
    assert (
        caido_client.graphql_endpoint("http://caido:8080")
        == "http://caido:8080" + caido_client.GRAPHQL_PATH
    )


# --- env_token / token_present ----------------------------------------------------------


def test_env_token_prioriza_pat_sobre_access_token(monkeypatch):
    monkeypatch.setenv(caido_client.ALT_TOKEN_ENV, "access-tok")
    monkeypatch.setenv(caido_client.TOKEN_ENV, "pat-tok")
    assert caido_client.env_token() == "pat-tok"


def test_env_token_cae_a_access_token(monkeypatch):
    monkeypatch.delenv(caido_client.TOKEN_ENV, raising=False)
    monkeypatch.setenv(caido_client.ALT_TOKEN_ENV, "access-tok")
    assert caido_client.env_token() == "access-tok"


def test_token_present_falso_sin_token(monkeypatch):
    monkeypatch.delenv(caido_client.TOKEN_ENV, raising=False)
    monkeypatch.delenv(caido_client.ALT_TOKEN_ENV, raising=False)
    assert caido_client.token_present() is False


# --- ensure_session (transporte simulado; sin red) ---------------------------------------


@pytest.fixture(autouse=True)
def _limpia_sesion():
    caido_client.reset_session()
    yield
    caido_client.reset_session()


def _fake_graphql(responses):
    """Devuelve un sustituto de ``graphql`` que responde según el documento enviado."""
    calls = []

    def fake(query, variables=None, **kw):
        calls.append((query, variables, kw.get("token")))
        for needle, resp in responses.items():
            if needle in query:
                return resp
        raise AssertionError("query inesperada: " + query[:60])

    fake.calls = calls
    return fake


def test_ensure_session_invitado_crea_proyecto(monkeypatch):
    monkeypatch.delenv(caido_client.TOKEN_ENV, raising=False)
    monkeypatch.delenv(caido_client.ALT_TOKEN_ENV, raising=False)
    fake = _fake_graphql(
        {
            "loginAsGuest": {
                "status": "ok",
                "data": {"loginAsGuest": {"token": {"accessToken": "tok.guest"}}},
            },
            "projects{": {"status": "ok", "data": {"projects": []}},
            "createProject": {
                "status": "ok",
                "data": {"createProject": {"project": {"id": "p1"}}},
            },
            "selectProject": {"status": "ok", "data": {"selectProject": {}}},
        }
    )
    monkeypatch.setattr(caido_client, "graphql", fake)
    out = caido_client.ensure_session()
    assert out == {"status": "ok", "token": "tok.guest", "project_id": "p1"}


def test_ensure_session_reutiliza_proyecto_ready_y_cachea(monkeypatch):
    monkeypatch.setenv(caido_client.TOKEN_ENV, "pat")
    fake = _fake_graphql(
        {
            "projects{": {
                "status": "ok",
                "data": {"projects": [{"id": "p9", "name": "x", "status": "READY"}]},
            },
            "selectProject": {"status": "ok", "data": {"selectProject": {}}},
        }
    )
    monkeypatch.setattr(caido_client, "graphql", fake)
    first = caido_client.ensure_session()
    n_calls = len(fake.calls)
    second = caido_client.ensure_session()
    assert first["token"] == "pat" and first["project_id"] == "p9"
    assert second == first
    assert len(fake.calls) == n_calls  # segunda llamada: caché, sin red
    # No crea proyecto si ya había uno.
    assert not any("createProject" in c[0] for c in fake.calls)


def test_ensure_session_sin_token_e_invitado_desactivado(monkeypatch):
    monkeypatch.delenv(caido_client.TOKEN_ENV, raising=False)
    monkeypatch.delenv(caido_client.ALT_TOKEN_ENV, raising=False)
    monkeypatch.setattr(caido_client, "ALLOW_GUEST", False)
    out = caido_client.ensure_session()
    assert out["status"] == "unauthenticated"


def test_ensure_session_invitado_rechazado(monkeypatch):
    monkeypatch.delenv(caido_client.TOKEN_ENV, raising=False)
    monkeypatch.delenv(caido_client.ALT_TOKEN_ENV, raising=False)
    fake = _fake_graphql(
        {
            "loginAsGuest": {
                "status": "ok",
                "data": {
                    "loginAsGuest": {
                        "token": None,
                        "error": {"__typename": "PermissionDeniedUserError"},
                    }
                },
            }
        }
    )
    monkeypatch.setattr(caido_client, "graphql", fake)
    out = caido_client.ensure_session()
    assert out["status"] == "unauthenticated"
    assert "--allow-guests" in out["error"]


# --- normalize_graphql_response --------------------------------------------------------


def test_normalize_ok_sin_errores():
    out = caido_client.normalize_graphql_response({"data": {"x": 1}})
    assert out == {"status": "ok", "data": {"x": 1}}


def test_normalize_graphql_error_transporta_errores_verbatim():
    payload = {"data": None, "errors": [{"message": "Unknown field 'foo'"}]}
    out = caido_client.normalize_graphql_response(payload)
    assert out["status"] == "graphql_error"
    assert out["errors"] == payload["errors"]
    assert out["data"] is None


def test_normalize_detecta_error_de_autorizacion():
    payload = {
        "data": None,
        "errors": [
            {
                "message": "Operation error",
                "extensions": {
                    "CAIDO": {"reason": "INVALID_TOKEN", "code": "AUTHORIZATION"}
                },
            }
        ],
    }
    out = caido_client.normalize_graphql_response(payload)
    assert out["status"] == "unauthenticated"
    assert out["errors"] == payload["errors"]


# --- split_target_url ------------------------------------------------------------------


def test_split_url_https_por_defecto_sin_esquema():
    out = caido_client.split_target_url("juice-shop.local/rest/products")
    assert out == {
        "host": "juice-shop.local",
        "port": 443,
        "is_tls": True,
        "path": "/rest/products",
    }


def test_split_url_http_con_puerto_explicito():
    out = caido_client.split_target_url("http://juice-shop:3000/")
    assert out["host"] == "juice-shop"
    assert out["port"] == 3000
    assert out["is_tls"] is False
    assert out["path"] == "/"


def test_split_url_conserva_query():
    out = caido_client.split_target_url("http://h:3000/search?q=1&x=2")
    assert out["path"] == "/search?q=1&x=2"


def test_split_url_sin_host_lanza():
    with pytest.raises(caido_client.CaidoError):
        caido_client.split_target_url("http:///solo-path")


def test_split_url_vacia_lanza():
    with pytest.raises(caido_client.CaidoError):
        caido_client.split_target_url("")


# --- build_raw_request -----------------------------------------------------------------


def test_build_raw_request_get_minimo_inyecta_host_y_connection_close():
    raw = caido_client.build_raw_request("get", "/", "example.com")
    lines = raw.split("\r\n")
    assert lines[0] == "GET / HTTP/1.1"
    assert "Host: example.com" in lines
    assert "Connection: close" in lines
    assert raw.endswith("\r\n\r\n")


def test_build_raw_request_normaliza_path_sin_barra():
    raw = caido_client.build_raw_request("GET", "rest/products", "h")
    assert raw.split("\r\n")[0] == "GET /rest/products HTTP/1.1"


def test_build_raw_request_respeta_host_y_connection_explicitos():
    raw = caido_client.build_raw_request(
        "GET",
        "/",
        "ignorado",
        headers={"Host": "explicit.example", "connection": "keep-alive"},
    )
    assert "Host: explicit.example" in raw and "Host: ignorado" not in raw
    assert "connection: keep-alive" in raw and "Connection: close" not in raw


def test_build_raw_request_content_length_cuenta_bytes():
    body = '{"user":"ñ"}'
    raw = caido_client.build_raw_request("POST", "/login", "h", body=body)
    assert f"Content-Length: {len(body.encode('utf-8'))}" in raw
    assert raw.endswith("\r\n\r\n" + body)


def test_build_raw_request_respeta_content_length_explicito():
    raw = caido_client.build_raw_request(
        "POST", "/", "h", headers={"Content-Length": "0"}, body="xx"
    )
    assert raw.count("Content-Length") == 1


# --- build_replay_input ----------------------------------------------------------------


def test_build_replay_input_usa_isTLS_y_blob_base64():
    import base64

    raw = "GET / HTTP/1.1\r\nHost: h\r\n\r\n"
    out = caido_client.build_replay_input("h", 3000, False, raw)
    inp = out["i"]
    assert inp["kind"] == "HTTP"
    raw_src = inp["requestSource"]["raw"]
    assert raw_src["connectionInfo"] == {"host": "h", "port": 3000, "isTLS": False}
    assert base64.b64decode(raw_src["raw"]).decode() == raw


def test_build_replay_input_host_vacio_lanza():
    with pytest.raises(caido_client.CaidoError):
        caido_client.build_replay_input("", 80, False, "x")


@pytest.mark.parametrize("bad_port", [0, 65536, -1, "no-num"])
def test_build_replay_input_puerto_invalido_lanza(bad_port):
    with pytest.raises(caido_client.CaidoError):
        caido_client.build_replay_input("h", bad_port, False, "x")


# --- build_history_vars ----------------------------------------------------------------


def test_build_history_vars_con_filtro_usa_campo_code():
    out = caido_client.build_history_vars("resp.code.eq:200", limit=10)
    assert out["f"] == {"code": "resp.code.eq:200"}
    assert out["n"] == 10
    assert out["o"] == {"by": "ID", "ordering": "DESC"}


def test_build_history_vars_sin_filtro_es_none():
    assert caido_client.build_history_vars("", limit=5)["f"] is None


@pytest.mark.parametrize("raw_limit,expected", [(0, 1), (-5, 1), (99999, 1000)])
def test_build_history_vars_acota_limit(raw_limit, expected):
    assert caido_client.build_history_vars("", limit=raw_limit)["n"] == expected


# --- decode_blob -----------------------------------------------------------------------


def test_decode_blob_base64_y_tolerancia():
    import base64

    assert caido_client.decode_blob(base64.b64encode(b"hola").decode()) == "hola"
    assert caido_client.decode_blob(None) == ""


# --- send_request (transporte simulado) ------------------------------------------------


def test_send_request_flujo_completo_correlaciona_respuesta(monkeypatch):
    monkeypatch.setattr(caido_client, "REPLAY_POLL_INTERVAL_S", 0)
    monkeypatch.setattr(
        caido_client,
        "ensure_session",
        lambda **kw: {"status": "ok", "token": "t", "project_id": "p"},
    )
    node = {
        "id": "7",
        "method": "GET",
        "host": "juice-shop",
        "port": 3000,
        "path": "/",
        "isTls": False,
        "response": {"id": "8", "statusCode": 200, "length": 10, "roundtripTime": 5},
    }
    fake = _fake_graphql(
        {
            "createReplaySession": {
                "status": "ok",
                "data": {"createReplaySession": {"session": {"id": "s1"}}},
            },
            "startReplayTask": {
                "status": "ok",
                "data": {"startReplayTask": {"task": {"id": "1"}}},
            },
            "requests(": {
                "status": "ok",
                "data": {"requests": {"edges": [{"node": node}]}},
            },
            "request(id": {
                "status": "ok",
                "data": {
                    "request": {"response": {"raw": "SFRUUC8xLjEgMjAwIE9LDQoNCmhvbGE="}}
                },
            },
        }
    )
    # Historial realista: la consulta de línea base (1ª) lo ve vacío; el sondeo ya ve la nueva.
    history = iter(
        [
            {"status": "ok", "data": {"requests": {"edges": []}}},
            {"status": "ok", "data": {"requests": {"edges": [{"node": node}]}}},
        ]
    )
    base_fake = fake

    def fake_seq(query, variables=None, **kw):
        if "requests(" in query:
            base_fake.calls.append((query, variables, kw.get("token")))
            return next(history)
        return base_fake(query, variables, **kw)

    fake_seq.calls = base_fake.calls
    fake = fake_seq
    monkeypatch.setattr(caido_client, "graphql", fake)
    out = caido_client.send_request("http://juice-shop:3000/")
    assert out["status"] == "done"
    assert out["response"]["status_code"] == 200
    assert out["response"]["raw"].endswith("hola")  # cuerpo devuelto, no sólo el código
    assert out["response"]["raw_truncated"] is False
    # El token de sesión se propaga a cada llamada.
    assert all(c[2] == "t" for c in fake.calls)


def test_send_request_url_invalida_no_llama_a_caido(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no debe llamar a Caido")

    monkeypatch.setattr(caido_client, "graphql", boom)
    monkeypatch.setattr(caido_client, "ensure_session", boom)
    assert caido_client.send_request("")["status"] == "failed"


def test_send_request_timeout_si_la_respuesta_no_llega(monkeypatch):
    monkeypatch.setattr(caido_client, "REPLAY_POLL_INTERVAL_S", 0)
    monkeypatch.setattr(caido_client, "REPLAY_POLL_TRIES", 2)
    monkeypatch.setattr(
        caido_client,
        "ensure_session",
        lambda **kw: {"status": "ok", "token": "t", "project_id": "p"},
    )
    fake = _fake_graphql(
        {
            "createReplaySession": {
                "status": "ok",
                "data": {"createReplaySession": {"session": {"id": "s1"}}},
            },
            "startReplayTask": {
                "status": "ok",
                "data": {"startReplayTask": {"task": {"id": "1"}}},
            },
            "requests(": {"status": "ok", "data": {"requests": {"edges": []}}},
        }
    )
    monkeypatch.setattr(caido_client, "graphql", fake)
    assert caido_client.send_request("http://h:3000/x")["status"] == "timeout"


def test_search_history_devuelve_entradas(monkeypatch):
    monkeypatch.setattr(
        caido_client,
        "ensure_session",
        lambda **kw: {"status": "ok", "token": "t", "project_id": "p"},
    )
    fake = _fake_graphql(
        {
            "requests(": {
                "status": "ok",
                "data": {
                    "requests": {
                        "count": {"value": 1},
                        "edges": [{"node": {"id": "1"}}],
                    }
                },
            }
        }
    )
    monkeypatch.setattr(caido_client, "graphql", fake)
    out = caido_client.search_history("resp.code.eq:200", 5)
    assert out == {"status": "done", "count": 1, "entries": [{"id": "1"}]}


def test_send_request_ignora_respuesta_antigua_de_la_misma_url(monkeypatch):
    """Una entrada previa (id <= línea base) con respuesta NO debe confundirse con la nueva."""
    monkeypatch.setattr(caido_client, "REPLAY_POLL_INTERVAL_S", 0)
    monkeypatch.setattr(caido_client, "REPLAY_POLL_TRIES", 3)
    monkeypatch.setattr(
        caido_client,
        "ensure_session",
        lambda **kw: {"status": "ok", "token": "t", "project_id": "p"},
    )
    stale = {
        "id": "5",
        "method": "GET",
        "host": "h",
        "port": 80,
        "path": "/x",
        "isTls": False,
        "response": {"id": "5", "statusCode": 200, "length": 1, "roundtripTime": 1},
    }
    fake = _fake_graphql(
        {
            "createReplaySession": {
                "status": "ok",
                "data": {"createReplaySession": {"session": {"id": "s"}}},
            },
            "startReplayTask": {
                "status": "ok",
                "data": {"startReplayTask": {"task": {"id": "1"}}},
            },
            # El historial sólo contiene la entrada antigua (id 5) = la línea base.
            "requests(": {
                "status": "ok",
                "data": {"requests": {"edges": [{"node": stale}]}},
            },
        }
    )
    monkeypatch.setattr(caido_client, "graphql", fake)
    out = caido_client.send_request("http://h:80/x")
    assert out["status"] == "timeout"  # nunca devuelve la respuesta obsoleta


# --- renovación de sesión obsoleta (Caido recreado) -------------------------------------


def _seq_graphql(monkeypatch, script):
    """``graphql`` falso que consume ``script`` (lista de (needle, respuesta)) en orden."""
    calls = []
    it = iter(script)

    def fake(query, variables=None, **kw):
        calls.append((query, kw.get("token")))
        needle, resp = next(it)
        assert needle in query, f"esperaba {needle!r}, llegó {query[:50]!r}"
        return resp

    monkeypatch.setattr(caido_client, "graphql", fake)
    return calls


def test_search_history_renueva_sesion_obsoleta_y_reintenta_una_vez(monkeypatch):
    monkeypatch.delenv(caido_client.TOKEN_ENV, raising=False)
    monkeypatch.delenv(caido_client.ALT_TOKEN_ENV, raising=False)
    # Sesión cacheada con un token que Caido ya no reconoce.
    caido_client._SESSION.update(token="viejo", project_id="p-viejo")
    auth_err = {"status": "unauthenticated", "error": "INVALID_TOKEN"}
    calls = _seq_graphql(
        monkeypatch,
        [
            ("requests(", auth_err),  # 1ª con token viejo -> rechazo
            (
                "loginAsGuest",
                {
                    "status": "ok",
                    "data": {"loginAsGuest": {"token": {"accessToken": "nuevo"}}},
                },
            ),
            (
                "projects{",
                {
                    "status": "ok",
                    "data": {"projects": [{"id": "p2", "status": "READY"}]},
                },
            ),
            ("selectProject", {"status": "ok", "data": {"selectProject": {}}}),
            (
                "requests(",
                {
                    "status": "ok",
                    "data": {"requests": {"count": {"value": 0}, "edges": []}},
                },
            ),
        ],
    )
    out = caido_client.search_history("")
    assert out["status"] == "done"
    assert calls[0][1] == "viejo" and calls[-1][1] == "nuevo"


def test_send_request_no_reenvia_trafico_si_falla_tras_start(monkeypatch):
    """El reintento sólo cubre etapas sin efecto lateral: startReplayTask se llama UNA vez."""
    monkeypatch.setattr(caido_client, "REPLAY_POLL_INTERVAL_S", 0)
    monkeypatch.setattr(
        caido_client,
        "ensure_session",
        lambda **kw: {"status": "ok", "token": "t", "project_id": "p"},
    )
    starts = []

    def fake(query, variables=None, **kw):
        if "createReplaySession" in query:
            return {
                "status": "ok",
                "data": {"createReplaySession": {"session": {"id": "s"}}},
            }
        if "startReplayTask" in query:
            starts.append(1)
            return {"status": "graphql_error", "errors": [{"message": "boom"}]}
        return {"status": "ok", "data": {"requests": {"edges": []}}}

    monkeypatch.setattr(caido_client, "graphql", fake)
    out = caido_client.send_request("http://h:80/x")
    assert out["status"] == "graphql_error"
    assert len(starts) == 1


# --- revisión independiente: robustez y seguridad ---------------------------------------

import socket  # noqa: E402
import threading  # noqa: E402


def _raw_server(payload: bytes):
    """Servidor TCP de un solo uso que responde ``payload`` crudo y cierra. -> (puerto, hilo)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run():
        conn, _ = srv.accept()
        conn.recv(65536)
        if payload:
            conn.sendall(payload)
        conn.close()
        srv.close()

    th = threading.Thread(target=run, daemon=True)
    th.start()
    return srv.getsockname()[1], th


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"garbage not http\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nshort",
    ],
)
def test_graphql_nunca_lanza_ante_respuestas_rotas(payload):
    port, _ = _raw_server(payload)
    out = caido_client.graphql("query{x}", url=f"http://127.0.0.1:{port}", timeout=3)
    assert out["status"] in ("unreachable", "failed")


def test_graphql_nunca_lanza_con_url_invalida():
    assert caido_client.graphql("query{x}", url="http://exa mple:80")["status"] in (
        "failed",
        "unreachable",
    )


@pytest.mark.parametrize(
    "bad", ["http://h:99999/", "http://h:abc/", "http://[::1/", "http://h:+80/"]
)
def test_split_url_invalida_lanza_caido_error_no_valueerror_pelado(bad):
    with pytest.raises(caido_client.CaidoError):
        caido_client.split_target_url(bad)


def test_split_url_normaliza_punto_final_y_mayusculas():
    assert (
        caido_client.split_target_url("http://EXAMPLE.example./")["host"]
        == "example.example"
    )


@pytest.mark.parametrize(
    "val,expected",
    [
        ("0", False),
        ("no", False),
        ("off", False),
        ("FALSE", False),
        ("basura", False),
        ("1", True),
        ("true", True),
        ("", True),
    ],
)
def test_allow_guest_falla_cerrado(monkeypatch, val, expected):
    import importlib

    monkeypatch.setenv("CAIDO_ALLOW_GUEST", val)
    try:
        assert importlib.reload(caido_client).ALLOW_GUEST is expected
    finally:
        monkeypatch.delenv("CAIDO_ALLOW_GUEST", raising=False)
        importlib.reload(caido_client)


def test_env_numericos_vacios_o_basura_no_abortan_el_import(monkeypatch):
    import importlib

    monkeypatch.setenv("CAIDO_TIMEOUT", "")
    monkeypatch.setenv("CAIDO_REPLAY_POLL_TRIES", "x")
    monkeypatch.setenv("CAIDO_REPLAY_POLL_INTERVAL", "")
    try:
        mod = importlib.reload(caido_client)
        assert mod.DEFAULT_TIMEOUT_S == 60 and mod.REPLAY_POLL_TRIES == 30
    finally:
        monkeypatch.undo()
        importlib.reload(caido_client)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"method": "GET / HTTP/1.1\r\nHost: x\r\n\r\nPOST"},
        {"method": "GET", "headers": {"X": "a\r\n\r\nGET /x HTTP/1.1"}},
        {"method": "GET", "headers": {"X\r\nY": "a"}},
        {"method": "GET", "headers": {"Bad:Name": "a"}},
        {"method": "GET", "path": "/a\r\nHost: evil"},
        {"method": "GET", "path": "/a b"},
    ],
)
def test_build_raw_request_rechaza_inyeccion_crlf(kwargs):
    kwargs = {"path": "/", **kwargs}
    with pytest.raises(caido_client.CaidoError):
        caido_client.build_raw_request(host="h", **kwargs)


def test_host_header_incluye_puerto_no_estandar_y_corchetes_ipv6():
    f = caido_client.host_header_value
    assert f("h", 80, False) == "h" and f("h", 443, True) == "h"
    assert f("h", 8080, False) == "h:8080"
    assert f("::1", 3000, False) == "[::1]:3000"


def test_send_request_con_linea_base_fallida_no_envia_trafico(monkeypatch):
    monkeypatch.setattr(
        caido_client,
        "ensure_session",
        lambda **kw: {"status": "ok", "token": "t", "project_id": "p"},
    )
    started = []

    def fake(query, variables=None, **kw):
        if "createReplaySession" in query:
            return {
                "status": "ok",
                "data": {"createReplaySession": {"session": {"id": "s"}}},
            }
        if "startReplayTask" in query:
            started.append(1)
            return {"status": "ok", "data": {}}
        return {"status": "unreachable", "error": "caído"}  # la línea base falla

    monkeypatch.setattr(caido_client, "graphql", fake)
    out = caido_client.send_request("http://h:80/x")
    assert out["status"] == "failed" and not started


def test_send_request_no_acepta_respuesta_de_otro_metodo(monkeypatch):
    monkeypatch.setattr(caido_client, "REPLAY_POLL_INTERVAL_S", 0)
    monkeypatch.setattr(caido_client, "REPLAY_POLL_TRIES", 2)
    monkeypatch.setattr(
        caido_client,
        "ensure_session",
        lambda **kw: {"status": "ok", "token": "t", "project_id": "p"},
    )
    get_node = {
        "id": "9",
        "method": "GET",
        "host": "h",
        "port": 80,
        "path": "/x",
        "isTls": False,
        "response": {"id": "9", "statusCode": 200, "length": 1, "roundtripTime": 1},
    }
    seq = iter(
        [
            {"edges": []},
            {"edges": [{"node": get_node}]},
            {"edges": [{"node": get_node}]},
        ]
    )

    def fake(query, variables=None, **kw):
        if "createReplaySession" in query:
            return {
                "status": "ok",
                "data": {"createReplaySession": {"session": {"id": "s"}}},
            }
        if "startReplayTask" in query:
            return {"status": "ok", "data": {"startReplayTask": {"task": {"id": "1"}}}}
        return {"status": "ok", "data": {"requests": next(seq)}}

    monkeypatch.setattr(caido_client, "graphql", fake)
    assert (
        caido_client.send_request("http://h:80/x", method="POST")["status"] == "timeout"
    )


def test_fetch_response_raw_trunca_al_tope(monkeypatch):
    import base64

    big = base64.b64encode(b"A" * 500).decode()
    monkeypatch.setattr(
        caido_client,
        "graphql",
        lambda *a, **k: {
            "status": "ok",
            "data": {"request": {"response": {"raw": big}}},
        },
    )
    text, truncated = caido_client._fetch_response_raw("1", "t", None, 5, 100)
    assert len(text) == 100 and truncated is True


def test_reauth_no_se_dispara_con_graphql_error_legitimo(monkeypatch):
    calls = []

    def fake(query, variables=None, **kw):
        calls.append(query)
        return {
            "status": "graphql_error",
            "errors": [{"message": "HTTPQL syntax error"}],
        }

    monkeypatch.setattr(caido_client, "graphql", fake)
    monkeypatch.setattr(
        caido_client,
        "ensure_session",
        lambda **kw: (_ for _ in ()).throw(AssertionError("no debe renovar sesión")),
    )
    out, _ = caido_client._graphql_reauth("q", {}, {"token": "t"}, None, 5)
    assert out["status"] == "graphql_error" and len(calls) == 1


@pytest.mark.parametrize(
    "doc,expected",
    [
        ("mutation{ startReplayTask(sessionId:1){ task{id} } }", True),
        (
            "mutation($i:CreateReplaySessionInput!){ createReplaySession(input:$i){session{id}} }",
            True,
        ),
        ("mutation{ runActiveWorkflow(id:1){ __typename } }", True),
        ("query{ projects{ id name } }", False),
        ("query{ requests(first:1){ count{value} } }", False),
    ],
)
def test_graphql_sends_traffic(doc, expected):
    assert caido_client.graphql_sends_traffic(doc) is expected


# --- revisión final: esquema, surrogates, IPv4-mapped, filtro de mutaciones -------------


@pytest.mark.parametrize("bad", ["file:///etc/passwd", "ftp://caido:21", "gopher://x"])
def test_resolve_url_rechaza_esquemas_no_http(bad):
    with pytest.raises(caido_client.CaidoError):
        caido_client.resolve_url(bad)


def test_graphql_con_caido_url_file_devuelve_failed_sin_leer_ficheros():
    out = caido_client.graphql("query{x}", url="file:///etc/passwd")
    assert out["status"] == "failed"


@pytest.mark.parametrize("kw", [{"body": "\ud800"}, {"headers": {"X": "\ud800"}}])
def test_send_request_con_surrogate_suelto_devuelve_failed_sin_lanzar(monkeypatch, kw):
    def boom(*a, **k):
        raise AssertionError("no debe llegar a Caido")

    monkeypatch.setattr(caido_client, "graphql", boom)
    monkeypatch.setattr(caido_client, "ensure_session", boom)
    out = caido_client.send_request("http://example.com/", method="POST", **kw)
    assert out["status"] == "failed"


@pytest.mark.parametrize(
    "url",
    [
        "http://[::ffff:169.254.169.254]/",
        "http://[::ffff:a9fe:a9fe]/",
        "http://[0:0:0:0:0:ffff:a9fe:a9fe]/",
    ],
)
def test_split_url_desmapea_ipv4_mapped_a_ipv4(url):
    assert caido_client.split_target_url(url)["host"] == "169.254.169.254"


def test_split_url_ipv6_normal_se_conserva():
    assert (
        caido_client.split_target_url("http://[2001:db8::1]:8080/")["host"]
        == "2001:db8::1"
    )


def test_caido_project_vacio_usa_el_nombre_por_defecto(monkeypatch):
    import importlib

    monkeypatch.setenv("CAIDO_PROJECT", "")
    try:
        assert importlib.reload(caido_client).PROJECT_NAME == "vulnerator"
    finally:
        monkeypatch.undo()
        importlib.reload(caido_client)


@pytest.mark.parametrize(
    "doc,expected",
    [
        ("query{ requests(first:1){ count{value} } }", False),
        (
            "query{ x{ connectionInfo{ host } } }",
            False,
        ),  # lectura que nombra connectionInfo
        ("query{ automateSessions{ id } }", False),  # lectura: nunca se toca
        (
            "mutation{ sendRequest(x:1){ id } }",
            True,
        ),  # nombre desconocido: lo cubren los verbos
        ("mutation{ runWorkflow(id:1){ ok } }", True),
        ("mutation{ testPlugin(id:1){ ok } }", True),
        ("mutation{ forwardInterceptMessage(id:1){ ok } }", True),
        ('mutation{ selectProject(id:"1"){ currentProject{ __typename } } }', False),
        ("mutation{ loginAsGuest{ token{ accessToken } } }", False),
        ('mutation{ createProject(input:{name:"x"}){ project{ id } } }', False),
    ],
)
def test_graphql_sends_traffic_solo_mutaciones_con_verbos_de_envio(doc, expected):
    assert caido_client.graphql_sends_traffic(doc) is expected
