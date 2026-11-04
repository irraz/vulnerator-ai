"""Tests stdlib-only de la interceptación de Caido (`docker/kali/caido_intercept.py`).

No importan `mcp`/`anyio` ni salen a la red: cubren las funciones PURAS (builder del
`InterceptOptionsInput`, aplanado de la cola, acotado de `limit`) y los orquestadores con
`graphql`/`ensure_session` SIMULADOS (monkeypatch sobre `caido_intercept.*`), nunca contra
un Caido real. El patrón calca `tests/test_caido_client.py`.

El flujo end-to-end contra un Caido real se valida APARTE, en vivo; aquí NO se finge
verificación en vivo: sólo se comprueba que los documentos se construyen/envían como se
espera y que cualquier etapa fallida se propaga sin lanzar.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

# El módulo bajo prueba vive en docker/kali/ (el servidor MCP NO se importa: arrastra
# `mcp`/`anyio`). Se añade el padre al path explícitamente, igual que test_caido_client.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import caido_intercept  # noqa: E402

# --- utilidades de simulación (sin red) -------------------------------------------------


def _ok_session(**kw):
    """`ensure_session` falso: sesión lista con token 't'."""
    return {"status": "ok", "token": "t", "project_id": "p"}


def _fake_graphql(responses):
    """Sustituto de `graphql` que responde según un substring del documento enviado.

    Registra cada llamada como ``(query, variables, token)`` en ``fake.calls``.
    """
    calls = []

    def fake(query, variables=None, **kw):
        calls.append((query, variables, kw.get("token")))
        for needle, resp in responses.items():
            if needle in query:
                return resp
        raise AssertionError("query inesperada: " + query[:80])

    fake.calls = calls
    return fake


def _b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


# --- build_options_input (PURA) --------------------------------------------------------


def test_build_options_input_filtros_vacios_son_none():
    out = caido_intercept.build_options_input(True, False)
    assert out["request"] == {"enabled": True, "filter": None}
    assert out["response"] == {"enabled": False, "filter": None}
    assert out["streamWs"] == {"enabled": False}


def test_build_options_input_filtro_no_vacio_usa_httpql_code():
    out = caido_intercept.build_options_input(
        True, True, "req.host.eq:h", "resp.code.eq:500"
    )
    assert out["request"]["filter"] == {"HTTPQL": {"code": "req.host.eq:h"}}
    assert out["response"]["filter"] == {"HTTPQL": {"code": "resp.code.eq:500"}}
    assert out["request"]["enabled"] is True and out["response"]["enabled"] is True


def test_build_options_input_omite_scope():
    assert "scope" not in caido_intercept.build_options_input(True, True, "x")


def test_build_options_input_bool_coerce():
    out = caido_intercept.build_options_input(1, 0)
    assert out["request"]["enabled"] is True and out["response"]["enabled"] is False


# --- parse_queue_nodes (PURA) ----------------------------------------------------------


def test_parse_queue_nodes_shape_y_renombra_is_tls():
    node = {
        "id": "42",
        "request": {
            "id": "7",
            "method": "POST",
            "host": "example.com",
            "port": 8443,
            "path": "/login",
            "isTls": True,
            "length": 123,
            "createdAt": "2026-01-01",
        },
    }
    assert caido_intercept.parse_queue_nodes([node]) == [
        {
            "id": "42",
            "method": "POST",
            "host": "example.com",
            "port": 8443,
            "path": "/login",
            "is_tls": True,
            "length": 123,
        }
    ]


def test_parse_queue_nodes_lista_vacia_o_none():
    assert caido_intercept.parse_queue_nodes([]) == []
    assert caido_intercept.parse_queue_nodes(None) == []


def test_parse_queue_nodes_ignora_nodos_vacios_y_sin_request():
    out = caido_intercept.parse_queue_nodes([None, {"id": "1"}])
    assert out == [
        {
            "id": "1",
            "method": None,
            "host": None,
            "port": None,
            "path": None,
            "is_tls": None,
            "length": None,
        }
    ]


# --- _clamp_limit (PURA) ---------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected", [(0, 1), (-5, 1), (1, 1), (50, 50), (1000, 1000), (99999, 1000)]
)
def test_clamp_limit_acota(raw, expected):
    assert caido_intercept._clamp_limit(raw) == expected


@pytest.mark.parametrize("bad", ["no-num", None, object()])
def test_clamp_limit_basura_cae_a_50(bad):
    assert caido_intercept._clamp_limit(bad) == 50


# --- set_intercept ---------------------------------------------------------------------


def test_set_intercept_construye_opciones_correctas(monkeypatch):
    monkeypatch.setattr(caido_intercept, "ensure_session", _ok_session)
    fake = _fake_graphql(
        {
            "setInterceptOptions": {
                "status": "ok",
                "data": {"setInterceptOptions": {"__typename": "InterceptOptions"}},
            }
        }
    )
    monkeypatch.setattr(caido_intercept, "graphql", fake)
    out = caido_intercept.set_intercept(
        request_enabled=True, response_enabled=True, request_httpql="req.host.eq:h"
    )
    assert out == {"status": "done", "request_enabled": True, "response_enabled": True}
    q, variables, token = fake.calls[0]
    assert "setInterceptOptions" in q and token == "t"
    assert variables == {
        "input": caido_intercept.build_options_input(True, True, "req.host.eq:h", "")
    }
    # El filtro HTTPQL viaja en el shape QueryInput correcto.
    assert variables["input"]["request"]["filter"] == {
        "HTTPQL": {"code": "req.host.eq:h"}
    }


def test_set_intercept_sin_sesion_no_llama_graphql(monkeypatch):
    monkeypatch.setattr(
        caido_intercept,
        "ensure_session",
        lambda **kw: {"status": "unauthenticated", "error": "sin token"},
    )

    def boom(*a, **k):
        raise AssertionError("no debe llamar a graphql sin sesión")

    monkeypatch.setattr(caido_intercept, "graphql", boom)
    out = caido_intercept.set_intercept()
    assert out["status"] == "unauthenticated"


def test_set_intercept_propaga_graphql_error_sin_lanzar(monkeypatch):
    monkeypatch.setattr(caido_intercept, "ensure_session", _ok_session)
    err = {"status": "graphql_error", "errors": [{"message": "Unknown field"}]}
    monkeypatch.setattr(
        caido_intercept, "graphql", _fake_graphql({"setInterceptOptions": err})
    )
    assert caido_intercept.set_intercept() == err


# --- intercept_status ------------------------------------------------------------------


def test_intercept_status_devuelve_data_verbatim(monkeypatch):
    monkeypatch.setattr(caido_intercept, "ensure_session", _ok_session)
    data = {
        "interceptStatus": "PAUSED",
        "interceptOptions": {
            "request": {"enabled": True},
            "response": {"enabled": False},
            "streamWs": {"enabled": False},
        },
    }
    monkeypatch.setattr(
        caido_intercept,
        "graphql",
        _fake_graphql({"interceptStatus": {"status": "ok", "data": data}}),
    )
    out = caido_intercept.intercept_status()
    assert out == {"status": "done", "intercept": data}


# --- list_queue ------------------------------------------------------------------------


def test_list_queue_parsea_cuenta_y_acota_limit(monkeypatch):
    monkeypatch.setattr(caido_intercept, "ensure_session", _ok_session)
    node = {
        "id": "1",
        "request": {
            "id": "7",
            "method": "GET",
            "host": "h",
            "port": 80,
            "path": "/a",
            "isTls": False,
            "length": 10,
            "createdAt": "t",
        },
    }
    fake = _fake_graphql(
        {
            "interceptEntriesByOffset": {
                "status": "ok",
                "data": {
                    "interceptEntriesByOffset": {
                        "count": {"value": 1},
                        "edges": [{"node": node}],
                    }
                },
            }
        }
    )
    monkeypatch.setattr(caido_intercept, "graphql", fake)
    out = caido_intercept.list_queue(99999)
    assert out["status"] == "done" and out["count"] == 1
    assert out["entries"] == [
        {
            "id": "1",
            "method": "GET",
            "host": "h",
            "port": 80,
            "path": "/a",
            "is_tls": False,
            "length": 10,
        }
    ]
    # limit acotado a 1000 en las variables enviadas.
    assert fake.calls[0][1] == {"limit": 1000}


def test_list_queue_sin_sesion_devuelve_error(monkeypatch):
    monkeypatch.setattr(
        caido_intercept,
        "ensure_session",
        lambda **kw: {"status": "unreachable", "error": "caído"},
    )
    assert caido_intercept.list_queue()["status"] == "unreachable"


# --- get_entry_raw ---------------------------------------------------------------------


def test_get_entry_raw_decodifica_blob(monkeypatch):
    monkeypatch.setattr(caido_intercept, "ensure_session", _ok_session)
    raw_text = "GET / HTTP/1.1\r\nHost: h\r\n\r\n"
    monkeypatch.setattr(
        caido_intercept,
        "graphql",
        _fake_graphql(
            {
                "interceptEntry(": {
                    "status": "ok",
                    "data": {
                        "interceptEntry": {
                            "id": "42",
                            "request": {"id": "7", "raw": _b64(raw_text)},
                        }
                    },
                }
            }
        ),
    )
    out = caido_intercept.get_entry_raw("42")
    assert out == {"status": "done", "id": "42", "raw": raw_text}


# --- forward ---------------------------------------------------------------------------


def test_forward_raw_none_busca_el_raw_actual_y_lo_reenvia(monkeypatch):
    monkeypatch.setattr(caido_intercept, "ensure_session", _ok_session)
    raw_text = "GET /held HTTP/1.1\r\nHost: h\r\n\r\n"
    fake = _fake_graphql(
        {
            "interceptEntry(": {
                "status": "ok",
                "data": {
                    "interceptEntry": {
                        "id": "42",
                        "request": {"id": "7", "raw": _b64(raw_text)},
                    }
                },
            },
            "forwardInterceptMessage": {
                "status": "ok",
                "data": {"forwardInterceptMessage": {"__typename": "Payload"}},
            },
        }
    )
    monkeypatch.setattr(caido_intercept, "graphql", fake)
    out = caido_intercept.forward("42")
    assert out == {"status": "done", "forwarded": "42", "edited": False}
    # Primero relee la entrada, luego reenvía.
    assert "interceptEntry(" in fake.calls[0][0]
    fwd_query, fwd_vars, _ = fake.calls[1]
    assert "forwardInterceptMessage" in fwd_query
    # Reenvía EXACTAMENTE el raw actual (re-codificado a base64) en el lado request.
    assert fwd_vars == {
        "id": "42",
        "input": {
            "request": {"updateRaw": _b64(raw_text), "updateContentLength": True}
        },
    }


def test_forward_raw_editado_envia_base64_del_texto_editado(monkeypatch):
    monkeypatch.setattr(caido_intercept, "ensure_session", _ok_session)

    def boom(*a, **k):
        raise AssertionError("con raw editado NO debe releer la entrada")

    monkeypatch.setattr(caido_intercept, "get_entry_raw", boom)
    fake = _fake_graphql(
        {
            "forwardInterceptMessage": {
                "status": "ok",
                "data": {"forwardInterceptMessage": {"__typename": "Payload"}},
            }
        }
    )
    monkeypatch.setattr(caido_intercept, "graphql", fake)
    edited = "GET /EDITED HTTP/1.1\r\nHost: evil.example\r\n\r\n"
    out = caido_intercept.forward("9", raw=edited, update_content_length=False)
    assert out == {"status": "done", "forwarded": "9", "edited": True}
    _, variables, _ = fake.calls[0]
    assert variables["input"]["request"]["updateRaw"] == _b64(edited)
    assert variables["input"]["request"]["updateContentLength"] is False


def test_forward_is_response_usa_la_clave_response(monkeypatch):
    monkeypatch.setattr(caido_intercept, "ensure_session", _ok_session)
    fake = _fake_graphql(
        {
            "forwardInterceptMessage": {
                "status": "ok",
                "data": {"forwardInterceptMessage": {"__typename": "Payload"}},
            }
        }
    )
    monkeypatch.setattr(caido_intercept, "graphql", fake)
    caido_intercept.forward("3", raw="HTTP/1.1 200 OK\r\n\r\n", is_response=True)
    _, variables, _ = fake.calls[0]
    assert "response" in variables["input"] and "request" not in variables["input"]


def test_forward_texto_no_codificable_devuelve_failed_sin_lanzar(monkeypatch):
    monkeypatch.setattr(caido_intercept, "ensure_session", _ok_session)

    def boom(*a, **k):
        raise AssertionError("no debe llamar a graphql con texto inválido")

    monkeypatch.setattr(caido_intercept, "graphql", boom)
    out = caido_intercept.forward("1", raw="\ud800")  # surrogate suelto
    assert out["status"] == "failed"


def test_forward_propaga_error_de_la_relectura(monkeypatch):
    """Si `get_entry_raw` falla (raw=None), se devuelve ese error sin enviar nada."""
    monkeypatch.setattr(caido_intercept, "ensure_session", _ok_session)
    fake = _fake_graphql(
        {
            "interceptEntry(": {
                "status": "graphql_error",
                "errors": [{"message": "no such entry"}],
            }
        }
    )
    monkeypatch.setattr(caido_intercept, "graphql", fake)
    out = caido_intercept.forward("404")
    assert out["status"] == "graphql_error"
    # Nunca se llegó a enviar el forward.
    assert all("forwardInterceptMessage" not in c[0] for c in fake.calls)


# --- drop / pause / resume -------------------------------------------------------------


def test_drop_llama_la_mutacion_correcta(monkeypatch):
    monkeypatch.setattr(caido_intercept, "ensure_session", _ok_session)
    fake = _fake_graphql(
        {
            "dropInterceptMessage": {
                "status": "ok",
                "data": {"dropInterceptMessage": {"__typename": "Payload"}},
            }
        }
    )
    monkeypatch.setattr(caido_intercept, "graphql", fake)
    out = caido_intercept.drop("9")
    assert out == {"status": "done", "dropped": "9"}
    q, variables, _ = fake.calls[0]
    assert "dropInterceptMessage" in q and variables == {"id": "9"}


def test_pause_llama_pause_intercept(monkeypatch):
    monkeypatch.setattr(caido_intercept, "ensure_session", _ok_session)
    fake = _fake_graphql(
        {"pauseIntercept": {"status": "ok", "data": {"pauseIntercept": {}}}}
    )
    monkeypatch.setattr(caido_intercept, "graphql", fake)
    out = caido_intercept.pause()
    assert out == {"status": "done", "intercept": "paused"}
    assert "pauseIntercept" in fake.calls[0][0]


def test_resume_llama_resume_intercept(monkeypatch):
    monkeypatch.setattr(caido_intercept, "ensure_session", _ok_session)
    fake = _fake_graphql(
        {"resumeIntercept": {"status": "ok", "data": {"resumeIntercept": {}}}}
    )
    monkeypatch.setattr(caido_intercept, "graphql", fake)
    out = caido_intercept.resume()
    assert out == {"status": "done", "intercept": "resumed"}
    assert "resumeIntercept" in fake.calls[0][0]


def test_drop_sin_sesion_propaga_error(monkeypatch):
    monkeypatch.setattr(
        caido_intercept,
        "ensure_session",
        lambda **kw: {"status": "unauthenticated", "error": "sin token"},
    )

    def boom(*a, **k):
        raise AssertionError("no debe llamar a graphql sin sesión")

    monkeypatch.setattr(caido_intercept, "graphql", boom)
    assert caido_intercept.drop("1")["status"] == "unauthenticated"
