"""Tests stdlib-only del Automate de Caido (`docker/kali/caido_automate.py`).

No importan `mcp`/`anyio` ni salen a la red: cubren las funciones PURAS (localización del
punto de inyección en BYTES, builder de ajustes con su validación fail-closed, aplanado de
nodos) y el orquestador `run_automate` con el transporte `graphql` y `ensure_session`
SUSTITUIDOS por fakes con dicts guionizados. Calca la estructura de `tests/test_caido_client.py`.

El flujo end-to-end con Caido real se verificó aparte, EN VIVO (fuzz sobre OWASP Juice Shop);
aquí no se ejecuta Caido: sólo se fija la mecánica create->update->start->poll y que cada
etapa que falla devuelve su error SIN lanzar.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

# El módulo bajo prueba vive en docker/kali/ (el servidor MCP NO se importa: arrastra
# `mcp`/`anyio`). Se añade el padre al path explícitamente.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import caido_automate  # noqa: E402
import caido_client  # noqa: E402

MARKER = caido_automate.DEFAULT_MARKER  # §


# --- build_placeholder_request: offsets en BYTES ----------------------------------------


def test_placeholder_offset_es_en_bytes_no_en_caracteres():
    # Cuerpo multibyte: "José" lleva una é (2 bytes en UTF-8) ANTES del marcador, así el
    # offset en bytes del marcador difiere de su índice en caracteres.
    body = "usuario=José" + MARKER
    out = caido_automate.build_placeholder_request("POST", "/login", "h", body=body)
    assert out["start"] == out["end"]
    assert MARKER not in out["raw"]

    marked = caido_client.build_raw_request("POST", "/login", "h", body=body)
    char_idx = marked.index(MARKER)
    byte_idx = marked.encode("utf-8").index(MARKER.encode("utf-8"))
    assert out["start"] == byte_idx
    assert byte_idx != char_idx  # prueba la semántica de BYTES (é mete 1 byte extra)


def test_placeholder_reinsertar_en_offset_reproduce_la_peticion_marcada():
    body = '{"q":"ña' + MARKER + '"}'  # ñ (2 bytes) antes del marcador
    out = caido_automate.build_placeholder_request("POST", "/x", "h", body=body)
    clean = out["raw"].encode("utf-8")
    reinserted = clean[: out["start"]] + MARKER.encode("utf-8") + clean[out["start"] :]
    marked = caido_client.build_raw_request("POST", "/x", "h", body=body).encode(
        "utf-8"
    )
    assert reinserted == marked


def test_placeholder_en_path_y_en_cabecera_funciona():
    in_path = caido_automate.build_placeholder_request("GET", "/a" + MARKER + "b", "h")
    assert MARKER not in in_path["raw"] and in_path["start"] > 0
    in_header = caido_automate.build_placeholder_request(
        "GET", "/", "h", headers={"X-Fuzz": "v" + MARKER}
    )
    assert MARKER not in in_header["raw"] and in_header["start"] > 0


def test_placeholder_marcador_ausente_lanza():
    with pytest.raises(caido_client.CaidoError):
        caido_automate.build_placeholder_request("GET", "/", "h", body="sin marcador")


def test_placeholder_marcador_vacio_lanza():
    with pytest.raises(caido_client.CaidoError):
        caido_automate.build_placeholder_request("GET", "/", "h", body="x", marker="")


def test_placeholder_multiples_marcadores_usa_el_primero_sin_lanzar():
    body = "a" + MARKER + "b" + MARKER
    out = caido_automate.build_placeholder_request("POST", "/x", "h", body=body)
    marked = caido_client.build_raw_request("POST", "/x", "h", body=body)
    first_byte_idx = marked.encode("utf-8").find(MARKER.encode("utf-8"))
    assert out["start"] == first_byte_idx  # el PRIMERO, no lanza por haber dos


# --- build_automate_settings: estructura y validación -----------------------------------


def test_settings_estructura_completa():
    s = caido_automate.build_automate_settings(["a", "b"], 10, 10, workers=5, delay=2)
    assert s["payloads"] == [
        {"options": {"simpleList": {"list": ["a", "b"]}}, "preprocessors": []}
    ]
    assert s["placeholders"] == [{"start": 10, "end": 10}]
    assert s["redirect"] == {"strategy": "NEVER", "max": 0}
    assert s["strategy"] == "SEQUENTIAL"
    assert s["concurrency"] == {"workers": 5, "delay": 2}
    assert s["retryOnFailure"] == {"maximumRetries": 0, "backoff": 0}
    assert s["closeConnection"] is True
    assert s["updateContentLength"] is True
    assert s["extractors"] == []


@pytest.mark.parametrize("strat", ["ALL", "SEQUENTIAL", "PARALLEL", "MATRIX"])
def test_settings_acepta_estrategias_validas(strat):
    s = caido_automate.build_automate_settings(["a"], 0, 0, strategy=strat)
    assert s["strategy"] == strat


def test_settings_normaliza_estrategia_en_minusculas():
    s = caido_automate.build_automate_settings(["a"], 0, 0, strategy="sequential")
    assert s["strategy"] == "SEQUENTIAL"


def test_settings_estrategia_invalida_lanza():
    with pytest.raises(caido_client.CaidoError):
        caido_automate.build_automate_settings(["a"], 0, 0, strategy="BOGUS")


def test_settings_payloads_vacios_lanza():
    with pytest.raises(caido_client.CaidoError):
        caido_automate.build_automate_settings([], 0, 0)


@pytest.mark.parametrize("bad_workers", [0, -1, "x"])
def test_settings_workers_invalido_lanza(bad_workers):
    with pytest.raises(caido_client.CaidoError):
        caido_automate.build_automate_settings(["a"], 0, 0, workers=bad_workers)


def test_settings_delay_negativo_lanza():
    with pytest.raises(caido_client.CaidoError):
        caido_automate.build_automate_settings(["a"], 0, 0, delay=-1)


# --- parse_entry_requests: aplanado y dato no confiable ---------------------------------


def _payload_node(word: str) -> dict:
    """Nodo con payload inyectado (base64) y respuesta real, como lo da Caido 0.59.0."""
    return {
        "sequenceId": "1",
        "payloads": [{"raw": base64.b64encode(word.encode()).decode(), "position": 0}],
        "error": None,
        "request": {
            "id": "r1",
            "response": {"statusCode": 200, "length": 1976, "roundtripTime": 12},
        },
    }


def test_parse_decodifica_payloads_y_mapea_respuesta():
    out = caido_automate.parse_entry_requests([_payload_node("apple")])
    assert out == [
        {
            "payloads": ["apple"],
            "status_code": 200,
            "length": 1976,
            "roundtrip_ms": 12,
            "error": None,
            "request_id": "r1",
        }
    ]


def test_parse_fila_con_respuesta_null_es_error_row():
    node = {
        "sequenceId": "2",
        "payloads": [{"raw": base64.b64encode(b"bad").decode(), "position": 0}],
        "error": "connection refused",
        "request": {"id": "r2", "response": None},  # respuesta null: fila de error
    }
    out = caido_automate.parse_entry_requests([node])
    assert out == [
        {
            "payloads": ["bad"],
            "status_code": None,
            "length": None,
            "roundtrip_ms": None,
            "error": "connection refused",
            "request_id": "r2",
        }
    ]


def test_parse_lista_vacia_y_none():
    assert caido_automate.parse_entry_requests([]) == []
    assert caido_automate.parse_entry_requests(None) == []


# --- run_automate: orquestación create->update->start->poll (transporte simulado) --------


@pytest.fixture(autouse=True)
def _poll_instantaneo(monkeypatch):
    """Sin esperas reales entre sondeos."""
    monkeypatch.setattr(caido_automate, "AUTOMATE_POLL_INTERVAL_S", 0)
    yield


def _ok_session(monkeypatch):
    monkeypatch.setattr(
        caido_automate,
        "ensure_session",
        lambda **kw: {"status": "ok", "token": "t", "project_id": "p"},
    )


def _fake_graphql(responses):
    """Sustituto de ``graphql`` que responde según un substring del documento enviado.

    ``responses`` puede mapear un needle a un dict fijo o a un iterador (para guionizar
    sondeos sucesivos de la misma query).
    """
    calls = []

    def fake(query, variables=None, **kw):
        calls.append((query, variables, kw.get("token")))
        for needle, resp in responses.items():
            if needle in query:
                if hasattr(resp, "__next__"):
                    return next(resp)
                return resp
        raise AssertionError("query inesperada: " + query[:70])

    fake.calls = calls
    return fake


def _create_ok():
    return {
        "status": "ok",
        "data": {"createAutomateSession": {"session": {"id": "s1", "entries": []}}},
    }


def _update_ok():
    return {
        "status": "ok",
        "data": {"updateAutomateSession": {"session": {"id": "s1"}, "error": None}},
    }


def _start_ok():
    return {
        "status": "ok",
        "data": {
            "startAutomateTask": {
                "automateTask": {"id": "task1", "entry": {"id": "e1"}}
            }
        },
    }


def _entry_payload(nodes, count):
    return {
        "status": "ok",
        "data": {
            "automateEntry": {
                "requestsByOffset": {
                    "count": {"value": count},
                    "edges": [{"node": n} for n in nodes],
                }
            }
        },
    }


def test_run_automate_flujo_completo_create_update_start_poll(monkeypatch):
    _ok_session(monkeypatch)
    nodes = [_payload_node("apple"), _payload_node("banana")]
    fake = _fake_graphql(
        {
            "createAutomateSession": _create_ok(),
            "updateAutomateSession": _update_ok(),
            "startAutomateTask": _start_ok(),
            # SEQUENTIAL con 2 payloads: cuenta alcanza 2 en el primer sondeo -> termina.
            "automateEntry": _entry_payload(nodes, 2),
        }
    )
    monkeypatch.setattr(caido_automate, "graphql", fake)
    out = caido_automate.run_automate(
        "http://juice-shop:3000/rest/products/search?q=" + MARKER,
        payloads=["apple", "banana"],
    )
    assert out["status"] == "done"
    assert out["session_id"] == "s1"
    assert out["entry_id"] == "e1"  # AUTORITATIVO: de automateTask.entry.id
    assert out["count"] == 2
    assert out["results"][0]["payloads"] == ["apple"]
    assert out["results"][0]["status_code"] == 200
    assert out["results"][1]["payloads"] == ["banana"]
    # Secuencia correcta de etapas.
    docs = [c[0] for c in fake.calls]
    assert "createAutomateSession" in docs[0]
    assert "updateAutomateSession" in docs[1]
    assert "startAutomateTask" in docs[2]
    assert "automateEntry" in docs[3]
    # El token de sesión se propaga a cada llamada.
    assert all(c[2] == "t" for c in fake.calls)


def test_run_automate_sondea_hasta_que_la_cuenta_deja_de_crecer(monkeypatch):
    _ok_session(monkeypatch)
    one = [_payload_node("apple")]
    # PARALLEL => expected=None: termina al estabilizarse la cuenta en 2 lecturas (1 y 1).
    entry_seq = iter([_entry_payload(one, 1), _entry_payload(one, 1)])
    fake = _fake_graphql(
        {
            "createAutomateSession": _create_ok(),
            "updateAutomateSession": _update_ok(),
            "startAutomateTask": _start_ok(),
            "automateEntry": entry_seq,
        }
    )
    monkeypatch.setattr(caido_automate, "graphql", fake)
    out = caido_automate.run_automate(
        "http://h:3000/?q=" + MARKER, payloads=["apple"], strategy="PARALLEL"
    )
    assert out["status"] == "done" and out["count"] == 1
    # Exactamente 2 sondeos a automateEntry (se estabilizó en el segundo).
    assert sum(1 for c in fake.calls if "automateEntry" in c[0]) == 2


def test_run_automate_url_invalida_no_llama_a_caido(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no debe llamar a Caido")

    monkeypatch.setattr(caido_automate, "graphql", boom)
    monkeypatch.setattr(caido_automate, "ensure_session", boom)
    out = caido_automate.run_automate("", payloads=["a"])
    assert out["status"] == "failed"


def test_run_automate_sin_marcador_no_llama_a_caido(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no debe llamar a Caido")

    monkeypatch.setattr(caido_automate, "graphql", boom)
    monkeypatch.setattr(caido_automate, "ensure_session", boom)
    # La URL no lleva § en ningún sitio -> build_placeholder_request falla fail-closed.
    out = caido_automate.run_automate("http://h/", payloads=["a"])
    assert out["status"] == "failed"


def test_run_automate_sesion_fallida_se_devuelve_tal_cual(monkeypatch):
    monkeypatch.setattr(
        caido_automate,
        "ensure_session",
        lambda **kw: {"status": "unauthenticated", "error": "sin token"},
    )

    def boom(*a, **k):
        raise AssertionError("no debe llamar a graphql si no hay sesión")

    monkeypatch.setattr(caido_automate, "graphql", boom)
    out = caido_automate.run_automate("http://h/?q=" + MARKER, payloads=["a"])
    assert out == {"status": "unauthenticated", "error": "sin token"}


@pytest.mark.parametrize(
    "stage",
    [
        "createAutomateSession",
        "updateAutomateSession",
        "startAutomateTask",
        "automateEntry",
    ],
)
def test_run_automate_etapa_fallida_devuelve_su_error_sin_lanzar(monkeypatch, stage):
    _ok_session(monkeypatch)
    err = {"status": "graphql_error", "errors": [{"message": "boom en " + stage}]}
    responses = {
        "createAutomateSession": _create_ok(),
        "updateAutomateSession": _update_ok(),
        "startAutomateTask": _start_ok(),
        "automateEntry": _entry_payload([_payload_node("a")], 1),
    }
    responses[stage] = err  # la etapa bajo prueba devuelve graphql_error
    monkeypatch.setattr(caido_automate, "graphql", _fake_graphql(responses))
    out = caido_automate.run_automate("http://h/?q=" + MARKER, payloads=["a"])
    assert out["status"] == "graphql_error"
    assert out["errors"][0]["message"] == "boom en " + stage


def test_run_automate_create_sin_sesion_es_failed(monkeypatch):
    _ok_session(monkeypatch)
    fake = _fake_graphql(
        {
            # createAutomateSession status ok pero sin session en el payload.
            "createAutomateSession": {
                "status": "ok",
                "data": {"createAutomateSession": {"session": None}},
            },
        }
    )
    monkeypatch.setattr(caido_automate, "graphql", fake)
    out = caido_automate.run_automate("http://h/?q=" + MARKER, payloads=["a"])
    assert out["status"] == "failed"


def test_run_automate_start_sin_entry_id_es_failed(monkeypatch):
    _ok_session(monkeypatch)
    fake = _fake_graphql(
        {
            "createAutomateSession": _create_ok(),
            "updateAutomateSession": _update_ok(),
            # startAutomateTask sin entry id -> no se puede sondear.
            "startAutomateTask": {
                "status": "ok",
                "data": {
                    "startAutomateTask": {"automateTask": {"id": "t", "entry": None}}
                },
            },
        }
    )
    monkeypatch.setattr(caido_automate, "graphql", fake)
    out = caido_automate.run_automate("http://h/?q=" + MARKER, payloads=["a"])
    assert out["status"] == "failed"
