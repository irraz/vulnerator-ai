"""Tests stdlib-only del cliente DNSDumpster (`dnsdumpster_client.py`).

Ejercitan la LÓGICA del cliente SIN tocar la red (``_get`` se sustituye por un fake o se
monkeypatchea ``urllib.request.urlopen``). Fijan que:
  - ``_validate_domain`` normaliza (quita esquema/barras) y rechaza fail-closed la basura;
  - ``_resolve_key`` toma la key explícita o la del entorno y falla sin ella;
  - ``extract_surface`` aplana A/CNAME/MX/NS a filas (host, IP, ASN, banners), deduplica
    IPs y CIDRs y recoge TXT — comprobado contra un fixture SINTÉTICO (example.com, IPs de
    rango documentación TEST-NET) con la forma real de la API;
  - el manejo de estados HTTP: 200->ok, 429->rate_limited (con reintento), 401/403->
    unauthorized, otros->failed, cuerpo no-JSON->failed;
  - ``recon_domain`` devuelve el error de la primera página si falla, y agrega páginas.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dnsdumpster_client as dd  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


# --------------------------------------------------------------- validación de entrada


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("example.com", "example.com"),
        ("https://example.com/", "example.com"),
        ("HTTP://Example.COM", "example.com"),
        ("  example.com  ", "example.com"),
    ],
)
def test_validate_domain_normaliza(raw, expected):
    assert dd._validate_domain(raw) == expected


@pytest.mark.parametrize("bad", ["", "   ", None, 123, "a b.com", "foo.com/path"])
def test_validate_domain_rechaza(bad):
    with pytest.raises(dd.DnsDumpsterError):
        dd._validate_domain(bad)


def test_resolve_key_explicita_o_entorno(monkeypatch):
    assert dd._resolve_key("abc") == "abc"
    monkeypatch.setenv(dd.API_KEY_ENV, "fromenv")
    assert dd._resolve_key(None) == "fromenv"
    monkeypatch.delenv(dd.API_KEY_ENV, raising=False)
    with pytest.raises(dd.DnsDumpsterError):
        dd._resolve_key(None)


# --------------------------------------------------------------- normalización de salida


def test_extract_surface_fixture():
    data = _load("dnsdumpster_example.json")
    surface = dd.extract_surface(data)
    # El fixture trae hosts en A/MX/NS; se aplanan a una fila por IP.
    assert surface["counts"]["hosts"] == 5
    assert len(surface["ips"]) == len(set(surface["ips"]))  # deduplicadas
    assert all(ip for ip in surface["ips"])  # sin vacíos
    # Debe haber registros A y NS (el fixture usa ambos).
    types = surface["counts"]["by_record_type"]
    assert "A" in types and "NS" in types
    # Las filas llevan los campos normalizados esperados.
    row = surface["hosts"][0]
    assert set(["record_type", "host", "ip", "asn", "ptr", "apps"]).issubset(row)
    # TXT se recoge verbatim (el fixture publica SPF + verificación).
    assert "v=spf1 -all" in surface["txt"]


def test_extract_surface_banners_y_apps():
    data = {
        "a": [
            {
                "host": "web.example.com",
                "ips": [
                    {
                        "ip": "192.0.2.4",
                        "asn": "64500",
                        "asn_name": "EXAMPLE",
                        "asn_range": "192.0.2.0/24",
                        "country": "US",
                        "country_code": "US",
                        "ptr": "web.example.com",
                        "banners": {
                            "http": {
                                "apps": ["Nginx"],
                                "server": "nginx",
                                "title": "Home",
                            },
                            "https": {
                                "apps": ["Nginx", "PHP"],
                                "cn": "example.com",
                                "server": "nginx",
                            },
                        },
                    }
                ],
            }
        ],
        "txt": ["v=spf1 -all"],
    }
    surface = dd.extract_surface(data)
    assert surface["ips"] == ["192.0.2.4"]
    assert surface["cidrs"] == ["192.0.2.0/24"]
    row = surface["hosts"][0]
    assert row["http_server"] == "nginx"
    assert row["https_cn"] == "example.com"
    assert "PHP" in row["apps"] and "Nginx" in row["apps"]  # apps fusionadas http+https


def test_extract_surface_robusto_a_basura():
    # Secciones ausentes, tipos inesperados: no revienta, devuelve vacío coherente.
    assert dd.extract_surface({})["ips"] == []
    assert dd.extract_surface({"a": "no-es-lista"})["hosts"] == []
    assert dd.extract_surface(None)["hosts"] == []


# --------------------------------------------------------------- manejo HTTP (fake urlopen)


class _FakeResp:
    def __init__(self, body: str):
        self._body = body.encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_get_ok(monkeypatch):
    monkeypatch.setattr(dd, "_throttle", lambda: None)
    monkeypatch.setattr(
        dd.urllib.request, "urlopen", lambda req, timeout: _FakeResp('{"a":[]}')
    )
    res = dd._get("/domain/x", "k", 10)
    assert res["status"] == "ok" and res["data"] == {"a": []}


def _make_httperror(code: int, body: str):
    import urllib.error

    err = urllib.error.HTTPError("http://x", code, "err", {}, None)
    err.read = lambda: body.encode("utf-8")  # type: ignore[assignment]
    return err


def test_get_status_codes(monkeypatch):
    monkeypatch.setattr(dd, "_throttle", lambda: None)

    def raise_code(code, body=""):
        def _urlopen(req, timeout):
            raise _make_httperror(code, body)

        return _urlopen

    monkeypatch.setattr(
        dd.urllib.request, "urlopen", raise_code(429, '{"error":"Rate limit exceeded"}')
    )
    assert dd._get("/domain/x", "k", 10)["status"] == "rate_limited"

    monkeypatch.setattr(dd.urllib.request, "urlopen", raise_code(403))
    assert dd._get("/domain/x", "k", 10)["status"] == "unauthorized"

    monkeypatch.setattr(dd.urllib.request, "urlopen", raise_code(500, "boom"))
    assert dd._get("/domain/x", "k", 10)["status"] == "failed"


def test_get_cuerpo_no_json(monkeypatch):
    monkeypatch.setattr(dd, "_throttle", lambda: None)
    monkeypatch.setattr(
        dd.urllib.request,
        "urlopen",
        lambda req, timeout: _FakeResp("<html>no json</html>"),
    )
    assert dd._get("/domain/x", "k", 10)["status"] == "failed"


# --------------------------------------------------------------- recon_domain (alto nivel)


def test_recon_domain_primer_fallo_es_fatal(monkeypatch):
    monkeypatch.setattr(
        dd,
        "query_domain",
        lambda *a, **k: {"status": "unauthorized", "error": "bad key"},
    )
    out = dd.recon_domain("example.com", api_key="k")
    assert out["status"] == "unauthorized"


def test_recon_domain_ok_normaliza(monkeypatch):
    data = _load("dnsdumpster_example.json")
    monkeypatch.setattr(
        dd, "query_domain", lambda *a, **k: {"status": "ok", "data": data}
    )
    out = dd.recon_domain("example.com", api_key="k", max_pages=1)
    assert out["status"] == "done"
    assert out["domain"] == "example.com"
    assert out["surface"]["counts"]["hosts"] == 5
