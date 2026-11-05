"""Tests stdlib-only del enrutado por proxy de Caido (`docker/kali/caido_proxy.py`).

No importan `mcp`/`anyio` ni salen a la red: cubren las funciones PURAS (endpoint del proxy,
`proxy_env`, `build_proxy_cli_args`), la rama de I/O de fichero + subprocess de `install_ca`
(apuntada a un tmpdir y a comandos reales inocuos como `true` / uno inexistente), y la ÚNICA
función con red (`fetch_ca`) con `urllib.request.urlopen` monkeypatcheado. El patrón calca
`tests/test_caido_client.py`.

El `enable_capture` de verdad (que confía la CA real y toca el trust store del sistema) se
valida aparte, EN VIVO, contra un Caido levantado en local; aquí se cubre su orquestación con
todo simulado (fetch/install/env), sin red ni escritura en el trust store del sistema.
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request
from pathlib import Path

# El módulo bajo prueba vive en docker/kali/ (el servidor MCP NO se importa: arrastra
# `mcp`/`anyio`). Se añade el padre al path explícitamente.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import caido_client  # noqa: E402
import caido_proxy  # noqa: E402

_FAKE_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBfakeCAIDOcertbase64blahblah==\n"
    "-----END CERTIFICATE-----\n"
)


# --- proxy_endpoint / proxy_env --------------------------------------------------------


def test_proxy_endpoint_mismo_host_port_que_la_api():
    assert caido_proxy.proxy_endpoint("http://caido:8080") == "http://caido:8080"


def test_proxy_endpoint_anade_esquema_y_puerto_por_defecto():
    # `resolve_url` añade http:// y, sin puerto, http => 80.
    assert caido_proxy.proxy_endpoint("caido") == "http://caido:80"


def test_proxy_endpoint_https_se_direcciona_por_http_al_proxy():
    # El VALOR del proxy es siempre http:// (el 8080 de Caido es texto plano aunque tunelice TLS).
    assert caido_proxy.proxy_endpoint("https://caido:8080") == "http://caido:8080"


def test_proxy_endpoint_ipv6_se_corchetea():
    assert caido_proxy.proxy_endpoint("http://[::1]:8080") == "http://[::1]:8080"


def test_proxy_env_deriva_las_cuatro_variables():
    out = caido_proxy.proxy_env("http://caido:8080")
    assert out["status"] == "ok"
    assert out["env"] == {
        "HTTP_PROXY": "http://caido:8080",
        "HTTPS_PROXY": "http://caido:8080",
        "http_proxy": "http://caido:8080",
        "https_proxy": "http://caido:8080",
    }


def test_proxy_env_desde_caido_url_del_entorno(monkeypatch):
    monkeypatch.setattr(caido_client, "DEFAULT_URL", "http://caido-host:8080")
    out = caido_proxy.proxy_env()  # sin arg: cae a CAIDO_URL (DEFAULT_URL)
    assert out["status"] == "ok"
    assert out["env"]["HTTPS_PROXY"] == "http://caido-host:8080"


def test_proxy_env_sin_url_falla_cerrado(monkeypatch):
    monkeypatch.setattr(caido_client, "DEFAULT_URL", "")
    out = caido_proxy.proxy_env("")
    assert out["status"] == "failed"
    assert "error" in out


def test_proxy_env_esquema_no_http_falla(monkeypatch):
    out = caido_proxy.proxy_env("ftp://caido:8080")
    assert out["status"] == "failed"


# --- build_proxy_cli_args --------------------------------------------------------------


def test_build_proxy_cli_args_devuelve_arg_proxy_server():
    assert caido_proxy.build_proxy_cli_args("http://caido:8080") == [
        "--proxy-server=http://caido:8080"
    ]


def test_build_proxy_cli_args_sin_url_devuelve_lista_vacia(monkeypatch):
    monkeypatch.setattr(caido_client, "DEFAULT_URL", "")
    assert caido_proxy.build_proxy_cli_args("") == []


# --- fetch_ca (urlopen monkeypatcheado) -------------------------------------------------


class _FakeResp:
    """Context manager mínimo que imita la respuesta de ``urlopen`` (sólo ``.read()``)."""

    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return self._body


def test_fetch_ca_ok_con_pem_valido(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["url"] = req.full_url
        return _FakeResp(_FAKE_PEM.encode("utf-8"))

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    out = caido_proxy.fetch_ca("http://caido:8080")
    assert out["status"] == "ok"
    assert "-----BEGIN CERTIFICATE-----" in out["pem"]
    assert seen["url"] == "http://caido:8080/ca.crt"  # pide el endpoint correcto


def test_fetch_ca_cuerpo_no_pem_falla(monkeypatch):
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda req, timeout=None: _FakeResp(b"<html>not a cert</html>"),
    )
    out = caido_proxy.fetch_ca("http://caido:8080")
    assert out["status"] == "failed"
    assert out["error"] == "respuesta no es un certificado PEM"


def test_fetch_ca_url_error_es_unreachable(monkeypatch):
    def boom(req, timeout=None):
        raise urllib.error.URLError("conexión rechazada")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    out = caido_proxy.fetch_ca("http://caido:8080")
    assert out["status"] == "unreachable"
    assert "error" in out


def test_fetch_ca_sin_url_falla_sin_red(monkeypatch):
    monkeypatch.setattr(caido_client, "DEFAULT_URL", "")

    def boom(*a, **k):
        raise AssertionError("no debe tocar la red sin URL")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    out = caido_proxy.fetch_ca("")
    assert out["status"] == "failed"


# --- install_ca (tmpdir + update_cmd falso) --------------------------------------------


def test_install_ca_escribe_y_actualiza_ok(tmp_path):
    dest = tmp_path / "caido.crt"
    out = caido_proxy.install_ca(_FAKE_PEM, dest=str(dest), update_cmd=("true",))
    assert out == {"status": "done", "path": str(dest)}
    assert dest.read_text() == _FAKE_PEM  # el PEM quedó escrito tal cual


def test_install_ca_crea_directorios_intermedios(tmp_path):
    dest = tmp_path / "sub" / "dir" / "caido.crt"
    out = caido_proxy.install_ca(_FAKE_PEM, dest=str(dest), update_cmd=("true",))
    assert out["status"] == "done"
    assert dest.exists()


def test_install_ca_actualizador_ausente_es_absent_sin_lanzar(tmp_path):
    dest = tmp_path / "caido.crt"
    out = caido_proxy.install_ca(
        _FAKE_PEM, dest=str(dest), update_cmd=("nonexistent-bin-xyz",)
    )
    assert out["status"] == "absent"  # no se finge: binario ausente reportado
    assert dest.read_text() == _FAKE_PEM  # la CA igualmente se escribió


def test_install_ca_actualizador_falla_returncode_es_failed(tmp_path):
    dest = tmp_path / "caido.crt"
    out = caido_proxy.install_ca(_FAKE_PEM, dest=str(dest), update_cmd=("false",))
    assert out["status"] == "failed"
    assert out["returncode"] != 0


def test_install_ca_pem_vacio_falla_sin_escribir(tmp_path):
    dest = tmp_path / "caido.crt"
    out = caido_proxy.install_ca("   ", dest=str(dest), update_cmd=("true",))
    assert out["status"] == "failed"
    assert not dest.exists()


def test_install_ca_dest_no_escribible_es_failed(tmp_path):
    # Un fichero existente usado como "directorio" en la ruta -> OSError al abrir el hijo.
    blocker = tmp_path / "blocker"
    blocker.write_text("x")
    dest = blocker / "caido.crt"
    out = caido_proxy.install_ca(_FAKE_PEM, dest=str(dest), update_cmd=("true",))
    assert out["status"] == "failed"


# --- enable_capture (orquestación con todo simulado) ------------------------------------


def test_enable_capture_happy_path(monkeypatch, tmp_path):
    dest = tmp_path / "caido.crt"
    monkeypatch.setattr(
        caido_proxy,
        "fetch_ca",
        lambda url=None, timeout=15: {"status": "ok", "pem": _FAKE_PEM},
    )
    out = caido_proxy.enable_capture(
        "http://caido:8080", dest=str(dest), update_cmd=("true",)
    )
    assert out["status"] == "done"
    assert out["ca_path"] == str(dest)
    assert out["env"]["HTTP_PROXY"] == "http://caido:8080"
    assert dest.read_text() == _FAKE_PEM


def test_enable_capture_se_detiene_si_fetch_ca_falla(monkeypatch, tmp_path):
    dest = tmp_path / "caido.crt"
    monkeypatch.setattr(
        caido_proxy,
        "fetch_ca",
        lambda url=None, timeout=15: {"status": "unreachable", "error": "caído"},
    )

    def boom(*a, **k):
        raise AssertionError("no debe instalar si fetch_ca falló")

    monkeypatch.setattr(caido_proxy, "install_ca", boom)
    out = caido_proxy.enable_capture(
        "http://caido:8080", dest=str(dest), update_cmd=("true",)
    )
    assert out["status"] == "unreachable"  # devuelve el dict de la etapa que falló
    assert not dest.exists()


def test_enable_capture_propaga_fallo_de_install(monkeypatch, tmp_path):
    dest = tmp_path / "caido.crt"
    monkeypatch.setattr(
        caido_proxy,
        "fetch_ca",
        lambda url=None, timeout=15: {"status": "ok", "pem": _FAKE_PEM},
    )
    # Actualizador ausente -> install_ca devuelve 'absent' -> enable_capture lo propaga.
    out = caido_proxy.enable_capture(
        "http://caido:8080", dest=str(dest), update_cmd=("nonexistent-bin-xyz",)
    )
    assert out["status"] == "absent"
