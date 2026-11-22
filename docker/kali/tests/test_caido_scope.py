"""Tests of the scope DECISION for the target declared by ``caido_request`` (PURE STDLIB).

Ejercitan ``scope_guard`` con el MISMO destino que construye el servidor
(``caido_client.scope_target(split_target_url(url))``, ``esquema://host:puerto``). El
behavior of the full tools (that a block never sends traffic) is tested in
``test_caido_server.py``.

Regression they pin: an early version declared only the HOST to the gate; the port was lost
and a target without a port was allowed "by host", skipping scope ``ports``. It was detected in
the LIVE verification (request to :9999 with ``ports:[3000]`` reached Caido).
"""

from __future__ import annotations

import sys
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PARENT))

import caido_client  # noqa: E402
import scope_guard  # noqa: E402

_SCOPE = {
    "enabled": True,
    "allow": [{"host": "juice-shop"}],
    "deny": [],
    "ports": [3000],
}


def _config():
    return scope_guard.parse_scope(_SCOPE)


def _declared(url: str) -> str:
    # The SAME function the server uses to declare the target to the gate.
    return caido_client.scope_target(caido_client.split_target_url(url))


def _allowed(url: str) -> bool:
    d = scope_guard.evaluate(_config(), [_declared(url)], f"caido_request {url}")
    return d.allowed


def test_puerto_permitido_pasa():
    assert _allowed("http://juice-shop:3000/") is True


def test_puerto_fuera_de_ports_se_bloquea():
    # The regression: with only the host declared this used to pass.
    assert _allowed("http://juice-shop:9999/") is False


def test_host_fuera_de_allow_se_bloquea():
    assert _allowed("http://otro-host:3000/") is False


def test_el_host_solo_perderia_el_puerto():
    # Documents WHY scheme://host:port is declared: host-only is allowed "by host".
    d = scope_guard.evaluate(_config(), ["juice-shop"], "caido_request x")
    assert d.allowed is True


def _allowed_with(scope: dict, url: str) -> bool:
    cfg = scope_guard.parse_scope(scope)
    return scope_guard.evaluate(
        cfg, [_declared(url)], f"caido_request {_declared(url)}"
    ).allowed


def test_ipv6_literal_dentro_de_cidr_pasa():
    scope = {"enabled": True, "allow": [{"cidr": "::1/128"}], "deny": []}
    assert _allowed_with(scope, "http://[::1]:3000/") is True


def test_userinfo_no_engana_al_gate():
    # El destino real es attacker.example; "allowed" en el userinfo no cuenta.
    scope = {"enabled": True, "allow": [{"host": "juice-shop"}], "deny": []}
    assert _allowed_with(scope, "http://juice-shop@attacker.example:3000/") is False


def test_punto_final_y_mayusculas_no_evaden_ni_bloquean():
    scope = {"enabled": True, "allow": [{"host": "juice-shop"}], "deny": []}
    assert _allowed_with(scope, "http://JUICE-SHOP.:3000/") is True
    assert _allowed_with(scope, "http://attacker.example.:3000/") is False


def test_ip_en_query_string_no_causa_bloqueo_falso():
    scope = {"enabled": True, "allow": [{"host": "juice-shop"}], "deny": []}
    assert _allowed_with(scope, "http://juice-shop:3000/?next=10.9.9.9") is True
