"""Tests stdlib-only del scope-guard opt-in (`docker/kali/scope_guard.py`).

No importan `mcp`/`anyio`: sólo librería estándar + pytest (patrón de
``tests/test_finding_store.py``). Cubren los 13 casos del plan §10:

  1. scope ausente -> no gate (passthrough).
  2. ``enabled: false`` -> no gate.
  3. kill-switch ``SCOPE_ENFORCE=0`` -> no gate aunque el archivo diga enabled.
  4. target en allow CIDR -> allowed.
  5. host literal en allow -> allowed; un sufijo NO coincide.
  6. deny tiene prioridad sobre allow.
  7. puerto fuera de ``ports`` -> bloquea; sin puerto con ports definido -> permitido por host.
  8. sin ``targets`` con scope activo -> bloquea.
  9. cinturón best-effort bloquea una IP obvia no declarada; una IP en allow no basta sola.
 10. URL normalizada (http host:3000, https IP con 443 inferido).
 11. config corrupta/JSON inválido/CIDR inválido -> ScopeError.
 12. ``format_violation_message`` produce el texto esperado.
 13. logging aislado de la violación: finding_store.read recupera el SCOPE_VIOLATION.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Los módulos bajo prueba viven en docker/kali/ (el servidor MCP NO se importa: arrastra
# `mcp`/`anyio`). Se añade el padre al path explícitamente.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import finding_store  # noqa: E402
import scope_guard  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_enforce(monkeypatch):
    """Asegura que SCOPE_ENFORCE no esté puesto por el entorno del CI."""
    monkeypatch.delenv("SCOPE_ENFORCE", raising=False)


def _cfg(**over):
    """ScopeConfig enabled construido desde un dict (parse_scope, pura)."""
    data = {"enabled": True}
    data.update(over)
    return scope_guard.parse_scope(data)


# ------------------------------------------------------------------ 1. scope ausente


def test_absent_scope_file_no_gate(tmp_path, monkeypatch):
    missing = tmp_path / "nope.json"
    monkeypatch.setenv("SCOPE_FILE", str(missing))
    config = scope_guard.load_scope()
    assert config is None
    decision = scope_guard.evaluate(config, None, "nmap 10.0.0.5")
    assert decision.allowed is True
    assert decision.enforced is False


# ------------------------------------------------------------------ 2. enabled:false


def test_enabled_false_no_gate():
    config = scope_guard.parse_scope({"enabled": False, "allow": [{"cidr": "10.0.0.0/24"}]})
    assert scope_guard.is_enforcing(config) is False
    decision = scope_guard.evaluate(config, None, "nmap 8.8.8.8")
    assert decision.allowed is True
    assert decision.enforced is False


# ------------------------------------------------------------------ 3. kill-switch


def test_kill_switch_scope_enforce_zero(monkeypatch):
    monkeypatch.setenv("SCOPE_ENFORCE", "0")
    config = _cfg(allow=[{"cidr": "10.0.0.0/24"}])
    assert scope_guard.is_enforcing(config) is False
    decision = scope_guard.evaluate(config, None, "nmap 8.8.8.8")
    assert decision.allowed is True
    assert decision.enforced is False


# ------------------------------------------------------------------ 4. allow CIDR


def test_target_in_allow_cidr():
    config = _cfg(allow=[{"cidr": "10.0.0.0/24"}])
    decision = scope_guard.evaluate(config, ["10.0.0.5"], "nmap -sV 10.0.0.5")
    assert decision.allowed is True
    assert decision.enforced is True


# ------------------------------------------------------------------ 5. host literal


def test_host_literal_in_allow_and_suffix_does_not_match():
    config = _cfg(allow=[{"host": "juice-shop"}])
    ok = scope_guard.evaluate(config, ["juice-shop"], "curl juice-shop")
    assert ok.allowed is True

    bad = scope_guard.evaluate(config, ["juice-shop.evil"], "curl juice-shop.evil")
    assert bad.allowed is False  # match literal: un sufijo NO coincide


# ------------------------------------------------------------------ 6. deny prioridad


def test_deny_takes_priority_over_allow():
    config = _cfg(
        allow=[{"cidr": "10.0.0.0/24"}],
        deny=[{"cidr": "10.0.0.5/32"}],
    )
    decision = scope_guard.evaluate(config, ["10.0.0.5"], "nmap 10.0.0.5")
    assert decision.allowed is False
    assert any("deny" in v["reason"] for v in decision.violations)


def test_deny_host_priority():
    config = _cfg(allow=[{"host": "juice-shop"}], deny=[{"host": "juice-shop"}])
    decision = scope_guard.evaluate(config, ["juice-shop"], "curl juice-shop")
    assert decision.allowed is False


# ------------------------------------------------------------------ 7. ports


def test_port_outside_ports_blocks():
    config = _cfg(allow=[{"host": "juice-shop"}], ports=[3000])
    bad = scope_guard.evaluate(config, ["juice-shop:8080"], "curl juice-shop:8080")
    assert bad.allowed is False
    ok = scope_guard.evaluate(config, ["juice-shop:3000"], "curl juice-shop:3000")
    assert ok.allowed is True


def test_no_port_with_ports_defined_allowed_by_host():
    config = _cfg(allow=[{"host": "juice-shop"}], ports=[3000])
    decision = scope_guard.evaluate(config, ["juice-shop"], "nmap juice-shop")
    assert decision.allowed is True  # sin puerto, se permite por host


# ------------------------------------------------------------------ 8. sin targets


def test_no_targets_with_scope_active_blocks():
    config = _cfg(allow=[{"cidr": "10.0.0.0/24"}])
    none = scope_guard.evaluate(config, None, "nmap 10.0.0.5")
    empty = scope_guard.evaluate(config, [], "nmap 10.0.0.5")
    assert none.allowed is False
    assert empty.allowed is False
    assert any(v.get("target") is None for v in none.violations)


# ------------------------------------------------------------------ 9. cinturón extra


def test_belt_blocks_obvious_undeclared_ip():
    config = _cfg(allow=[{"cidr": "10.0.0.0/24"}])
    # targets declarados en allow, pero el comando toca una IP fuera de allow.
    decision = scope_guard.evaluate(
        config, ["10.0.0.5"], "nmap 10.0.0.5 && curl http://8.8.8.8"
    )
    assert decision.allowed is False
    assert any("8.8.8.8" == v.get("target") for v in decision.violations)


def test_belt_blocks_deny_ip_in_command():
    config = _cfg(allow=[{"cidr": "10.0.0.0/24"}], deny=[{"cidr": "10.0.0.9/32"}])
    decision = scope_guard.evaluate(config, ["10.0.0.5"], "nmap 10.0.0.5 10.0.0.9")
    assert decision.allowed is False
    assert any("10.0.0.9" == v.get("target") for v in decision.violations)


def test_belt_does_not_approve_without_targets():
    # Una IP en allow dentro del comando NO basta: sin targets declarados, se bloquea.
    config = _cfg(allow=[{"cidr": "10.0.0.0/24"}])
    decision = scope_guard.evaluate(config, None, "nmap 10.0.0.5")
    assert decision.allowed is False
    assert any(v.get("target") is None for v in decision.violations)


# ------------------------------------------------------------------ 10. URL normalizada


def test_url_normalized_http_host_port():
    config = _cfg(allow=[{"host": "juice-shop"}], ports=[3000])
    decision = scope_guard.evaluate(
        config, ["http://juice-shop:3000/rest/products"], "curl http://juice-shop:3000/rest/products"
    )
    assert decision.allowed is True


def test_url_normalized_https_ip_infers_443():
    t = scope_guard.normalize_target("https://10.0.0.5")
    assert t.host == "10.0.0.5"
    assert t.ip is not None
    assert t.port == 443
    config = _cfg(allow=[{"cidr": "10.0.0.0/24"}], ports=[443])
    decision = scope_guard.evaluate(config, ["https://10.0.0.5"], "curl https://10.0.0.5")
    assert decision.allowed is True


# ------------------------------------------------------------------ 11. config corrupta


def test_invalid_json_raises_scope_error(tmp_path, monkeypatch):
    bad = tmp_path / "scope.json"
    bad.write_text("{ not valid json", encoding="utf-8")
    monkeypatch.setenv("SCOPE_FILE", str(bad))
    with pytest.raises(scope_guard.ScopeError):
        scope_guard.load_scope()


def test_invalid_cidr_raises_scope_error():
    with pytest.raises(scope_guard.ScopeError):
        scope_guard.parse_scope({"enabled": True, "allow": [{"cidr": "no-es-cidr"}]})


def test_invalid_ports_raises_scope_error():
    with pytest.raises(scope_guard.ScopeError):
        scope_guard.parse_scope({"enabled": True, "ports": ["80"]})


def test_non_dict_root_raises_scope_error():
    with pytest.raises(scope_guard.ScopeError):
        scope_guard.parse_scope(["enabled", True])


# ------------------------------------------------------------------ 12. mensaje


def test_format_violation_message_lists_target_and_allowed():
    config = _cfg(allow=[{"cidr": "10.0.0.0/24"}, {"host": "juice-shop"}])
    decision = scope_guard.evaluate(config, ["8.8.8.8"], "nmap 8.8.8.8")
    msg = scope_guard.format_violation_message(decision, config)
    assert msg.startswith("SCOPE_VIOLATION: target 8.8.8.8 is outside allowed scope")
    assert "10.0.0.0/24" in msg
    assert "juice-shop" in msg


def test_format_violation_message_no_targets():
    config = _cfg(allow=[{"cidr": "10.0.0.0/24"}])
    decision = scope_guard.evaluate(config, None, "nmap 10.0.0.5")
    msg = scope_guard.format_violation_message(decision, config)
    assert "no 'targets' were declared" in msg


# ------------------------------------------------------------------ 13. logging aislado


def _log_violation(engagement_id, decision, config, command):
    """Réplica del logging best-effort del servidor para probarlo de forma AISLADA.

    Escribe un finding ``state="discarded"`` ``title="SCOPE_VIOLATION"`` con los targets
    rechazados + el comando + el motivo. El servidor hace exactamente esto envuelto en
    try/except; aquí se prueba que el registro es recuperable por ``finding_store.read``.
    """
    message = scope_guard.format_violation_message(decision, config)
    rejected = [v.get("target") for v in decision.violations if v.get("target") is not None]
    finding_store.append(
        engagement_id or "_scope-violations",
        {
            "title": "SCOPE_VIOLATION",
            "state": "discarded",
            "phase": "act",
            "target": ", ".join(str(t) for t in rejected),
            "evidence": {"command": command, "output": message},
        },
    )


def test_violation_logging_recoverable(tmp_path, monkeypatch):
    monkeypatch.setenv("KALI_ARTIFACTS_DIR", str(tmp_path))
    config = _cfg(allow=[{"cidr": "10.0.0.0/24"}])
    command = "nmap 8.8.8.8"
    decision = scope_guard.evaluate(config, ["8.8.8.8"], command)
    assert decision.allowed is False

    _log_violation("eng-x", decision, config, command)

    page = finding_store.read("eng-x")
    assert page["total"] == 1
    rec = page["findings"][0]
    assert rec["title"] == "SCOPE_VIOLATION"
    assert rec["state"] == "discarded"
    assert "8.8.8.8" in rec["target"]
    assert rec["evidence"]["command"] == command
