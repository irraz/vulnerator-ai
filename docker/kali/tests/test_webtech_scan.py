"""Tests stdlib-only del fingerprinting web por cruce (`webtech_scan.py`).

Ejercitan los PARSERS puros y el CRUCE contra fixtures SINTÉTICOS (example.com) con la
forma real de cada herramienta: whatweb (``--log-json``), webanalyze (``-output json``) y
wpscan (``--format json``, tanto "no es WordPress" como WordPress detectado). Fijan que:
  - ``parse_whatweb`` extrae plugins+versiones del array ``--log-json``;
  - ``parse_webanalyze`` extrae app_name/version/categorías del ``-output json``;
  - ``parse_wpscan`` distingue "no es WordPress" (``scan_aborted``) de WP detectado
    (core+plugins+tema con versión) y normaliza a ``techs``;
  - ``cross_reference`` fusiona por nombre, agrega versiones por fuente, y marca
    ``version_conflict`` cuando dos fuentes discrepan y acuerdo cuando coinciden;
  - ``run_webtech`` falla fail-closed con URL inválida y omite (no finge) una herramienta
    ausente.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import webtech_scan as wt  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _read(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


# --------------------------------------------------------------- parsers


def test_parse_whatweb_fixture():
    techs = wt.parse_whatweb(_read("whatweb_example.json"))
    names = {t["name"] for t in techs}
    assert "HTTPServer" in names and "MetaGenerator" in names
    assert all(t["source"] == "whatweb" for t in techs)
    # El fixture trae plugins versionados (jQuery/PHP): su versión se extrae.
    by_name = {t["name"]: t["version"] for t in techs}
    assert by_name.get("jQuery") == "3.6.0"


def test_parse_whatweb_versiones():
    raw = '[{"plugins": {"jQuery": {"version": ["3.4.1"]}, "PHP": {"version": ["8.1.2"]}, "HTML5": {}}}]'
    techs = {t["name"]: t["version"] for t in wt.parse_whatweb(raw)}
    assert techs["jQuery"] == "3.4.1"
    assert techs["PHP"] == "8.1.2"
    assert techs["HTML5"] == ""  # sin versión pero presente


def test_parse_whatweb_json_roto():
    assert wt.parse_whatweb("no json") == []
    assert wt.parse_whatweb("") == []


def test_parse_webanalyze_fixture():
    techs = wt.parse_webanalyze(_read("webanalyze_example.json"))
    names = {t["name"] for t in techs}
    assert "WordPress" in names
    assert all(t["source"] == "webanalyze" for t in techs)
    # Las categorías se conservan (WordPress -> CMS) y la versión se extrae.
    wp = next(t for t in techs if t["name"] == "WordPress")
    assert wp["version"] == "6.4.8"
    assert any("CMS" in c for c in wp.get("categories", []))


def test_parse_wpscan_no_es_wordpress_fixture():
    res = wt.parse_wpscan(_read("wpscan_not_wordpress.json"))
    assert res["is_wordpress"] is False
    assert (
        "WordPress" in res["aborted_reason"] or "does not seem" in res["aborted_reason"]
    )
    assert res["techs"] == []


def test_parse_wpscan_wordpress_detectado():
    res = wt.parse_wpscan(_read("wpscan_wordpress.json"))
    assert res["is_wordpress"] is True
    assert res["wp_version"] == "6.4.8"
    assert "twentytwentyfour" in res["theme"]
    slugs = {p["slug"] for p in res["plugins"]}
    assert {"contact-form-7", "revslider", "wordpress-seo"}.issubset(slugs)
    # normaliza core+plugins+tema a techs con prefijo plugin:/theme:
    tech_names = {t["name"] for t in res["techs"]}
    assert "WordPress" in tech_names
    assert "plugin:contact-form-7" in tech_names
    cf7 = next(t for t in res["techs"] if t["name"] == "plugin:contact-form-7")
    assert cf7["version"] == "5.9.3"


# --------------------------------------------------------------- cruce de versiones


def test_cross_reference_acuerdo():
    # Dos fuentes ven jQuery con la MISMA versión: sin conflicto, best = esa versión.
    a = [{"name": "jQuery", "version": "3.4.1", "source": "whatweb"}]
    b = [{"name": "jquery", "version": "3.4.1", "source": "webanalyze"}]
    out = wt.cross_reference(a, b)
    jq = next(t for t in out["technologies"] if t["name"].lower() == "jquery")
    assert jq["version_conflict"] is False
    assert jq["best_version"] == "3.4.1"
    assert set(jq["sources"]) == {"whatweb", "webanalyze"}
    assert out["conflicts"] == []


def test_cross_reference_conflicto():
    # Dos fuentes discrepan en la versión de jQuery: se marca conflicto y se listan ambas.
    a = [{"name": "jQuery", "version": "3.4.1", "source": "whatweb"}]
    b = [{"name": "jQuery", "version": "3.5.0", "source": "webanalyze"}]
    out = wt.cross_reference(a, b)
    jq = next(t for t in out["technologies"] if t["name"].lower() == "jquery")
    assert jq["version_conflict"] is True
    assert set(out["conflicts"][0]["versions"]) == {"3.4.1", "3.5.0"}


def test_cross_reference_orden_por_num_fuentes():
    # La tech vista por más fuentes va primero.
    a = [{"name": "WordPress", "version": "6.4.8", "source": "whatweb"}]
    b = [{"name": "WordPress", "version": "6.4.8", "source": "wpscan"}]
    c = [{"name": "Nginx", "version": "1.25.3", "source": "whatweb"}]
    out = wt.cross_reference(a, b, c)
    assert out["technologies"][0]["name"] == "WordPress"  # 2 fuentes > 1


def test_cross_reference_tres_fuentes():
    ww = wt.parse_whatweb(_read("whatweb_example.json"))
    wa = wt.parse_webanalyze(_read("webanalyze_example.json"))
    wp = wt.parse_wpscan(_read("wpscan_not_wordpress.json"))["techs"]
    out = wt.cross_reference(ww, wa, wp)
    assert "whatweb" in out["sources"] and "webanalyze" in out["sources"]
    assert len(out["technologies"]) > 0
    # whatweb y webanalyze comparten el nombre "jQuery" con la misma versión -> se fusiona
    # en una sola entrada vista por dos fuentes, sin conflicto.
    jq = next(t for t in out["technologies"] if t["name"].lower() == "jquery")
    assert set(jq["sources"]) == {"whatweb", "webanalyze"}
    assert jq["version_conflict"] is False
    assert jq["best_version"] == "3.6.0"


# --------------------------------------------------------------- orquestador


def test_run_webtech_url_invalida():
    out = wt.run_webtech("")
    assert out["status"] == "failed"


def test_run_webtech_sin_binarios(monkeypatch):
    # Si ninguna herramienta está disponible, falla claro (no finge).
    monkeypatch.setattr(wt, "_which", lambda b: None)
    out = wt.run_webtech("https://example.com")
    assert out["status"] == "failed"
    assert set(out["skipped"]) >= {"whatweb", "webanalyze"}


def test_run_webtech_normaliza_url(monkeypatch):
    # Sin esquema -> se asume https; con ninguna tool disponible seguimos validando la URL.
    monkeypatch.setattr(wt, "_which", lambda b: None)
    out = wt.run_webtech("example.com")
    assert out["url"] == "https://example.com"
