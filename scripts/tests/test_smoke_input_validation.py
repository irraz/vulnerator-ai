"""Tests for smoke input validation and strict suite enforcement."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
GUARD = SCRIPTS / "smoke.py"


def _load_smoke():
    spec = importlib.util.spec_from_file_location("smoke", GUARD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


smoke = _load_smoke()


def test_malformed_config_is_reported_not_raised(tmp_path, monkeypatch, capsys):
    bad = tmp_path / "config.yaml"
    bad.write_text("mcp_servers: [unclosed\n", encoding="utf-8")
    monkeypatch.setattr(smoke, "CONFIG", bad)

    report = smoke.Report()
    smoke.check_contracts(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "invalid YAML" in out


def test_non_mapping_yaml_is_reported(tmp_path, monkeypatch, capsys):
    bad = tmp_path / "config.yaml"
    bad.write_text("- just\n- a list\n", encoding="utf-8")
    monkeypatch.setattr(smoke, "CONFIG", bad)

    report = smoke.Report()
    smoke.check_contracts(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "expected a mapping" in out


def test_invalid_utf8_map_is_reported(tmp_path, monkeypatch, capsys):
    bad = tmp_path / "ARCHITECTURE_MAP.md"
    bad.write_bytes(b"\xff\xfe\x00\x01")
    monkeypatch.setattr(smoke, "MAP", bad)

    report = smoke.Report()
    smoke.check_map(report)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "cannot read" in out


def _suite_env(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    monkeypatch.setattr(smoke, "ROOT", root)
    monkeypatch.setattr(smoke, "find_uv", lambda: None)
    return root


def test_strict_mode_fails_on_missing_suite(tmp_path, monkeypatch, capsys):
    _suite_env(tmp_path, monkeypatch)
    monkeypatch.setattr(smoke, "SUITES", (("missing/tests", ["pytest"]),))

    report = smoke.Report()
    smoke.check_tests(report, strict_suites=True)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "missing suite directory" in out


def test_default_mode_only_warns_on_missing_suite(tmp_path, monkeypatch):
    _suite_env(tmp_path, monkeypatch)
    monkeypatch.setattr(smoke, "SUITES", (("missing/tests", ["pytest"]),))

    report = smoke.Report()
    smoke.check_tests(report)

    assert report.failures == 0
    assert report.warnings >= 1


def test_strict_mode_fails_when_no_tests_are_collected(tmp_path, monkeypatch, capsys):
    root = _suite_env(tmp_path, monkeypatch)
    (root / "empty").mkdir()
    monkeypatch.setattr(smoke, "SUITES", (("empty", ["pytest"]),))
    monkeypatch.setattr(
        smoke,
        "run_suite",
        lambda suite, deps, uv: (5, {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}, ""),
    )

    report = smoke.Report()
    smoke.check_tests(report, strict_suites=True)

    out = capsys.readouterr().out
    assert report.failures >= 1
    assert "no tests collected" in out
