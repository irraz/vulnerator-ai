"""Regression for the map gate: sections, Annex C, forbidden drift and section 14.

Covers the documented blocking: `check_map` used to read only Annexes A/B, so renaming a
map section did not break the gate.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
ROOT = SCRIPTS.parent
MAP = ROOT / "ARCHITECTURE_MAP.md"


def _load_smoke():
    spec = importlib.util.spec_from_file_location("smoke", SCRIPTS / "smoke.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


smoke = _load_smoke()


def test_map_gate_covers_sections_annex_c_and_drift():
    text = MAP.read_text(encoding="utf-8")

    # (a) the 14 numbered headers exist, exactly once and in order.
    headers = [int(m.group(1)) for m in re.finditer(r"^## (\d+)\.", text, re.M)]
    assert headers == list(range(1, 15)), headers

    # (b) the Annex C rows match the real smoke suites.
    _a, _b, c_rows = smoke._annex_tables(text)
    assert len(c_rows) == len(smoke.SUITES)
    assert set(c_rows) == {suite for suite, _deps in smoke.SUITES}

    # (c) the map must not contain the forbidden drift strings.
    for forbidden in smoke.FORBIDDEN_DRIFT:
        assert forbidden not in text, forbidden


@pytest.mark.parametrize("marker", smoke.FORBIDDEN_DRIFT)
def test_forbidden_drift_marker_fails_the_gate(marker, tmp_path, monkeypatch):
    mutated = MAP.read_text(encoding="utf-8") + "\n" + marker + "\n"
    fake_map = tmp_path / "ARCHITECTURE_MAP.md"
    fake_map.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(smoke, "MAP", fake_map)

    report = smoke.Report()
    smoke.check_map(report)
    assert report.failures >= 1


def test_section_14_rename_fails_the_gate(tmp_path, monkeypatch):
    original = MAP.read_text(encoding="utf-8")
    assert "## 14. Known debt" in original

    mutated = original.replace("## 14. Known debt", "## 14. Known liabilities")
    fake_map = tmp_path / "ARCHITECTURE_MAP.md"
    fake_map.write_text(mutated, encoding="utf-8")
    monkeypatch.setattr(smoke, "MAP", fake_map)

    report = smoke.Report()
    smoke.check_map(report)
    assert report.failures >= 1
