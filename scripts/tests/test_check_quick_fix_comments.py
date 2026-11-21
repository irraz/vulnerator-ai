#!/usr/bin/env python3
"""Tests del gate de comentarios quick-fix (check_quick_fix_comments.py)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "check_quick_fix_comments.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_quick_fix_comments", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cfc = _load()

# Falsos positivos del español y de sintaxis adyacente: deben dar 0 hallazgos.
FALSE_POSITIVES = [
    "# todo el store",
    "# todo simulado",
    "# TODOS LOS CHECKS",
    "# temporary credentials (STS)",
    "# pre-parche",
    "# PARCHEADA",
    "# El store tiene un TODO pendiente",
    '"""Lee TODO el store del engagement."""',
]

# Marcadores inyectados que deben detectarse 10/10.
MARKERS = [
    "TODO",
    "FIXME",
    "HACK",
    "XXX",
    "TEMP",
    "WORKAROUND",
    "PARCHE",
    "QUICKFIX",
    "QUICK FIX",
    "HOTFIX",
]


@pytest.mark.parametrize("line", FALSE_POSITIVES)
def test_false_positives(line, tmp_path):
    f = tmp_path / "sample.py"
    f.write_text(line + "\n", encoding="utf-8")
    assert cfc.scan_file(f) == []


@pytest.mark.parametrize("marker", MARKERS)
def test_true_positive(marker, tmp_path):
    f = tmp_path / "sample.py"
    f.write_text(f"# {marker}: inyeccion de prueba\n", encoding="utf-8")
    found = cfc.scan_file(f)
    assert len(found) == 1
    assert found[0][0] == 1


def test_ten_injected_markers(tmp_path):
    f = tmp_path / "sample.py"
    f.write_text("\n".join(f"# {m}: inyeccion" for m in MARKERS) + "\n", encoding="utf-8")
    found = cfc.scan_file(f)
    assert len(found) == 10
    assert [x[0] for x in found] == list(range(1, 11))


def test_docstring_variant(tmp_path):
    f = tmp_path / "sample.py"
    f.write_text('"""QUICK FIX: arreglo rapido"""\n', encoding="utf-8")
    assert len(cfc.scan_file(f)) == 1


def test_repo_is_clean():
    findings = []
    for f in cfc.collect_files([ROOT]):
        findings.extend(cfc.scan_file(f))
    assert findings == [], "\n".join(
        f"{p}:{line}: [{tipo}] | {texto}" for p, line, tipo, texto in findings
    )
