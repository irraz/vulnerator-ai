"""Tests de la regla anti-comentarios de parche rapido.

Corpus de falsos positivos (espanol y marcadores sin separador) y corpus de
marcadores inyectados, mas un barrido real del repo que debe salir limpio.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
CHECKER = SCRIPTS / "check_quick_fix_comments.py"
ROOT = SCRIPTS.parent


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_quick_fix_comments", CHECKER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cfc = _load_checker()

# Los marcadores se construyen por concatenacion para que este propio fichero no
# contenga jamas un marcador con separador y el barrido del repo salga limpio.
_MARKERS = [
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
    "KLUDGE",
    "TRAMP",
]

# Comentarios que NO son deuda: el marcador no abre la nota o no lleva separador.
FALSE_POSITIVES = [
    "# todo el store",
    "# todo simulado",
    "# TODOS LOS CHECKS",
    "# temporary credentials",
    "# pre-parche",
    "# PARCHEADA",
    "# El store tiene un TODO pendiente",
    "# hotfix pendiente",
    "# temporal mientras tanto",
    '"""Lee TODO el store"""',
    "// trabajo en torno al problema",
    # Un '#' dentro de un literal NO es un comentario: no se marca.
    's = "error # TODO: fix"',
    'x = f"{y} # FIXME: z"',
    'key: "value # TODO: x"',
    'echo "a # FIXME: b"',
]

# Comentarios que SI son deuda: el marcador abre la nota y lleva ':' o '!'.
TRUE_POSITIVES = [
    "# " + "TODO" + ":",
    "# " + "FIXME" + ":",
    "# " + "HACK" + ":",
    "# " + "PARCHE" + ":",
    "# " + "QUICK FIX" + ":",
    "# " + "HOTFIX" + "!",
    "// " + "TODO" + ":",
    "/* " + "FIXME" + ": */",
    "<!-- " + "HACK" + ": -->",
    '"""' + "TODO" + ": leave this for later" + '"""',
    " * " + "XXX" + ":",
]


def test_false_positives_are_not_flagged():
    for line in FALSE_POSITIVES:
        assert not cfc.COMMENT_RE.match(line), line
        assert not cfc.DOCSTRING_RE.match(line), line


def test_true_positives_are_flagged():
    for line in TRUE_POSITIVES:
        assert cfc.COMMENT_RE.match(line) or cfc.DOCSTRING_RE.match(line), line


def test_marker_list_matches_checker():
    assert sorted(cfc.MARKERS) == sorted(_MARKERS)


def test_scan_file_flags_injected_marker(tmp_path):
    target = tmp_path / "sample.py"
    target.write_text("def f():\n    # " + "TODO" + ": arreglar\n    return 1\n", encoding="utf-8")
    found = cfc.scan_file(target)
    assert found == [(2, "# " + "TODO" + ": arreglar")]


def test_scan_file_ignores_clean_file(tmp_path):
    target = tmp_path / "clean.py"
    target.write_text("def f():\n    # todo el store\n    return 1\n", encoding="utf-8")
    assert cfc.scan_file(target) == []


def test_trailing_comment_is_flagged(tmp_path):
    target = tmp_path / "trailing.py"
    target.write_text("x = 1  # " + "TODO" + ": arreglar\n", encoding="utf-8")
    assert cfc.scan_file(target) == [(1, "x = 1  # " + "TODO" + ": arreglar")]


def test_trailing_comment_lowercase_is_not_flagged(tmp_path):
    target = tmp_path / "trailing_clean.py"
    target.write_text("x = 1  # todo el store\n", encoding="utf-8")
    assert cfc.scan_file(target) == []


def test_trailing_marker_inside_string_is_not_flagged(tmp_path):
    """Un '#' en un literal no es comentario: tokenize no lo emite como COMMENT."""
    target = tmp_path / "string_fp.py"
    target.write_text(
        's = "error # ' + "TODO" + ': fix"\n'
        'x = 1  # ' + "TODO" + ": real\n",
        encoding="utf-8",
    )
    found = cfc.scan_file(target)
    assert found == [(2, "x = 1  # " + "TODO" + ": real")]


def test_trailing_marker_out_of_scope_in_non_python(tmp_path):
    """En .sh/.yaml/.toml la media linea queda fuera de ambito (sin parser)."""
    for suffix, content in (
        ("yaml", 'key: "value # ' + "TODO" + ': x"\n'),
        ("sh", 'echo "a # ' + "FIXME" + ': b"\n'),
    ):
        target = tmp_path / f"sample.{suffix}"
        target.write_text(content, encoding="utf-8")
        assert cfc.scan_file(target) == [], target


def test_double_hash_marker_is_flagged(tmp_path):
    target = tmp_path / "double.py"
    target.write_text("## " + "FIXME" + ": doble\n", encoding="utf-8")
    assert cfc.scan_file(target) == [(1, "## " + "FIXME" + ": doble")]


def test_repo_is_clean():
    """El repo no debe contener ningun comentario de parche/atajo/deuda."""
    proc = subprocess.run(
        [sys.executable, str(CHECKER), "--all"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
