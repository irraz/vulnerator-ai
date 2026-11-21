"""Tests for the anti-quick-fix-comment rule.

Corpus of false positives (Spanish and markers without a separator) and a corpus
of injected markers, plus a real sweep of the repo that must come out clean.
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

# The markers are built by concatenation so that this very file never contains a
# marker with a separator and the repo sweep comes out clean.
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

# Comments that are NOT debt: the marker does not open the note or has no separator.
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
    # A '#' inside a literal is NOT a comment: it is not flagged.
    's = "error # TODO: fix"',
    'x = f"{y} # FIXME: z"',
    'key: "value # TODO: x"',
    'echo "a # FIXME: b"',
]

# Comments that ARE debt: the marker opens the note and is followed by ':' or '!'.
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
    """A '#' in a literal is not a comment: tokenize does not emit it as COMMENT."""
    target = tmp_path / "string_fp.py"
    target.write_text(
        's = "error # ' + "TODO" + ': fix"\n'
        'x = 1  # ' + "TODO" + ": real\n",
        encoding="utf-8",
    )
    found = cfc.scan_file(target)
    assert found == [(2, "x = 1  # " + "TODO" + ": real")]


def test_trailing_marker_out_of_scope_in_non_python(tmp_path):
    """In .sh/.yaml/.toml the mid-line case is out of scope (no parser)."""
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
    """The repo must not contain any quick-fix/shortcut/debt comment."""
    proc = subprocess.run(
        [sys.executable, str(CHECKER), "--all"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
