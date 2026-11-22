"""Tests for the non-English language guard."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
GUARD = SCRIPTS / "check_language.py"

# Built from escapes so this very file never carries non-English characters.
SPANISH_SAMPLE = "a\u00f1adir"
SPANISH_ACCENTS = ("a\u00f1adir", "\u00bfqu\u00e9?", "\u00a1ahora!", "caf\u00e9")
NON_MARKERS = ("\u2705", "\u274c", "\u26a0\ufe0f", "\u2500\u2500\u2500", "\u2705 all 6 suites pass")


def _load_guard():
    spec = importlib.util.spec_from_file_location("check_language", GUARD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = _load_guard()


def test_emoji_and_box_drawing_do_not_match():
    for sample in NON_MARKERS:
        assert guard.NON_ENGLISH_RE.search(sample) is None, sample


def test_spanish_markers_match():
    for sample in SPANISH_ACCENTS:
        assert guard.NON_ENGLISH_RE.search(sample) is not None, sample


def test_new_finding_fails_the_guard():
    baseline = {
        "version": guard.BASELINE_VERSION,
        "regex": guard.NON_ENGLISH_RE.pattern,
        "normalization": guard.NORMALIZATION,
        "entries": {},
    }
    finding = guard.Finding("new.py", 1, SPANISH_SAMPLE, guard.line_digest(SPANISH_SAMPLE))
    new, stale = guard.evaluate([finding], baseline)
    assert [item.path for item in new] == ["new.py"]
    assert stale == []


def test_stale_baseline_entry_fails_the_guard():
    orphan = guard.Finding("old.py", 1, "legacy", guard.line_digest("legacy"))
    baseline = {
        "version": guard.BASELINE_VERSION,
        "regex": guard.NON_ENGLISH_RE.pattern,
        "normalization": guard.NORMALIZATION,
        "entries": {orphan.digest: {"count": 1, "first": "old.py:1"}},
    }
    new, stale = guard.evaluate([], baseline)
    assert new == []
    assert len(stale) == 1
    assert stale[0][0] == orphan.digest


def test_rendered_baseline_accepts_the_same_findings():
    first = guard.Finding("b.py", 2, SPANISH_SAMPLE, guard.line_digest(SPANISH_SAMPLE))
    second = guard.Finding("a.py", 1, SPANISH_SAMPLE, guard.line_digest(SPANISH_SAMPLE))
    baseline = guard.render_baseline([first, second])
    assert list(baseline["entries"]) == [guard.line_digest(SPANISH_SAMPLE)]
    assert baseline["entries"][guard.line_digest(SPANISH_SAMPLE)]["count"] == 2
    new, stale = guard.evaluate([first, second], baseline)
    assert new == [] and stale == []


def test_baseline_metadata_must_match():
    matching = {
        "version": guard.BASELINE_VERSION,
        "regex": guard.NON_ENGLISH_RE.pattern,
        "normalization": guard.NORMALIZATION,
        "entries": {},
    }
    assert guard.baseline_metadata_matches(matching) is True
    mismatched = dict(matching, normalization="NFD")
    assert guard.baseline_metadata_matches(mismatched) is False


def test_repo_matches_committed_baseline(capsys):
    assert guard.main(["--all"]) == 0
    out = capsys.readouterr().out
    assert "OK: 0 new non-English lines" in out
