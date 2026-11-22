#!/usr/bin/env python3
"""Blocks new non-English prose in the repository tree.

Deterministic guard over every UTF-8 text file: it flags lines containing an
explicit set of Spanish/non-English characters by codepoint, so emoji and
box-drawing characters never match. Known debt is sealed in
``.language.baseline.json`` keyed by SHA-256 of the NFC-normalized line
content. Lines are normalized before matching, so NFD and NFC spellings are
detected identically. A detected line whose hash is not in the baseline fails,
and a baseline entry whose observed count differs from the recorded count
(fewer occurrences, or more than were sealed) fails until
``--update-baseline`` records the new state.

Exit: ``0`` clean, ``1`` findings or stale baseline, ``2`` usage error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from collections import Counter
from pathlib import Path
from typing import Literal, NamedTuple

NormalizationForm = Literal["NFC", "NFD", "NFKC", "NFKD"]

NON_ENGLISH_RE = re.compile(
    r"[\u00e1\u00e9\u00ed\u00f3\u00fa\u00f1\u00fc"
    r"\u00c1\u00c9\u00cd\u00d3\u00da\u00d1\u00dc\u00bf\u00a1]"
)
NORMALIZATION: NormalizationForm = "NFC"
BASELINE_VERSION = 1
BASELINE_NAME = ".language.baseline.json"
MAX_FILE_BYTES = 2_000_000

EXCLUDED_DIRS = {
    ".cache",
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".venv",
    "media",
    "node_modules",
    "venv",
}


class Finding(NamedTuple):
    path: str
    lineno: int
    text: str
    digest: str


def line_digest(line: str) -> str:
    normalized = unicodedata.normalize(NORMALIZATION, line)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def is_text_file(path: Path) -> bool:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return False
        path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return False
    return True


def iter_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == BASELINE_NAME or path.is_symlink():
            continue
        if any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        if is_text_file(path):
            files.append(path)
    return files


def scan_file(root: Path, path: Path) -> list[Finding]:
    rel = path.relative_to(root).as_posix()
    findings: list[Finding] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        # Normalize before matching: NFD spellings (e.g. "n" + combining tilde)
        # must be flagged exactly like their NFC equivalent.
        normalized = unicodedata.normalize(NORMALIZATION, line)
        if NON_ENGLISH_RE.search(normalized):
            findings.append(Finding(rel, lineno, line, line_digest(normalized)))
    return findings


def collect_findings(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(root):
        findings.extend(scan_file(root, path))
    findings.sort(key=lambda item: (item.path, item.lineno, item.digest))
    return findings


def baseline_path(root: Path, override: str | None) -> Path:
    if override:
        return Path(override)
    return root / BASELINE_NAME


class BaselineError(ValueError):
    """The baseline file is missing, unreadable, or not the expected JSON shape."""


def load_baseline(path: Path) -> dict:
    """Loads the sealed baseline, raising BaselineError instead of leaking a traceback."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BaselineError(
            f"cannot read baseline {path}: {exc.__class__.__name__}"
        ) from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BaselineError(
            f"invalid baseline JSON in {path}: "
            f"line {exc.lineno} column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(data, dict):
        raise BaselineError(f"malformed baseline {path}: expected a JSON object")
    entries = data.get("entries")
    if not isinstance(entries, dict):
        raise BaselineError(f"malformed baseline {path}: 'entries' must be an object")
    for digest, meta in entries.items():
        count = meta.get("count") if isinstance(meta, dict) else None
        if isinstance(count, bool) or not isinstance(count, int):
            raise BaselineError(
                f"malformed baseline {path}: entry {digest!r} must be an object "
                f"with an integer 'count'"
            )
    return data


def baseline_metadata_matches(baseline: dict) -> bool:
    return (
        baseline.get("version") == BASELINE_VERSION
        and baseline.get("regex") == NON_ENGLISH_RE.pattern
        and baseline.get("normalization") == NORMALIZATION
    )


def evaluate(
    findings: list[Finding], baseline: dict
) -> tuple[list[Finding], list[tuple[str, int, str]]]:
    """Returns (new findings, baseline count mismatches).

    A mismatch is reported when the observed count of a baselined line differs
    from the recorded count in either direction: fewer occurrences mean the
    baseline is stale, more mean the line was duplicated beyond the seal.
    """
    counts = Counter(finding.digest for finding in findings)
    entries = baseline["entries"]

    new = [finding for finding in findings if finding.digest not in entries]

    mismatches: list[tuple[str, int, str]] = []
    for digest, meta in sorted(entries.items()):
        expected = int(meta["count"])
        actual = counts.get(digest, 0)
        if actual != expected:
            mismatches.append((digest, actual - expected, str(meta.get("first", ""))))
    return new, mismatches


def render_baseline(findings: list[Finding]) -> dict:
    counts = Counter(finding.digest for finding in findings)
    first_seen: dict[str, str] = {}
    for finding in findings:
        first_seen.setdefault(finding.digest, f"{finding.path}:{finding.lineno}")
    return {
        "version": BASELINE_VERSION,
        "regex": NON_ENGLISH_RE.pattern,
        "normalization": NORMALIZATION,
        "entries": {
            digest: {"count": counts[digest], "first": first_seen[digest]}
            for digest in sorted(counts)
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Blocks new non-English prose against a sealed baseline."
    )
    parser.add_argument("paths", nargs="*", help="Files or directories to review.")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Reviews the whole repository.",
    )
    parser.add_argument(
        "--baseline",
        help="Baseline path (defaults to .language.baseline.json at the repo root).",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Records the current findings as the new sealed baseline.",
    )
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    baseline_file = baseline_path(root, args.baseline)

    if args.update_baseline:
        current = collect_findings(root)
        payload = render_baseline(current)
        baseline_file.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(
            f"baseline updated: {len(current)} finding(s), "
            f"{len(payload['entries'])} distinct line hash(es) -> {baseline_file}"
        )
        return 0

    if not baseline_file.exists():
        print(f"error: baseline not found: {baseline_file}", file=sys.stderr)
        return 2
    try:
        baseline = load_baseline(baseline_file)
    except BaselineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if not baseline_metadata_matches(baseline):
        print(
            "error: baseline metadata does not match this guard "
            "(version/regex/normalization changed); run --update-baseline",
            file=sys.stderr,
        )
        return 1

    if args.all:
        targets = [root]
    elif args.paths:
        targets = [Path(target) for target in args.paths]
    else:
        parser.error("provide at least one path or use --all")

    findings: list[Finding] = []
    for target in targets:
        if not target.exists():
            print(f"error: path does not exist: {target}", file=sys.stderr)
            return 2
        if target.is_dir():
            for path in iter_files(target):
                findings.extend(scan_file(target, path))
        elif is_text_file(target):
            findings.extend(scan_file(target.parent, target))
    findings.sort(key=lambda item: (item.path, item.lineno, item.digest))

    new, mismatches = evaluate(findings, baseline)
    for finding in new:
        print(f"{finding.path}:{finding.lineno}: | {finding.text.strip()}")
    for digest, delta, where in mismatches:
        if delta < 0:
            print(f"stale baseline entry: {digest} ({delta}) last seen {where}")
        else:
            print(f"baseline count exceeded: {digest} (+{delta}) last seen {where}")

    if new or mismatches:
        print(
            f"{len(new)} new non-English line(s), "
            f"{len(mismatches)} baseline count mismatch(es)"
        )
        return 1

    total_baselined = sum(int(meta["count"]) for meta in baseline["entries"].values())
    print(f"OK: 0 new non-English lines ({total_baselined} baselined)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
