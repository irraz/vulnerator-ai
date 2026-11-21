#!/usr/bin/env python3
"""Blocks quick-fix / shortcut / debt comments in the repo tree.

Deterministic rule, sensitive to the separator: a marker is debt only if it opens
the comment and is followed by ``:`` or ``!``. The separator is what keeps the
Spanish false positives out (``# todo el store``, ``# PARCHEADA``,
``# temporary credentials``): without it, the loose regex gave 19 false
positives in this repo; with it, 0.

Scope: code and configuration files (``.py``, ``.sh``, ``.yaml``...).
Tests are not excluded: a marker injected into a test is also a finding.

Mid-line detection scope: only in ``.py``, and only on real ``COMMENT``
tokens (``tokenize``), which is the only deterministic way to avoid flagging a
``#`` inside a literal (``s = "error # TODO: fix"``). In the rest of the
files (``.sh``, ``.yaml``, ``.toml``) a mid-line marker is OUT OF SCOPE by
explicit decision: without a parser there is no reliable way to tell a comment
from a literal, and the gate is blocking. Markers that open the note
(``# TODO:``, ``## FIXME:``, docstrings) are detected in all files.

Output: ``path:line: | comment`` per finding and a final summary.
Exit: ``0`` clean, ``1`` findings, ``2`` usage error.
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import tokenize
from pathlib import Path

MARKERS = (
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
)

_MARKER_ALT = "|".join(re.escape(m) for m in sorted(MARKERS, key=len, reverse=True))

# The marker opens the comment (#, ##, //, /*, *, <!--) and is followed by ':' or '!'.
COMMENT_RE = re.compile(r"^\s*(?:#+|//|/\*|\*|<!--)\s*(?:" + _MARKER_ALT + r")\s*[:!]")
# The marker is the first token of a docstring and is followed by ':' or '!'.
DOCSTRING_RE = re.compile(r"^\s*(?:\"\"\"|''')\s*(?:" + _MARKER_ALT + r")\s*[:!]")
# Mid-line in .py: applied ONLY to the text of tokenize COMMENT tokens.
TRAILING_MARKER_RE = re.compile(r"^\s*#+\s*(?:" + _MARKER_ALT + r")\s*[:!]")

CODE_SUFFIXES = {
    ".py",
    ".sh",
    ".bash",
    ".js",
    ".ts",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".cfg",
    ".conf",
    ".dockerfile",
    ".mk",
    ".make",
}
CODE_NAMES = {"Dockerfile", "Makefile"}

EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "node_modules",
    "media",
}


def is_code_file(path: Path) -> bool:
    """True if the file is in the rule's scope."""
    return path.name in CODE_NAMES or path.suffix.lower() in CODE_SUFFIXES


def is_excluded(path: Path, root: Path) -> bool:
    """True if the file hangs from an excluded directory."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False
    return any(part in EXCLUDED_DIRS for part in rel.parts)


def collect_files(targets: list[str], root: Path) -> list[Path]:
    """Resolves the requested paths to in-scope code files."""
    files: list[Path] = []
    for target in targets:
        p = Path(target)
        if not p.exists():
            raise SystemExit(f"error: path does not exist: {p}")
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and is_code_file(f) and not is_excluded(f, p):
                    files.append(f)
        elif is_code_file(p):
            files.append(p)
    return files


def _py_comment_tokens(text: str) -> list[tuple[int, str]]:
    """Real comments of a .py: [(line, text)] only COMMENT tokens.

    ``tokenize`` is the only deterministic source: a ``#`` inside a literal does
    not produce a COMMENT token, so it is not flagged. If the file does not
    tokenize (half-written syntax, truncated file), mid-line is not detected: the
    gate still covers the markers that open the note.
    """
    tokens: list[tuple[int, str]] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT:
                tokens.append((tok.start[0], tok.string))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return []
    return tokens


def scan_file(path: Path) -> list[tuple[int, str]]:
    """Returns [(line, comment)] with debt markers."""
    found: list[tuple[int, str]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"warning: could not read {path}: {exc}", file=sys.stderr)
        return found

    flagged_lines: set[int] = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        if COMMENT_RE.match(line) or DOCSTRING_RE.match(line):
            found.append((lineno, line.strip()))
            flagged_lines.add(lineno)

    if path.suffix.lower() == ".py":
        lines = text.splitlines()
        for lineno, comment in _py_comment_tokens(text):
            if lineno in flagged_lines:
                continue
            if TRAILING_MARKER_RE.match(comment):
                found.append((lineno, lines[lineno - 1].strip()))

    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Blocks quick-fix/shortcut/debt comments."
    )
    parser.add_argument("paths", nargs="*", help="Files or directories to review.")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Reviews the whole repository (respects excluded directories).",
    )
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    if args.all:
        targets = [str(root)]
    elif args.paths:
        targets = args.paths
    else:
        parser.error("provide at least one path or use --all")

    findings: list[tuple[str, int, str]] = []
    for f in collect_files(targets, root):
        for lineno, text in scan_file(f):
            findings.append((str(f), lineno, text))
    findings.sort(key=lambda item: (item[0], item[1]))

    for ruta, lineno, text in findings:
        print(f"{ruta}:{lineno}: | {text}")

    if findings:
        print(f"{len(findings)} quick-fix/shortcut/debt comment(s)")
        return 1
    print("OK: 0 quick-fix/shortcut/debt comments")
    return 0


if __name__ == "__main__":
    sys.exit(main())
