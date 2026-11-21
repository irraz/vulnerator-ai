#!/usr/bin/env python3
"""Bloquea comentarios de parche/atajo/deuda (marcadores quick-fix).

Regla canónica (una sola pasada, sin listas de deuda):

    ^\\s*(?:#|//|/\\*|\\*|<!--)\\s*(?:TODO|FIXME|HACK|XXX|TEMP|WORKAROUND|PARCHE|
    QUICKFIX|QUICK FIX|HOTFIX|KLUDGE|TRAMP)\\s*[:!]

más la variante docstring que empieza por el marcador tras ``\"\"\"``/``'''``.

El anclaje al prefijo de comentario + separador ``:``/``!`` es lo que evita los
falsos positivos del español («# todo el store», «# TODOS LOS CHECKS»,
«# pre-parche», «# PARCHEADA»). NO relajar a substring: sin prefijo y separador
el español legítimo dispara falsos positivos.

Ámbito: .py .sh .bash .js .ts .yml .yaml .toml .ini .cfg .conf .mk .make
Dockerfile Makefile *.dockerfile; solo comentarios/docstrings.

Uso:
    python3 scripts/check_quick_fix_comments.py [--all] [RUTA ...]

Salida: ``ruta:línea: [tipo] | comentario`` por hallazgo, más un resumen.
Exit: ``1`` si hay hallazgos, ``0`` si no, ``2`` si hay error de argumentos.
"""

import argparse
import re
import sys
from pathlib import Path

# --- Regla canónica ----------------------------------------------------------
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

COMMENT_RE = re.compile(
    r"^\s*(?:#|//|/\*|\*|<!--)\s*(?:" + _MARKER_ALT + r")\s*[:!]",
    re.IGNORECASE,
)
DOCSTRING_RE = re.compile(
    r"^\s*(?:\"\"\"|''')\s*(?:" + _MARKER_ALT + r")\s*[:!]",
    re.IGNORECASE,
)

# --- Ámbito y exclusiones ----------------------------------------------------
SCOPE_EXTENSIONS = {
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
    ".mk",
    ".make",
    ".dockerfile",
}
SCOPE_NAMES = {"Dockerfile", "Makefile"}
EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "node_modules",
    ".tox",
    "dist",
    "build",
}


def _in_scope(path):
    return path.suffix in SCOPE_EXTENSIONS or path.name in SCOPE_NAMES


def _excluded(path, root):
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    return any(part in EXCLUDED_DIRS for part in rel.parts)


def collect_files(targets):
    """Devuelve los ficheros en ámbito de los objetivos (rutas o directorios)."""
    files = []
    for target in targets:
        p = Path(target)
        if not p.exists():
            raise SystemExit(f"error: la ruta no existe: {p}")
        if p.is_dir():
            root = p
            for f in sorted(p.rglob("*")):
                if not f.is_file() or _excluded(f, root) or not _in_scope(f):
                    continue
                files.append(f)
        elif _in_scope(p):
            files.append(p)
        else:
            print(f"aviso: fuera de ámbito: {p}", file=sys.stderr)
    return files


def scan_file(path):
    """Devuelve [(linea, tipo, comentario)] para los marcadores del fichero."""
    found = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"aviso: no se pudo leer {path}: {exc}", file=sys.stderr)
        return found
    for lineno, line in enumerate(text.splitlines(), start=1):
        if COMMENT_RE.search(line):
            found.append((lineno, "marcador:comentario", line.strip()))
        elif DOCSTRING_RE.search(line):
            found.append((lineno, "marcador:docstring", line.strip()))
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Bloquea comentarios con marcadores quick-fix en comentarios/docstrings."
    )
    parser.add_argument("paths", nargs="*", help="Ficheros o directorios a revisar.")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Revisa todo el repositorio (respeta .git/.venv/__pycache__ y caches).",
    )
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    if args.all:
        targets = [root]
    elif args.paths:
        targets = args.paths
    else:
        parser.error("indica al menos una ruta o usa --all")

    def display(f):
        try:
            return str(f.relative_to(root))
        except ValueError:
            return str(f)

    findings = []
    for f in collect_files(targets):
        for line, tipo, text in scan_file(f):
            findings.append((display(f), line, tipo, text))
    findings.sort(key=lambda item: (item[0], item[1], item[2]))

    for ruta, line, tipo, text in findings:
        print(f"{ruta}:{line}: [{tipo}] | {text}")

    if findings:
        print(f"{len(findings)} hallazgo(s) de marcador quick-fix")
        return 1
    print("OK: 0 hallazgos")
    return 0


if __name__ == "__main__":
    sys.exit(main())
