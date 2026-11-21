#!/usr/bin/env python3
"""Bloquea comentarios de parche rapido / atajo / deuda en el arbol del repo.

Regla determinista y sensata al separador: un marcador solo es de deuda si abre
el comentario y va seguido de ``:`` o ``!``. El separador es lo que aparta los
falsos positivos del espanol (``# todo el store``, ``# PARCHEADA``,
``# temporary credentials``): sin el no, el regex suelto daba 19 falsos
positivos en este repo; con el, 0.

Ambito: ficheros de codigo y configuracion (``.py``, ``.sh``, ``.yaml``...).
No excluye tests: un marcador inyectado en un test es tambien un hallazgo.

Alcance de la deteccion a media linea: solo en ``.py``, y solo sobre tokens
``COMMENT`` reales (``tokenize``), que es la unica forma determinista de no marcar
un ``#`` dentro de un literal (``s = "error # TODO: fix"``). En el resto de
ficheros (``.sh``, ``.yaml``, ``.toml``) un marcador a media linea queda FUERA de
ambito por decision explicita: sin un parser no hay forma fiable de distinguir
comentario de literal, y el gate es bloqueante. Los marcadores que abren la nota
(``# TODO:``, ``## FIXME:``, docstrings) se detectan en todos los ficheros.

Salida: ``ruta:línea: | comentario`` por hallazgo y un resumen final.
Exit: ``0`` limpio, ``1`` hallazgos, ``2`` error de uso.
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

# El marcador abre el comentario (#, ##, //, /*, *, <!--) y lleva ':' o '!' despues.
COMMENT_RE = re.compile(r"^\s*(?:#+|//|/\*|\*|<!--)\s*(?:" + _MARKER_ALT + r")\s*[:!]")
# El marcador es el primer token de un docstring y lleva ':' o '!' despues.
DOCSTRING_RE = re.compile(r"^\s*(?:\"\"\"|''')\s*(?:" + _MARKER_ALT + r")\s*[:!]")
# Media linea en .py: se aplica SOLO al texto de tokens COMMENT de tokenize.
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
    """True si el fichero entra en el ambito de la regla."""
    return path.name in CODE_NAMES or path.suffix.lower() in CODE_SUFFIXES


def is_excluded(path: Path, root: Path) -> bool:
    """True si el fichero cuelga de un directorio excluido."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False
    return any(part in EXCLUDED_DIRS for part in rel.parts)


def collect_files(targets: list[str], root: Path) -> list[Path]:
    """Resuelve las rutas pedidas a ficheros de codigo dentro del ambito."""
    files: list[Path] = []
    for target in targets:
        p = Path(target)
        if not p.exists():
            raise SystemExit(f"error: la ruta no existe: {p}")
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and is_code_file(f) and not is_excluded(f, p):
                    files.append(f)
        elif is_code_file(p):
            files.append(p)
    return files


def _py_comment_tokens(text: str) -> list[tuple[int, str]]:
    """Comentarios reales de un .py: [(linea, texto)] solo tokens COMMENT.

    ``tokenize`` es la unica fuente determinista: un ``#`` dentro de un literal no
    produce un token COMMENT, asi que no se marca. Si el fichero no tokeniza
    (sintaxis a medias, fichero truncado), no se detecta media linea: el gate
    sigue cubriendo los marcadores que abren la nota.
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
    """Devuelve [(linea, comentario)] con marcadores de deuda."""
    found: list[tuple[int, str]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"aviso: no se pudo leer {path}: {exc}", file=sys.stderr)
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
        description="Bloquea comentarios de parche rapido/atajo/deuda."
    )
    parser.add_argument("paths", nargs="*", help="Ficheros o directorios a revisar.")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Revisa todo el repositorio (respeta los directorios excluidos).",
    )
    args = parser.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    if args.all:
        targets = [str(root)]
    elif args.paths:
        targets = args.paths
    else:
        parser.error("indica al menos una ruta o usa --all")

    findings: list[tuple[str, int, str]] = []
    for f in collect_files(targets, root):
        for lineno, text in scan_file(f):
            findings.append((str(f), lineno, text))
    findings.sort(key=lambda item: (item[0], item[1]))

    for ruta, lineno, text in findings:
        print(f"{ruta}:{lineno}: | {text}")

    if findings:
        print(f"{len(findings)} comentario(s) de parche/atajo/deuda")
        return 1
    print("OK: 0 comentarios de parche/atajo/deuda")
    return 0


if __name__ == "__main__":
    sys.exit(main())
