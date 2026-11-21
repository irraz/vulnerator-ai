#!/usr/bin/env python3
"""Bloquea comentarios de parche/atajo/deuda en ficheros ``.py``.

Regla determinista de dos capas (listas cerradas en este propio script):

1. Marcador EN/ES con sintaxis de nota: el marcador va seguido de ``:``, ``-``
   o fin de línea. Así el español ``TODO el ciclo`` no coincide (letras después).
2. Intención de deuda: SOLO dentro del MISMO comentario (una línea), tienen que
   aparecer a la vez un término de deuda y una cue de justificación. Sin cue no
   se bloquea.

Ámbito: solo comentarios ``#`` de ficheros ``.py`` (no docstrings ni strings,
 vía ``tokenize``). Excluye ``*/tests/*``, ``*/fixtures/*``, ``*/.venv/*`` y
``__pycache__``; ``--all`` respeta los mismos excluidos.

Salida: ``ruta:línea: [tipo] | comentario`` por hallazgo, más un resumen.
Exit: ``1`` si hay hallazgos, ``0`` si no, ``2`` si hay error de argumentos.
"""

import argparse
import re
import sys
import tokenize
from pathlib import Path

# --- Capa 1: marcadores con sintaxis de nota ---------------------------------
EN_MARKERS = ("TODO", "FIXME", "HACK", "XXX", "WORKAROUND", "BUG", "KLUDGE", "DEBT")
ES_MARKERS = (
    "PARCHE",
    "ATAJO",
    "DEUDA TÉCNICA",
    "DEUDA",
    "PROVISIONAL",
    "TEMPORAL",
    "REMIENDO",
    "CHAPUZA",
)

# Cola de nota: separador (:, #, -, en/em dash, punto, cierres) o fin de línea.
_NOTE_TAIL = r"(?=\s*[:#\-–—.)\]}>]|\s*$)"  # noqa: RUF001 (los dash son separadores intencionados)


def _marker_re(markers):
    alts = "|".join(re.escape(m) for m in sorted(markers, key=len, reverse=True))
    return re.compile(r"\b(?:" + alts + r")\b" + _NOTE_TAIL)


EN_MARKER_RE = _marker_re(EN_MARKERS)
ES_MARKER_RE = _marker_re(ES_MARKERS)

# --- Capa 2: intención de deuda dentro del MISMO comentario -------------------
DEBT_TERMS = (
    r"workaround",
    r"quick\s+fix",
    r"for\s+now",
    r"temporary",
    r"temporal",
    r"provisional",
    r"parche",
    r"atajo",
    r"deuda",
    r"tech\s+debt",
    r"kludge",
    r"hack",
    r"not\s+ideal",
    r"no\s+es\s+ideal",
    r"remiendo",
)
DEBT_CUES = (
    r"hasta\s+que",
    r"until",
    r"mientras\s+tanto",
    r"mientras",
    r"por\s+ahora",
    r"de\s+momento",
    r"provisionalmente",
    r"temporalmente",
    r"for\s+now",
    r"later",
    r"future",
    r"pr[oó]xima",
    r"deber[íi]a\s+refactor",
    r"to\s+be\s+refactored",
    r"should\s+be\s+refactored",
    r"no\s+es\s+ideal",
    r"not\s+ideal",
    r"workaround",
    r"quick\s+fix",
)

DEBT_TERM_RE = re.compile(r"\b(?:" + "|".join(DEBT_TERMS) + r")\b", re.IGNORECASE)
DEBT_CUE_RE = re.compile(r"\b(?:" + "|".join(DEBT_CUES) + r")\b", re.IGNORECASE)

EXCLUDED_DIRS = {"tests", "fixtures", "__pycache__", ".venv", "venv"}


def _excluded(path):
    return any(part in EXCLUDED_DIRS for part in path.parts)


def collect_files(targets):
    files = []
    for target in targets:
        p = Path(target)
        if not p.exists():
            raise SystemExit(f"error: la ruta no existe: {p}")
        if p.is_dir():
            for f in sorted(p.rglob("*.py")):
                if not _excluded(f.relative_to(p)):
                    files.append(f)
        elif p.suffix == ".py":
            files.append(p)
    return files


def scan_file(path):
    """Devuelve [(linea, tipo, comentario)] para los comentarios '#' del fichero."""
    found = []
    try:
        with open(path, "rb") as fh:
            for tok in tokenize.tokenize(fh.readline):
                if tok.type != tokenize.COMMENT:
                    continue
                text = tok.string.strip()
                line = tok.start[0]
                if EN_MARKER_RE.search(text):
                    found.append((line, "marcador:EN", text))
                if ES_MARKER_RE.search(text):
                    found.append((line, "marcador:ES", text))
                if DEBT_TERM_RE.search(text) and DEBT_CUE_RE.search(text):
                    found.append((line, "intencion:deuda", text))
    except (tokenize.TokenError, IndentationError, SyntaxError, UnicodeDecodeError) as exc:
        print(f"aviso: no se pudo tokenizar {path}: {exc}", file=sys.stderr)
    return found


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Bloquea comentarios de parche/atajo/deuda en comentarios '#' de .py."
    )
    parser.add_argument("paths", nargs="*", help="Ficheros o directorios .py a revisar.")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Revisa todo el repositorio (respeta tests/fixtures/__pycache__/.venv).",
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
        return str(f.relative_to(root)) if args.all else str(f)

    findings = []
    for f in collect_files(targets):
        for line, tipo, text in scan_file(f):
            findings.append((display(f), line, tipo, text))
    findings.sort(key=lambda item: (item[0], item[1], item[2]))

    for ruta, line, tipo, text in findings:
        print(f"{ruta}:{line}: [{tipo}] | {text}")

    if findings:
        print(f"{len(findings)} hallazgo(s) de deuda")
        return 1
    print("OK: 0 hallazgos")
    return 0


if __name__ == "__main__":
    sys.exit(main())
