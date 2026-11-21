"""Regresion del gate del mapa: secciones, Anexo C y deriva prohibida.

Cubre el bloqueo documentado: `check_mapa` solo leia los Anexos A/B, asi que
renombrar una seccion del mapa no rompia el gate.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1]
ROOT = SCRIPTS.parent
MAP = ROOT / "ARCHITECTURE_MAP.md"


def _cargar_smoke():
    spec = importlib.util.spec_from_file_location("smoke", SCRIPTS / "smoke.py")
    assert spec is not None and spec.loader is not None
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


smoke = _cargar_smoke()


def test_mapa_gate_cubre_secciones_anexo_c_y_deriva():
    texto = MAP.read_text(encoding="utf-8")

    # (a) las 14 cabeceras numeradas existen, una sola vez y en orden.
    cabeceras = [int(m.group(1)) for m in re.finditer(r"^## (\d+)\.", texto, re.M)]
    assert cabeceras == list(range(1, 15)), cabeceras

    # (b) las filas del Anexo C coinciden con las suites reales del smoke.
    _a, _b, filas_c = smoke._annex_tables(texto)
    assert len(filas_c) == len(smoke.SUITES)
    assert set(filas_c) == {suite for suite, _deps in smoke.SUITES}

    # (c) el mapa no debe contener las cadenas de deriva prohibidas.
    for prohibida in smoke.FORBIDDEN_DRIFT:
        assert prohibida not in texto, prohibida
