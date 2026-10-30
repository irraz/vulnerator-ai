"""Tests de ``load_plugins`` (STDLIB PURA, con un doble de ``mcp`` — SIN el SDK).

Usan el árbol de fixtures en ``tests/fixtures/plugins/`` como ``plugins_root`` y un doble de
``mcp`` cuyo ``_tool_manager`` registra las llamadas a ``remove_tool`` (para probar la
reversión NIT-8). No se importa el SDK ``mcp`` (no está en el venv de dev).
"""

from __future__ import annotations

import sys
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PARENT))

import plugin_loader  # noqa: E402

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "plugins"


class _FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeToolManager:
    def __init__(self) -> None:
        self._names: list[str] = []
        self.removed: list[str] = []

    def list_tools(self):
        return [_FakeTool(n) for n in self._names]

    def remove_tool(self, name: str) -> None:
        self.removed.append(name)
        self._names.remove(name)


class _FakeMcp:
    def __init__(self) -> None:
        self._tool_manager = _FakeToolManager()

    def tool(self, *args, **kwargs):
        def _decorator(fn):
            name = kwargs.get("name") or fn.__name__
            self._tool_manager._names.append(name)
            return fn

        return _decorator


def _by_name(report):
    return {r.name: r for r in report.plugins}


def test_raiz_inexistente_reporte_vacio_y_last_report(tmp_path):
    mcp = _FakeMcp()
    missing = str(tmp_path / "nope")
    report = plugin_loader.load_plugins(mcp, missing)
    assert report.plugins == []
    # LAST_REPORT quedó asignado al reporte vacío (HIGH-1).
    assert plugin_loader.LAST_REPORT is report


def test_raiz_que_no_es_dir_reporte_vacio(tmp_path):
    f = tmp_path / "a-file"
    f.write_text("x", encoding="utf-8")
    report = plugin_loader.load_plugins(_FakeMcp(), str(f))
    assert report.plugins == []


def test_orden_determinista_y_omisiones():
    mcp = _FakeMcp()
    report = plugin_loader.load_plugins(mcp, str(_FIXTURES))
    names = [r.name for r in report.plugins]

    # Orden alfabético estricto entre los candidatos presentes.
    assert names == sorted(names)
    # Dir .disabled ignorado y dir sin plugin.py omitido.
    assert "example.disabled" not in names
    assert "not_a_plugin" not in names
    # 'aaa_first' va antes que 'zzz_last'.
    assert names.index("aaa_first") < names.index("zzz_last")


def test_plugin_valido_cargado_con_tool_skill_volumen():
    report = plugin_loader.load_plugins(_FakeMcp(), str(_FIXTURES))
    rec = _by_name(report)["aaa_first"]
    assert rec.status == "loaded"
    assert rec.phase == "loaded"
    assert rec.tools == ["aaa_tool"]
    assert rec.skill is not None and rec.skill.endswith("skill.md")
    assert rec.volumes == ["aaa-vol"]


def test_import_de_hermano_resuelve_medium3():
    report = plugin_loader.load_plugins(_FakeMcp(), str(_FIXTURES))
    rec = _by_name(report)["sibling_import"]
    assert rec.status == "loaded"
    assert rec.tools == ["sibling_tool"]


def test_import_roto_cae_en_fase_import():
    report = plugin_loader.load_plugins(_FakeMcp(), str(_FIXTURES))
    rec = _by_name(report)["broken_import"]
    assert rec.status == "failed"
    assert rec.phase == "import"
    # El reporte guarda SOLO el mensaje corto (una línea, sin rutas ni traceback).
    assert rec.error and "\n" not in rec.error


def test_api_ausente_e_incompatible_caen_en_fase_api():
    report = plugin_loader.load_plugins(_FakeMcp(), str(_FIXTURES))
    recs = _by_name(report)
    assert recs["no_api"].status == "failed"
    assert recs["no_api"].phase == "api"
    assert recs["bad_api"].status == "failed"
    assert recs["bad_api"].phase == "api"


def test_sin_register_cae_en_register_missing():
    report = plugin_loader.load_plugins(_FakeMcp(), str(_FIXTURES))
    rec = _by_name(report)["no_register"]
    assert rec.status == "failed"
    assert rec.phase == "register-missing"


def test_register_que_lanza_revierte_tools_nit8():
    mcp = _FakeMcp()
    report = plugin_loader.load_plugins(mcp, str(_FIXTURES))
    rec = _by_name(report)["raises_register"]
    assert rec.status == "failed"
    assert rec.phase == "register"
    # NIT-8: la tool parcial 'partial_tool' se revirtió vía _tool_manager.remove_tool.
    assert "partial_tool" in mcp._tool_manager.removed
    assert "partial_tool" not in mcp._tool_manager._names


def test_sys_path_restaurado_tras_la_pasada():
    before = list(sys.path)
    plugin_loader.load_plugins(_FakeMcp(), str(_FIXTURES))
    assert sys.path == before


def test_nombre_invalido_cae_en_fase_name(tmp_path):
    # Un nombre de dir inválido se crea en caliente (no portable como fixture versionado).
    bad = tmp_path / "bad name!"
    bad.mkdir()
    (bad / "plugin.py").write_text("PLUGIN_API = 1\n\ndef register(ctx):\n    pass\n", encoding="utf-8")
    report = plugin_loader.load_plugins(_FakeMcp(), str(tmp_path))
    rec = _by_name(report)["bad name!"]
    assert rec.status == "failed"
    assert rec.phase == "name"


def test_last_report_asignado_tras_pasada_no_vacia():
    report = plugin_loader.load_plugins(_FakeMcp(), str(_FIXTURES))
    assert plugin_loader.LAST_REPORT is report
    assert report.plugins  # hubo candidatos
