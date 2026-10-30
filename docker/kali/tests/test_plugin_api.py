"""Tests de ``PluginContext`` (STDLIB PURA, con un doble de ``mcp`` — SIN el SDK).

El contrato se valida con un doble de ``mcp`` que imita la parte de la API interna de
FastMCP que ``PluginContext`` toca: ``mcp.tool(*a, **k)`` (decorador) y
``mcp._tool_manager.list_tools()`` (nombres existentes). No se importa el SDK ``mcp``
(no está en el venv de dev), igual que el resto de tests del core.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_PARENT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PARENT))

import plugin_api  # noqa: E402


class _FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeToolManager:
    """Doble del ``_tool_manager`` de FastMCP: lista y elimina tools por nombre."""

    def __init__(self, names=None) -> None:
        self._names = list(names or [])

    def list_tools(self):
        return [_FakeTool(n) for n in self._names]

    def remove_tool(self, name: str) -> None:
        self._names.remove(name)


class _FakeMcp:
    """Doble de FastMCP: ``tool(*a, **k)`` registra el nombre al aplicarse al fn."""

    def __init__(self, existing=None) -> None:
        self._tool_manager = _FakeToolManager(existing)

    def tool(self, *args, **kwargs):
        def _decorator(fn):
            name = kwargs.get("name") or fn.__name__
            self._tool_manager._names.append(name)
            return fn

        return _decorator


class _McpWithoutListTools:
    """Doble SIN ``_tool_manager.list_tools`` para probar el fallback MEDIUM-2."""

    class _TM:
        pass

    def __init__(self) -> None:
        self._tool_manager = self._TM()

    def tool(self, *args, **kwargs):  # pragma: no cover - no debe llegar a delegar
        def _decorator(fn):
            return fn

        return _decorator


def test_tool_delega_y_registra_el_nombre():
    mcp = _FakeMcp()
    ctx = plugin_api.PluginContext(mcp, "/opt/plugins/p")

    @ctx.tool()
    def my_scan():  # noqa: D401
        return "ok"

    assert ctx.tools == ["my_scan"]
    assert ctx.collisions == []
    # La tool quedó efectivamente registrada en el doble.
    assert "my_scan" in {t.name for t in mcp._tool_manager.list_tools()}


def test_tool_colision_con_nativa_no_delega():
    mcp = _FakeMcp(existing=["server_info"])
    ctx = plugin_api.PluginContext(mcp, "/opt/plugins/p")

    @ctx.tool(name="server_info")
    def clash():
        return "nope"

    assert ctx.tools == []
    assert ctx.collisions == ["server_info"]


def test_tool_colision_con_otro_plugin_no_delega():
    # Dos contextos sobre el MISMO mcp: el primero registra 'shared', el segundo colisiona.
    mcp = _FakeMcp()
    ctx_a = plugin_api.PluginContext(mcp, "/opt/plugins/a")
    ctx_b = plugin_api.PluginContext(mcp, "/opt/plugins/b")

    @ctx_a.tool(name="shared")
    def first():
        return 1

    @ctx_b.tool(name="shared")
    def second():
        return 2

    assert ctx_a.tools == ["shared"]
    assert ctx_b.tools == []
    assert ctx_b.collisions == ["shared"]


def test_tool_fallback_medium2_falla_sin_list_tools():
    mcp = _McpWithoutListTools()
    ctx = plugin_api.PluginContext(mcp, "/opt/plugins/p")

    with pytest.raises(AttributeError):

        @ctx.tool()
        def broken():
            return "x"


def test_skill_valida_realpath_bajo_plugin_dir(tmp_path):
    plugin_dir = tmp_path / "p"
    plugin_dir.mkdir()
    (plugin_dir / "skill.md").write_text("hola", encoding="utf-8")
    ctx = plugin_api.PluginContext(_FakeMcp(), str(plugin_dir))

    ctx.skill("skill.md")
    assert ctx.skill_path == os.path.realpath(str(plugin_dir / "skill.md"))


def test_skill_que_escapa_no_se_anota(tmp_path):
    plugin_dir = tmp_path / "p"
    plugin_dir.mkdir()
    ctx = plugin_api.PluginContext(_FakeMcp(), str(plugin_dir))

    ctx.skill("../outside.md")
    assert ctx.skill_path is None


def test_skill_segunda_llamada_es_error_de_contrato(tmp_path):
    plugin_dir = tmp_path / "p"
    plugin_dir.mkdir()
    (plugin_dir / "a.md").write_text("a", encoding="utf-8")
    (plugin_dir / "b.md").write_text("b", encoding="utf-8")
    ctx = plugin_api.PluginContext(_FakeMcp(), str(plugin_dir))

    ctx.skill("a.md")
    ctx.skill("b.md")
    # Se queda con la primera; la segunda se ignora.
    assert ctx.skill_path == os.path.realpath(str(plugin_dir / "a.md"))


def test_needs_volume_anota():
    ctx = plugin_api.PluginContext(_FakeMcp(), "/opt/plugins/p")
    ctx.needs_volume("my-vol")
    ctx.needs_volume("other")
    assert ctx.volumes == ["my-vol", "other"]


def test_plugin_dir_y_vendor_dir_siempre_absolutos():
    ctx = plugin_api.PluginContext(_FakeMcp(), "/opt/plugins/p")
    assert os.path.isabs(ctx.plugin_dir())
    assert os.path.isabs(ctx.vendor_dir())
    assert ctx.plugin_dir() == "/opt/plugins/p"
    assert ctx.vendor_dir() == "/opt/plugins/p/vendor"


def test_vendor_dir_absoluto_aunque_no_exista(tmp_path):
    # vendor/ no existe pero vendor_dir() devuelve ruta absoluta igualmente (nunca None).
    plugin_dir = tmp_path / "p"
    plugin_dir.mkdir()
    ctx = plugin_api.PluginContext(_FakeMcp(), str(plugin_dir))
    assert ctx.vendor_dir() == str(plugin_dir / "vendor")
    assert not os.path.exists(ctx.vendor_dir())


def test_constantes_de_contrato():
    assert plugin_api.SUPPORTED_PLUGIN_API == 1
    assert plugin_api.DISABLED_SUFFIX == ".disabled"
    assert plugin_api.PLUGIN_DIR_NAME_RE.match("ok-plugin_1.2")
    assert not plugin_api.PLUGIN_DIR_NAME_RE.match("bad name!")
