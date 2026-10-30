"""Test del plugin de EJEMPLO ``example-hello`` (STDLIB PURA, con doble de ``mcp``).

El directorio del plugin termina en ``.disabled``, por lo que NO es importable por nombre:
se carga su ``plugin.py`` POR RUTA con ``importlib.util.spec_from_file_location`` (igual que
hace el cargador real). Se ejecuta ``register(ctx)`` con un ``PluginContext`` real sobre un
doble de ``mcp`` (el SDK no está en el venv de dev), siguiendo el patrón de ``test_plugin_api``.

Verifica que el plugin monta la tool ``hello``, declara la skill y el volumen, y que la tool
capturada devuelve el saludo inocuo esperado.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PARENT))

import plugin_api  # noqa: E402

# Ruta al plugin.py del ejemplo (directorio .disabled -> solo cargable por ruta).
_PLUGIN_DIR = _PARENT.parent.parent / "plugins" / "example-hello.disabled"
_PLUGIN_PY = _PLUGIN_DIR / "plugin.py"


class _FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name


class _FakeToolManager:
    def __init__(self, names=None) -> None:
        self._names = list(names or [])

    def list_tools(self):
        return [_FakeTool(n) for n in self._names]

    def remove_tool(self, name: str) -> None:
        self._names.remove(name)


class _FakeMcp:
    """Doble de FastMCP que CAPTURA la función decorada por ``tool()`` para invocarla."""

    def __init__(self, existing=None) -> None:
        self._tool_manager = _FakeToolManager(existing)
        self.registered: dict = {}

    def tool(self, *args, **kwargs):
        def _decorator(fn):
            name = kwargs.get("name") or fn.__name__
            self._tool_manager._names.append(name)
            self.registered[name] = fn
            return fn

        return _decorator


def _load_example_plugin():
    spec = importlib.util.spec_from_file_location("ph_example_hello", str(_PLUGIN_PY))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_plugin_declara_contrato_basico():
    module = _load_example_plugin()
    assert module.PLUGIN_API == plugin_api.SUPPORTED_PLUGIN_API
    assert module.PLUGIN_NAME == "example-hello"
    assert callable(module.register)


def test_register_monta_hello_skill_y_volumen():
    module = _load_example_plugin()
    mcp = _FakeMcp()
    ctx = plugin_api.PluginContext(mcp, str(_PLUGIN_DIR))

    module.register(ctx)

    # Monta la tool 'hello'.
    assert ctx.tools == ["hello"]
    assert ctx.collisions == []
    assert "hello" in mcp.registered

    # Declara la skill (directorio skill/ bajo el plugin).
    assert ctx.skill_path == os.path.realpath(str(_PLUGIN_DIR / "skill"))

    # Declara (anota) el volumen de artefactos.
    assert ctx.volumes == ["kali-artifacts"]


def test_tool_hello_devuelve_saludo_inocuo():
    module = _load_example_plugin()
    mcp = _FakeMcp()
    ctx = plugin_api.PluginContext(mcp, str(_PLUGIN_DIR))

    module.register(ctx)
    hello = mcp.registered["hello"]

    assert hello() == {"status": "done", "greeting": "hello, world"}
    assert hello("kiro") == {"status": "done", "greeting": "hello, kiro"}
