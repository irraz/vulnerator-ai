"""Test of the EXAMPLE plugin ``example-hello`` (PURE STDLIB, with an ``mcp`` double).

The plugin's directory ends in ``.disabled``, so it is NOT importable by name: its
``plugin.py`` is loaded BY PATH with ``importlib.util.spec_from_file_location`` (just like
the real loader does). ``register(ctx)`` is run with a real ``PluginContext`` over an ``mcp``
double (the SDK is not in the dev venv), following the ``test_plugin_api`` pattern.

It verifies that the plugin mounts the ``hello`` tool, declares the skill and the volume,
and that the captured tool returns the expected harmless greeting.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PARENT))

import plugin_api  # noqa: E402

# Path to the example's plugin.py (.disabled directory -> only loadable by path).
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
    """Double of FastMCP that CAPTURES the function decorated by ``tool()`` to invoke it."""

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

    # Mounts the 'hello' tool.
    assert ctx.tools == ["hello"]
    assert ctx.collisions == []
    assert "hello" in mcp.registered

    # Declares the skill (skill/ directory under the plugin).
    assert ctx.skill_path == os.path.realpath(str(_PLUGIN_DIR / "skill"))

    # Declares (annotates) the artifacts volume.
    assert ctx.volumes == ["kali-artifacts"]


def test_tool_hello_devuelve_saludo_inocuo():
    module = _load_example_plugin()
    mcp = _FakeMcp()
    ctx = plugin_api.PluginContext(mcp, str(_PLUGIN_DIR))

    module.register(ctx)
    hello = mcp.registered["hello"]

    assert hello() == {"status": "done", "greeting": "hello, world"}
    assert hello("kiro") == {"status": "done", "greeting": "hello, kiro"}
