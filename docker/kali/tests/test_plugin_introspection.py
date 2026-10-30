"""EXECUTABLE guard of the FastMCP internal API that the plugin system depends on.

This is the ONLY test that validates §5.3 FOR REAL: it runs against the real ``mcp`` SDK the
four assumptions about ``FastMCP``'s internal/public API on which the plugin loader
(``plugin_loader`` / ``plugin_api``) and ``server_info`` rely:

  1. ``mcp._tool_manager.list_tools()`` exists, is SYNCHRONOUS (not a coroutine function) and
     returns objects with a ``.name`` attribute.
  2. The PUBLIC ``FastMCP.list_tools`` is ``async`` (that is why ``server_info`` uses the
     internal one).
  3. Registering a tool TWICE with the same name is a SILENT no-op (it does not raise and does
     not replace the first) — the basis of explicit collision detection.
  4. ``_tool_manager.remove_tool(name)`` exists and works — the basis of the NIT-8 rollback.

If the SDK is NOT installed (dev venv) -> EXPLICIT ``pytest.skip``: the skip is only for the
environment without the SDK. IN CI/IMAGE WITH THE SDK IT MUST NOT BE SKIPPED: a real API
failure cannot be masked by the local skip.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

# The SDK is only in the Kali image / a venv with mcp>=1.28,<2. Without it, explicit skip.
fastmcp_mod = pytest.importorskip(
    "mcp.server.fastmcp",
    reason="'mcp' SDK not installed (dev venv); in image/CI with the SDK it must NOT be skipped",
)
FastMCP = fastmcp_mod.FastMCP


def _new_server() -> "FastMCP":
    return FastMCP("introspection-test")


def test_tool_manager_list_tools_es_sincrono_y_da_objetos_con_name():
    mcp = _new_server()

    @mcp.tool()
    def alpha() -> str:
        """test tool."""
        return "alpha"

    tool_manager = mcp._tool_manager
    # It exists and is NOT a coroutine function (it is SYNCHRONOUS).
    assert hasattr(tool_manager, "list_tools")
    assert not inspect.iscoroutinefunction(tool_manager.list_tools)

    tools = tool_manager.list_tools()
    assert not inspect.iscoroutine(tools), "list_tools() no debe devolver una corutina"
    names = {t.name for t in tools}  # each object exposes .name
    assert "alpha" in names


def test_fastmcp_list_tools_publico_es_async():
    # FastMCP's public method is async: that is why server_info uses the internal (synchronous)
    # tool_manager instead of this one (which would require an event loop).
    assert inspect.iscoroutinefunction(FastMCP.list_tools)


def test_add_tool_duplicado_es_noop_silencioso():
    mcp = _new_server()

    @mcp.tool(name="dup")
    def first() -> str:
        """first."""
        return "first"

    before = {t.name for t in mcp._tool_manager.list_tools()}
    assert "dup" in before

    # Registering another with the SAME name must not raise...
    @mcp.tool(name="dup")
    def second() -> str:
        """second (same key)."""
        return "second"

    after = [t for t in mcp._tool_manager.list_tools() if t.name == "dup"]
    # ...nor duplicate the entry (there is still exactly one 'dup').
    assert len(after) == 1


def test_remove_tool_existe_y_funciona():
    mcp = _new_server()

    @mcp.tool(name="temp")
    def temp() -> str:
        """temporary tool."""
        return "temp"

    assert "temp" in {t.name for t in mcp._tool_manager.list_tools()}
    assert hasattr(mcp._tool_manager, "remove_tool")
    mcp._tool_manager.remove_tool("temp")
    assert "temp" not in {t.name for t in mcp._tool_manager.list_tools()}


def test_server_puede_listar_tools_via_api_publica_async():
    # Sanity: the async public API also works (confirms the object is usable).
    mcp = _new_server()

    @mcp.tool()
    def beta() -> str:
        """test tool."""
        return "beta"

    tools = asyncio.run(mcp.list_tools())
    assert "beta" in {t.name for t in tools}
