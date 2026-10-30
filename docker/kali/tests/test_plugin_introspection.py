"""Guardia EJECUTABLE de la API interna de FastMCP de la que depende el plugin system.

Este es el ÚNICO test que valida §5.3 DE VERDAD: ejecuta contra el SDK ``mcp`` real las
cuatro asunciones sobre la API interna/pública de ``FastMCP`` en las que se apoyan el
cargador de plugins (``plugin_loader`` / ``plugin_api``) y ``server_info``:

  1. ``mcp._tool_manager.list_tools()`` existe, es SÍNCRONO (no es coroutine function) y
     devuelve objetos con atributo ``.name``.
  2. El ``FastMCP.list_tools`` PÚBLICO es ``async`` (por eso ``server_info`` usa el interno).
  3. Registrar DOS veces una tool con el mismo nombre es un no-op SILENCIOSO (no lanza y no
     reemplaza la primera) — base de la detección explícita de colisiones.
  4. ``_tool_manager.remove_tool(name)`` existe y funciona — base del revert NIT-8.

Si el SDK NO está instalado (venv dev) -> ``pytest.skip`` EXPLÍCITO: el skip es sólo para
el entorno sin SDK. EN CI/IMAGEN CON SDK NO DEBE SALTARSE: un fallo real de API no puede
quedar enmascarado por el skip local.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest

# El SDK sólo está en la imagen Kali / un venv con mcp>=1.28,<2. Sin él, skip explícito.
fastmcp_mod = pytest.importorskip(
    "mcp.server.fastmcp",
    reason="SDK 'mcp' no instalado (venv dev); en imagen/CI con SDK NO debe saltarse",
)
FastMCP = fastmcp_mod.FastMCP


def _new_server() -> "FastMCP":
    return FastMCP("introspection-test")


def test_tool_manager_list_tools_es_sincrono_y_da_objetos_con_name():
    mcp = _new_server()

    @mcp.tool()
    def alpha() -> str:
        """tool de prueba."""
        return "alpha"

    tool_manager = mcp._tool_manager
    # Existe y NO es una coroutine function (es SÍNCRONO).
    assert hasattr(tool_manager, "list_tools")
    assert not inspect.iscoroutinefunction(tool_manager.list_tools)

    tools = tool_manager.list_tools()
    assert not inspect.iscoroutine(tools), "list_tools() no debe devolver una corutina"
    names = {t.name for t in tools}  # cada objeto expone .name
    assert "alpha" in names


def test_fastmcp_list_tools_publico_es_async():
    # El método público de FastMCP es async: por eso server_info usa el tool_manager interno
    # (síncrono) en vez de este (requeriría un event loop).
    assert inspect.iscoroutinefunction(FastMCP.list_tools)


def test_add_tool_duplicado_es_noop_silencioso():
    mcp = _new_server()

    @mcp.tool(name="dup")
    def first() -> str:
        """primera."""
        return "first"

    before = {t.name for t in mcp._tool_manager.list_tools()}
    assert "dup" in before

    # Registrar otra con el MISMO nombre no debe lanzar...
    @mcp.tool(name="dup")
    def second() -> str:
        """segunda (misma clave)."""
        return "second"

    after = [t for t in mcp._tool_manager.list_tools() if t.name == "dup"]
    # ...ni duplicar la entrada (sigue habiendo exactamente una 'dup').
    assert len(after) == 1


def test_remove_tool_existe_y_funciona():
    mcp = _new_server()

    @mcp.tool(name="temp")
    def temp() -> str:
        """tool temporal."""
        return "temp"

    assert "temp" in {t.name for t in mcp._tool_manager.list_tools()}
    assert hasattr(mcp._tool_manager, "remove_tool")
    mcp._tool_manager.remove_tool("temp")
    assert "temp" not in {t.name for t in mcp._tool_manager.list_tools()}


def test_server_puede_listar_tools_via_api_publica_async():
    # Sanity: la API pública async también funciona (confirma que el objeto es usable).
    mcp = _new_server()

    @mcp.tool()
    def beta() -> str:
        """tool de prueba."""
        return "beta"

    tools = asyncio.run(mcp.list_tools())
    assert "beta" in {t.name for t in tools}
