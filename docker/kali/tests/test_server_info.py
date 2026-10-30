"""SHAPE tests of the `server_info` wiring and of the plugin loader.

Environment constraint (like ``test_server_recon_tools``): ``kali_mcp_server.py`` requires
``mcp<2`` (FastMCP 1.x) and it is not in the dev venv, so the server is NOT imported: its
source TEXT is inspected. Here it is pinned that ``server_info``:
  - derives ``tools`` by synchronous INTROSPECTION (``mcp._tool_manager.list_tools()``), not
    from a static list;
  - no longer contains the old static list of 15 tool names;
  - adds a ``plugins`` block read from the loader's report;
and that ``plugin_loader.load_plugins`` is invoked ONLY inside the ``__main__`` guard
(HIGH-1), never at module level (it would run on every import and in the tests without the
SDK).
"""

from __future__ import annotations

from pathlib import Path

_SERVER_PATH = Path(__file__).resolve().parent.parent / "kali_mcp_server.py"


def _source() -> str:
    return _SERVER_PATH.read_text(encoding="utf-8")


def test_tools_por_introspeccion_sincrona():
    source = _source()
    # Derives from the tool manager's SYNCHRONOUS internal API.
    assert "mcp._tool_manager.list_tools()" in source
    # Does NOT use the public FastMCP.list_tools (async): must not appear as `mcp.list_tools(`.
    assert "mcp.list_tools(" not in source


def test_lista_estatica_de_15_nombres_eliminada():
    source = _source()
    # The old static list enumerated these constants as elements of `tools`
    # (with a trailing comma). That form must no longer exist anywhere in the server.
    for const in (
        "START_COLLECTION_TOOL_NAME,",
        "SCAN_STATUS_TOOL_NAME,",
        "READ_LOGS_TOOL_NAME,",
        "CANCEL_SCAN_TOOL_NAME,",
        "IAM_ENUM_TOOL_NAME,",
        "IAM_SIMULATE_TOOL_NAME,",
        "KALI_EXEC_TOOL_NAME,",
        "KALI_RUN_TOOL_NAME,",
        "RECORD_FINDING_TOOL_NAME,",
        "READ_FINDINGS_STORE_TOOL_NAME,",
        "DNS_RECON_TOOL_NAME,",
        "WEBTECH_SCAN_TOOL_NAME,",
    ):
        assert const not in source, f"la lista estática aún referencia {const!r}"
    # The textual marker of the old inline list (`"server_info",` as an element) neither.
    assert '"server_info",' not in source


def test_bloque_plugins_en_server_info():
    source = _source()
    assert '"plugins": _plugins_block()' in source
    # The block uses the closed schema read from LAST_REPORT.
    assert "plugin_loader.LAST_REPORT" in source or "LAST_REPORT" in source


def test_load_plugins_bajo_guard_main_y_no_a_nivel_modulo():
    source = _source()
    assert 'if __name__ == "__main__":' in source
    guard_idx = source.index('if __name__ == "__main__":')
    # The invocation must exist and be AFTER the guard (inside the __main__ block).
    call = "plugin_loader.load_plugins("
    assert call in source
    assert source.index(call) > guard_idx, "load_plugins no está bajo el guard __main__"
    # And there must be no invocation at module level (before the guard).
    assert (
        source[:guard_idx].find(call) == -1
    ), "load_plugins se invoca a nivel de módulo"
