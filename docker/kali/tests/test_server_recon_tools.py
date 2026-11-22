"""Tests de FORMA del cableado de `dns_recon` / `webtech_scan` en el servidor MCP.

Environment constraint (like ``test_kali_run``): ``kali_mcp_server.py`` requires
``mcp<2`` (FastMCP 1.x) and it is not in the dev venv, so the server is NOT imported: its
SOURCE TEXT is inspected. Both tools' LOGIC lives in ``dnsdumpster_client`` /
``webtech_scan`` and is covered in their own tests; here only that the server:
  - imports the modules (``webtech_scan`` with an ALIAS to avoid shadowing the same-named tool);
  - declara las constantes de nombre de tool y las registra en ``server_info``;
  - exposes ``@mcp.tool`` wrappers that DELEGATE to the logic (not reimplement it);
  - reporta la disponibilidad REAL de binarios y la presencia de la API key.
"""

from __future__ import annotations

from pathlib import Path

_SERVER_PATH = Path(__file__).resolve().parent.parent / "kali_mcp_server.py"


def _source() -> str:
    return _SERVER_PATH.read_text(encoding="utf-8")


def test_imports_de_modulos():
    source = _source()
    assert "import dnsdumpster_client" in source
    # The webtech_scan module is imported with an alias to avoid colliding with the tool.
    assert "import webtech_scan as webtech" in source


def test_constantes_de_tool():
    source = _source()
    assert 'DNS_RECON_TOOL_NAME = "dns_recon"' in source
    assert 'WEBTECH_SCAN_TOOL_NAME = "webtech_scan"' in source


def test_wrappers_registrados_y_delegan():
    source = _source()
    assert "@mcp.tool(name=DNS_RECON_TOOL_NAME)" in source
    assert "def dns_recon(" in source
    assert "dnsdumpster_client.recon_domain(" in source

    assert "@mcp.tool(name=WEBTECH_SCAN_TOOL_NAME)" in source
    assert "def webtech_scan(" in source
    # Delegates via the module ALIAS, not the function name (avoids shadowing).
    assert "webtech.run_webtech(" in source


def test_server_info_lista_tools_y_disponibilidad():
    source = _source()
    # `server_info` no longer carries a static list of tool names: it derives `tools` via
    # introspection of the FastMCP registry (see test_server_info.py). The recon tools
    # siguen declaradas con sus constantes en el decorador `@mcp.tool(name=...)`.
    assert "@mcp.tool(name=DNS_RECON_TOOL_NAME)" in source
    assert "@mcp.tool(name=WEBTECH_SCAN_TOOL_NAME)" in source
    assert '"recon_tools":' in source
    assert '"dnsdumpster_key_present":' in source
    # Availability is computed with shutil.which over the webtech module's binaries.
    assert "shutil.which(webtech.WHATWEB_BIN)" in source
    assert "shutil.which(webtech.WPSCAN_BIN)" in source


def test_no_hay_shadowing_del_modulo():
    # Inside the tool body, `webtech_scan.` must NOT be used (that would be the function, not the
    # module): all module references go through the alias `webtech.`.
    source = _source()
    body_start = source.index("def webtech_scan(")
    body = source[body_start:]
    assert "webtech_scan.run_webtech" not in body
    assert "webtech_scan.DEFAULT_TOOL_TIMEOUT_S" not in body
