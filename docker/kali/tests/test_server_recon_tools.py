"""Tests de FORMA del cableado de `dns_recon` / `webtech_scan` en el servidor MCP.

Restricción del entorno (igual que ``test_kali_run``): ``kali_mcp_server.py`` exige
``mcp<2`` (FastMCP 1.x) y en el venv dev no está, así que NO se importa el servidor: se
inspecciona su TEXTO fuente. La LÓGICA de ambas tools vive en ``dnsdumpster_client`` /
``webtech_scan`` y se cubre en sus propios tests; aquí sólo se fija que el servidor:
  - importa los módulos (``webtech_scan`` con ALIAS para no sombrear a la tool homónima);
  - declara las constantes de nombre de tool y las registra en ``server_info``;
  - expone wrappers ``@mcp.tool`` que DELEGAN en la lógica (no la reimplementan);
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
    # El módulo webtech_scan se importa con alias para no colisionar con la tool.
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
    # Delega usando el ALIAS del módulo, no el nombre de la función (evita el shadowing).
    assert "webtech.run_webtech(" in source


def test_server_info_lista_tools_y_disponibilidad():
    source = _source()
    assert "DNS_RECON_TOOL_NAME," in source
    assert "WEBTECH_SCAN_TOOL_NAME," in source
    assert '"recon_tools":' in source
    assert '"dnsdumpster_key_present":' in source
    # La disponibilidad se calcula con shutil.which sobre los binarios del módulo webtech.
    assert "shutil.which(webtech.WHATWEB_BIN)" in source
    assert "shutil.which(webtech.WPSCAN_BIN)" in source


def test_no_hay_shadowing_del_modulo():
    # Dentro del cuerpo de la tool NO debe usarse `webtech_scan.` (sería la función, no el
    # módulo): toda referencia al módulo va por el alias `webtech.`.
    source = _source()
    body_start = source.index("def webtech_scan(")
    body = source[body_start:]
    assert "webtech_scan.run_webtech" not in body
    assert "webtech_scan.DEFAULT_TOOL_TIMEOUT_S" not in body
