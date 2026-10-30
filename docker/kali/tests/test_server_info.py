"""Tests de FORMA del cableado de `server_info` y del cargador de plugins.

Restricción del entorno (igual que ``test_server_recon_tools``): ``kali_mcp_server.py``
exige ``mcp<2`` (FastMCP 1.x) y en el venv dev no está, así que NO se importa el servidor:
se inspecciona su TEXTO fuente. Aquí se fija que ``server_info``:
  - deriva ``tools`` por INTROSPECCIÓN síncrona (``mcp._tool_manager.list_tools()``), no de
    una lista estática;
  - ya NO contiene la antigua lista estática de 15 nombres de tool;
  - añade un bloque ``plugins`` leído del reporte del cargador;
y que ``plugin_loader.load_plugins`` se invoca SOLO dentro del guard ``__main__`` (HIGH-1),
nunca a nivel de módulo (correría en cada import y en los tests sin SDK).
"""

from __future__ import annotations

from pathlib import Path

_SERVER_PATH = Path(__file__).resolve().parent.parent / "kali_mcp_server.py"


def _source() -> str:
    return _SERVER_PATH.read_text(encoding="utf-8")


def test_tools_por_introspeccion_sincrona():
    source = _source()
    # Deriva de la API interna SÍNCRONA del tool manager.
    assert "mcp._tool_manager.list_tools()" in source
    # NO usa el FastMCP.list_tools público (async): no debe aparecer como `mcp.list_tools(`.
    assert "mcp.list_tools(" not in source


def test_lista_estatica_de_15_nombres_eliminada():
    source = _source()
    # La vieja lista estática enumeraba estas constantes como elementos de `tools`
    # (con coma final). Esa forma ya no debe existir en ningún sitio del servidor.
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
    # El marcador textual de la vieja lista inline (`"server_info",` como elemento) tampoco.
    assert '"server_info",' not in source


def test_bloque_plugins_en_server_info():
    source = _source()
    assert '"plugins": _plugins_block()' in source
    # El bloque usa el esquema cerrado leído de LAST_REPORT.
    assert "plugin_loader.LAST_REPORT" in source or "LAST_REPORT" in source


def test_load_plugins_bajo_guard_main_y_no_a_nivel_modulo():
    source = _source()
    assert 'if __name__ == "__main__":' in source
    guard_idx = source.index('if __name__ == "__main__":')
    # La invocación debe existir y estar DESPUÉS del guard (dentro del bloque __main__).
    call = "plugin_loader.load_plugins("
    assert call in source
    assert source.index(call) > guard_idx, "load_plugins no está bajo el guard __main__"
    # Y no debe haber una invocación a nivel de módulo (antes del guard).
    assert (
        source[:guard_idx].find(call) == -1
    ), "load_plugins se invoca a nivel de módulo"
