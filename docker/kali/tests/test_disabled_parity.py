"""Test de PARIDAD del sufijo .disabled entre las dos capas (NIT-6).

El sufijo que apaga un plugin vive en DOS sitios que NO deben divergir:
  - la capa Python: ``plugin_api.DISABLED_SUFFIX`` (lo usa ``plugin_loader`` para ignorar el
    directorio en el servidor kali-mcp);
  - la capa shell: el ``for`` de skills de plugins del ``command`` de ``ooda-agent`` en
    ``docker-compose.yml``, que salta los directorios ``*.disabled`` antes de copiar su skill.

Si una capa cambiara el sufijo y la otra no, un plugin quedaría "medio apagado" (apagado en
una capa y vivo en la otra). Este test fija que:
  1. ``plugin_api.DISABLED_SUFFIX == '.disabled'`` (fuente única del lado Python);
  2. el ``command`` de ``ooda-agent`` contiene la regla shell que salta ``*.disabled``,
     por INSPECCIÓN del texto fuente del compose (no se levanta el stack).

Restricción de entorno (igual que el resto del core): STDLIB PURA, sin importar el SDK
``mcp`` ni el servidor; ``plugin_api`` es STDLIB PURA y sí se puede importar.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PARENT))

import plugin_api  # noqa: E402

# Raíz del worktree = dos niveles por encima de docker/kali/.
_COMPOSE_PATH = _PARENT.parent.parent / "docker-compose.yml"


def test_disabled_suffix_es_punto_disabled():
    """La fuente única del lado Python es exactamente '.disabled'."""
    assert plugin_api.DISABLED_SUFFIX == ".disabled"


def test_compose_salta_disabled_en_el_bucle_de_skills():
    """El command de ooda-agent salta los plugins *.disabled con el MISMO sufijo."""
    source = _COMPOSE_PATH.read_text(encoding="utf-8")
    # La regla shell que apaga un plugin por nombre de directorio. Comparte el sufijo
    # '.disabled' con plugin_api.DISABLED_SUFFIX: ambas capas deben usar el mismo.
    assert 'case "$$name" in *.disabled) continue' in source
    # El sufijo del compose coincide literalmente con la constante del lado Python.
    assert f"*{plugin_api.DISABLED_SUFFIX})" in source


def test_bucle_de_skills_blindado():
    """El bucle de skills de plugins está blindado (no puede abortar el arranque)."""
    source = _COMPOSE_PATH.read_text(encoding="utf-8")
    # Gateado en que el directorio exista y ejecutado en un subshell con `set +e`.
    assert "if [ -d /opt/plugins ]; then (" in source
    assert "set +e;" in source
