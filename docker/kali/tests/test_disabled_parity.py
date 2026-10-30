"""PARITY test of the .disabled suffix between the two layers (NIT-6).

The suffix that turns off a plugin lives in TWO places that must NOT diverge:
  - the Python layer: ``plugin_api.DISABLED_SUFFIX`` (``plugin_loader`` uses it to ignore the
    directory in the kali-mcp server);
  - the shell layer: the plugin skills ``for`` of the ``ooda-agent`` ``command`` in
    ``docker-compose.yml``, which skips ``*.disabled`` directories before copying their skill.

If one layer changed the suffix and the other did not, a plugin would end up "half off" (off
in one layer and alive in the other). This test pins that:
  1. ``plugin_api.DISABLED_SUFFIX == '.disabled'`` (single source on the Python side);
  2. the ``ooda-agent`` ``command`` contains the shell rule that skips ``*.disabled``, by
     INSPECTION of the compose source text (the stack is not brought up).

Environment constraint (like the rest of the core): PURE STDLIB, without importing the
``mcp`` SDK or the server; ``plugin_api`` is PURE STDLIB and can indeed be imported.
"""

from __future__ import annotations

import sys
from pathlib import Path

_PARENT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PARENT))

import plugin_api  # noqa: E402

# Worktree root = two levels above docker/kali/.
_COMPOSE_PATH = _PARENT.parent.parent / "docker-compose.yml"


def test_disabled_suffix_es_punto_disabled():
    """The single source on the Python side is exactly '.disabled'."""
    assert plugin_api.DISABLED_SUFFIX == ".disabled"


def test_compose_salta_disabled_en_el_bucle_de_skills():
    """The ooda-agent command skips *.disabled plugins with the SAME suffix."""
    source = _COMPOSE_PATH.read_text(encoding="utf-8")
    # The shell rule that turns off a plugin by directory name. It shares the '.disabled'
    # suffix with plugin_api.DISABLED_SUFFIX: both layers must use the same one.
    assert 'case "$$name" in *.disabled) continue' in source
    # The compose suffix matches the Python-side constant literally.
    assert f"*{plugin_api.DISABLED_SUFFIX})" in source


def test_bucle_de_skills_blindado():
    """The plugin skills loop is shielded (it cannot abort startup)."""
    source = _COMPOSE_PATH.read_text(encoding="utf-8")
    # Gated on the directory existing and run in a subshell with `set +e`.
    assert "if [ -d /opt/plugins ]; then (" in source
    assert "set +e;" in source
