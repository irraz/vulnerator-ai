"""EXAMPLE plugin shipped DISABLED (``*.disabled`` directory).

It demonstrates the full ``PluginContext`` contract without changing the server's behavior:
by living in a ``.disabled`` directory, neither the loader nor the skills loop mounts it, so
the default is identical to today. To activate it, rename the directory by removing the
``.disabled`` suffix (see this plugin's ``README.md``).

It registers a HARMLESS tool (``hello``) that does not touch the network, filesystem, or
target: it only returns a greeting. It also declares a skill and a volume to exercise the
entire contract.
"""

from __future__ import annotations

# Version of the plugin contract that this example implements (must match the core's
# ``plugin_api.SUPPORTED_PLUGIN_API``).
PLUGIN_API = 1

# Name of the plugin, used by the loader and by ``server_info``.
PLUGIN_NAME = "example-hello"


def register(ctx):
    """Declares the plugin's tool, skill, and volume through ``ctx``.

    ``ctx`` is a ``PluginContext``: ``ctx.tool`` is a decorator with collision detection;
    ``ctx.skill`` declares the (single) skill; ``ctx.needs_volume`` annotates a volume (only
    declarative).
    """

    @ctx.tool()
    def hello(name: str = "world") -> dict:
        """HARMLESS example tool: returns a greeting, with no side effects."""
        return {"status": "done", "greeting": f"hello, {name}"}

    # Declares the example skill (``skill/`` directory relative to this plugin).
    ctx.skill(path="skill")

    # Declares (only annotates) that the plugin would use the Kali artifacts volume.
    ctx.needs_volume("kali-artifacts")
