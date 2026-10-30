"""Fixture: dir ending in .disabled -> the loader IGNORES it (must not be loaded)."""

PLUGIN_API = 1


def register(ctx):  # pragma: no cover - never reached: the dir is disabled
    @ctx.tool(name="should_not_appear")
    def should_not_appear():
        return "nope"
