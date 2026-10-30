"""Second valid plugin (fixture) to check deterministic alphabetical order."""

PLUGIN_API = 1


def register(ctx):
    @ctx.tool(name="zzz_tool")
    def zzz_tool():
        return "zzz"
