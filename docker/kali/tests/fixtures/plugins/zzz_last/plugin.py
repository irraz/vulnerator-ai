"""Segundo plugin válido (fixture) para comprobar orden alfabético determinista."""

PLUGIN_API = 1


def register(ctx):
    @ctx.tool(name="zzz_tool")
    def zzz_tool():
        return "zzz"
