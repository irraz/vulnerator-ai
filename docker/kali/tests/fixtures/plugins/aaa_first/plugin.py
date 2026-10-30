"""Plugin válido mínimo (fixture). Registra una tool y declara su skill."""

PLUGIN_API = 1


def register(ctx):
    @ctx.tool(name="aaa_tool")
    def aaa_tool():
        return "aaa"

    ctx.skill("skill.md")
    ctx.needs_volume("aaa-vol")
