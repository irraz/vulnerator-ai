"""Fixture fase 'register' + NIT-8: registra una tool y luego LANZA.

El loader debe revertir la tool ya montada vía ``_tool_manager.remove_tool``.
"""

PLUGIN_API = 1


def register(ctx):
    @ctx.tool(name="partial_tool")
    def partial_tool():
        return "partial"

    raise RuntimeError("boom en register")
