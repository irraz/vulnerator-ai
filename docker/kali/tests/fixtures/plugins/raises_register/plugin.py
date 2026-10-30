"""Phase 'register' + NIT-8 fixture: registers a tool and then RAISES.

The loader must roll back the already-mounted tool via ``_tool_manager.remove_tool``.
"""

PLUGIN_API = 1


def register(ctx):
    @ctx.tool(name="partial_tool")
    def partial_tool():
        return "partial"

    raise RuntimeError("boom en register")
