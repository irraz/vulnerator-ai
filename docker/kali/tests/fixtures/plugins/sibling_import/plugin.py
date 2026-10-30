"""Fixture MEDIUM-3: plugin.py que importa un HERMANO (``helper``) del mismo dir.

Si el ``sys.path`` insert del loader no estuviera, este ``import helper`` fallaría y el
plugin caería en fase 'import'. Con el insert, resuelve contra el propio directorio.
"""

import helper  # noqa: F401 - hermano del mismo dir del plugin

PLUGIN_API = 1


def register(ctx):
    @ctx.tool(name=helper.TOOL_NAME)
    def sibling_tool():
        return helper.VALUE
