"""MEDIUM-3 fixture: plugin.py that imports a SIBLING (``helper``) from the same dir.

If the loader's ``sys.path`` insert were not there, this ``import helper`` would fail and the
plugin would fall into phase 'import'. With the insert, it resolves against its own directory.
"""

import helper  # noqa: F401 - sibling from the plugin's own dir

PLUGIN_API = 1


def register(ctx):
    @ctx.tool(name=helper.TOOL_NAME)
    def sibling_tool():
        return helper.VALUE
