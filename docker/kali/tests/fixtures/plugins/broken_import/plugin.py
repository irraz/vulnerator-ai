"""Phase 'import' fixture: imports a nonexistent module -> exec_module raises."""

import this_module_does_not_exist_anywhere  # noqa: F401

PLUGIN_API = 1


def register(ctx):  # pragma: no cover - never reached
    pass
