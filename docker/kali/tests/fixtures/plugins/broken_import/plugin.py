"""Fixture fase 'import': importa un módulo inexistente -> exec_module lanza."""

import this_module_does_not_exist_anywhere  # noqa: F401

PLUGIN_API = 1


def register(ctx):  # pragma: no cover - nunca se alcanza
    pass
