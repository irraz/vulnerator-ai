"""Fixture: dir terminado en .disabled -> el loader lo IGNORA (no debe cargarse)."""

PLUGIN_API = 1


def register(ctx):  # pragma: no cover - nunca se alcanza: el dir está deshabilitado
    @ctx.tool(name="should_not_appear")
    def should_not_appear():
        return "nope"
