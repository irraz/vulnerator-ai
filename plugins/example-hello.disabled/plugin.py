"""Plugin de EJEMPLO entregado DESHABILITADO (directorio ``*.disabled``).

Demuestra el contrato completo de ``PluginContext`` sin cambiar el comportamiento del
servidor: al vivir en un directorio ``.disabled`` ni el cargador ni el bucle de skills lo
montan, así que el default es idéntico a hoy. Para activarlo, renombra el directorio
quitando el sufijo ``.disabled`` (ver ``README.md`` de este plugin).

Registra una tool INOCUA (``hello``) que no toca red, filesystem ni target: solo devuelve
un saludo. Además declara una skill y un volumen para ejercitar el contrato entero.
"""

from __future__ import annotations

# Versión del contrato de plugin que este ejemplo implementa (debe casar con
# ``plugin_api.SUPPORTED_PLUGIN_API`` del core).
PLUGIN_API = 1

# Nombre del plugin, usado por el cargador y por ``server_info``.
PLUGIN_NAME = "example-hello"


def register(ctx):
    """Declara la tool, la skill y el volumen del plugin a través del ``ctx``.

    ``ctx`` es un ``PluginContext``: ``ctx.tool`` es un decorador con detección de
    colisión; ``ctx.skill`` declara la (única) skill; ``ctx.needs_volume`` anota un
    volumen (solo declarativo).
    """

    @ctx.tool()
    def hello(name: str = "world") -> dict:
        """Tool de ejemplo INOCUA: devuelve un saludo, sin efectos secundarios."""
        return {"status": "done", "greeting": f"hello, {name}"}

    # Declara la skill de ejemplo (directorio ``skill/`` relativo a este plugin).
    ctx.skill(path="skill")

    # Declara (solo anota) que el plugin usaría el volumen de artefactos de Kali.
    ctx.needs_volume("kali-artifacts")
