# Escribir un plugin de kali-mcp

Guía para autores de plugins. Para el detalle del descubrimiento/carga y de las dos rutas
del árbol `plugins/`, consulta [discovery.md](discovery.md).

## Estructura de un plugin

Un plugin es un **subdirectorio inmediato** de `plugins/` con, al menos, un `plugin.py`:

```
plugins/
  mi-plugin/
    plugin.py          # obligatorio: PLUGIN_API, PLUGIN_NAME, register(ctx)
    vendor/            # opcional: dependencias de terceros empaquetadas
    skill/             # opcional: la skill que se copia al perfil de Hermes
      SKILL.md
    README.md          # recomendado
```

`plugin.py` debe exponer:

- `PLUGIN_API = 1` — versión del contrato que el plugin implementa. El cargador exige
  **igualdad exacta** con `plugin_api.SUPPORTED_PLUGIN_API`; si no casan, el plugin se
  rechaza en fase `api`.
- `PLUGIN_NAME = "mi-plugin"` — nombre del plugin (para logs y `server_info`).
- `register(ctx)` — función que recibe un `PluginContext` y declara tools, skill y
  volúmenes a través de él.

## `register(ctx)`

Es el **único punto** por el que el plugin toca el servidor. Recibe un `PluginContext` ya
configurado para el directorio del plugin. Ejemplo mínimo:

```python
from __future__ import annotations

PLUGIN_API = 1
PLUGIN_NAME = "mi-plugin"


def register(ctx):
    @ctx.tool()
    def hello(name: str = "world") -> dict:
        """Tool de ejemplo inocua."""
        return {"status": "done", "greeting": f"hello, {name}"}

    ctx.skill(path="skill")
    ctx.needs_volume("kali-artifacts")
```

El plugin de ejemplo `plugins/example-hello.disabled/` demuestra el contrato completo y
sirve de plantilla.

## API de `PluginContext`

Firmas fijas, versionadas con `PLUGIN_API = 1`:

- `ctx.tool(*args, **kwargs)` — **decorador de tool con detección de colisión**. Resuelve el
  nombre objetivo (kwarg `name=` o `fn.__name__`) y consulta las tools ya registradas. Si el
  nombre ya existe, **no** delega: anota la colisión (el plugin queda `degraded`) y devuelve
  la función intacta. Si no existe, delega literalmente en `mcp.tool(*a, **k)` y anota el
  nombre. Si no puede obtener la lista fiable de nombres, el registro **falla** (no delega a
  ciegas).
- `ctx.skill(path)` — declara la **única** skill del plugin (ruta relativa al directorio del
  plugin). Valida con `realpath` que la ruta resuelta queda **bajo** el directorio del
  plugin; si escapa, se ignora con un warning no fatal. Una segunda llamada es un error de
  contrato (máximo una skill): se ignora.
- `ctx.needs_volume(name)` — **solo anota** que el plugin necesita un volumen. **No monta ni
  habilita nada**; es declarativo para `server_info`.
- `ctx.plugin_dir()` — ruta absoluta del directorio del plugin (siempre devuelve ruta,
  exista o no).
- `ctx.vendor_dir()` — ruta absoluta de `<plugin_dir>/vendor` (siempre devuelve ruta, exista
  o no). **Contrato**: devuelve la ruta a `vendor/`; tú decides si existe y si la insertas en
  `sys.path`. No crea el directorio ni verifica su contenido.

## Regla de PREFIJAR módulos (sombra en `sys.modules`)

El cargador importa cada `plugin.py` bajo un nombre namespaced (`vuln_plugin_<dir>`) e
inserta el directorio del plugin en `sys.path` **solo** mientras ejecuta su cuerpo, para que
`import <hermano>` resuelva contra el propio directorio del plugin.

Aun así, los módulos hermanos que importes (y cualquier dependencia de `vendor/`) entran en
`sys.modules` por su **nombre tal cual**. Si dos plugins (o un plugin y el core) usan el
mismo nombre de módulo, el segundo **sombrea** al primero en `sys.modules`. Para evitarlo,
**prefija** los nombres de tus módulos y paquetes vendorizados con algo propio del plugin
(p. ej. `miplugin_utils` en vez de `utils`). No asumas que tu `utils` es el que se importa.

## La skill = nombre del directorio

La skill del plugin se copia al perfil de Hermes bajo un directorio **con el nombre del
plugin** (el nombre de su directorio). Es el bucle de skills del `command` de `ooda-agent`
en `docker-compose.yml` quien hace la copia desde el bind-mount `/opt/plugins`. Nombra el
directorio del plugin con cuidado: es también el nombre de su skill en Hermes.

## Cómo entregar `vendor/` y `skill/`

- **`vendor/`**: empaqueta aquí las dependencias de terceros del plugin. Si necesitas que
  Python las encuentre, inserta `ctx.vendor_dir()` en `sys.path` **dentro de `register`** y
  recuerda la regla de prefijos. `vendor_dir()` no añade nada por sí solo.
- **`skill/`**: deja aquí el `SKILL.md` (y recursos) de la skill. Declárala con
  `ctx.skill(path="skill")`. Se copia a Hermes como se describe arriba; recuerda que esa capa
  es **viva** (bind-mount) y solo necesita reinicio de `ooda-agent`, mientras que las tools
  viajan en la imagen **congelada** de la Kali y necesitan rebuild (ver
  [discovery.md](discovery.md)).

## Postura de seguridad (NIT-7)

El código de un plugin se ejecuta con **confianza plena**: corre en el **mismo proceso** del
servidor kali-mcp, con sus mismos privilegios, **sin sandbox** y **sin aislamiento** entre
el plugin y el servidor. Un plugin puede hacer lo que haga el core.

Además, el perfil de Hermes **ya no hace whitelist** de las tools de la Kali (se retiró
`mcp_servers.kali.tools.include` de `agent-ooda/profile/config.yaml`): el **servidor MCP es
la fuente de verdad** y lo que el servidor expone es lo que Hermes ve. Por tanto, una tool
aportada por un plugin de terceros entra en la superficie de Hermes **sin pasar por un
gate**. Instala únicamente plugins de **origen conocido y revisado**.

Si quisieras volver a revisar tool por tool, la vía es **reañadir manualmente** una
`include:` con la whitelist exacta de nombres (tal como los expone el servidor) bajo
`mcp_servers.kali.tools` en el `config.yaml`. No está puesta por defecto.

## `.disabled` como constante única (NIT-6)

El sufijo que apaga un plugin es `.disabled`, definido **una sola vez** en el código Python
como `plugin_api.DISABLED_SUFFIX`. Lo comparten el cargador (capa de tools) y el bucle de
skills del compose (capa de Hermes), y un test de paridad fija que no diverjan. Para apagar
un plugin, renombra su directorio añadiendo `.disabled`; para encenderlo, quítalo.

## Cómo testear con un `ctx` doble

Los tests del core **no** importan el SDK `mcp` ni el servidor: usan un **doble** de `mcp`
que imita la parte de la API interna de FastMCP que `PluginContext` toca —`mcp.tool(*a, **k)`
(decorador) y `mcp._tool_manager.list_tools()` (nombres existentes)—. Sigue el mismo patrón
para tu plugin: construye un `PluginContext` con ese doble y llama a tu `register(ctx)`,
luego afirma sobre `ctx.tools`, `ctx.skill_path`, `ctx.volumes` y `ctx.collisions`.
Consulta `docker/kali/tests/test_plugin_api.py` y `test_example_hello.py` como ejemplos.
