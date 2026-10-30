# Descubrimiento y carga de plugins

Este documento describe **cómo** el servidor kali-mcp descubre y carga los plugins, y las
**dos rutas** por las que el árbol `plugins/` entra en el stack. Para escribir un plugin,
consulta [developing-plugins.md](developing-plugins.md).

## Cuándo se cargan

La carga ocurre **una sola vez, en el arranque del servidor**, dentro del guard
`if __name__ == "__main__":` de `docker/kali/kali_mcp_server.py`, ANTES de abrir ningún
plano (datos ni control). Nunca se invoca a nivel de módulo: así `load_plugins` no corre en
cada `import` del servidor ni en los tests (que no tienen el SDK `mcp`). La llamada es:

```python
plugin_loader.load_plugins(mcp, os.environ.get("PLUGINS_DIR", "plugins"))
```

Es decir, la raíz de plugins por defecto es `plugins` **relativa al WORKDIR**
(`/opt/kali-mcp/plugins` dentro de la imagen), configurable con la variable de entorno
`PLUGINS_DIR`.

## Orden de descubrimiento

El cargador enumera los **subdirectorios inmediatos** de la raíz de plugins en **orden
alfabético determinista** (`sorted(os.listdir(...))`). Un directorio es candidato solo si:

- no empieza por `.` (ocultos ignorados);
- no termina en `.disabled` (ver abajo);
- es un directorio;
- contiene un fichero `plugin.py`.

El orden alfabético es estable entre arranques: dos plugins que registren tools en un orden
reproducible verán siempre la misma secuencia.

## El sufijo `.disabled`

Un directorio cuyo nombre termina en `.disabled` se **ignora por completo**. El sufijo es
una **constante única** en el código Python: `plugin_api.DISABLED_SUFFIX = ".disabled"`
(NIT-6). Esa MISMA cadena la comparte el bucle de skills de plugins del `command` de
`ooda-agent` en `docker-compose.yml`, que salta los directorios `*.disabled` antes de
copiar su skill. El test `docker/kali/tests/test_disabled_parity.py` fija que ambas capas
usan el mismo sufijo, de modo que no pueden divergir (un plugin nunca queda "apagado en una
capa y vivo en la otra").

Para activar un plugin entregado deshabilitado, se quita el sufijo del nombre del
directorio; para volver a apagarlo, se reañade. (El impacto de un rename sobre cada ruta se
detalla en «Las dos rutas» más abajo.)

## Errores no fatales (aislamiento)

Cada plugin se procesa dentro de su propio `try/except`: **un plugin roto no tumba a los
demás ni al arranque del servidor**. El cargador aplica un micro-algoritmo por fases y, en
cada fallo, registra hasta dónde llegó sin propagar la excepción:

- `name` — el nombre del directorio no casa el regex permitido.
- `import` — el cuerpo de `plugin.py` (o un `import` de un módulo hermano) lanzó.
- `api` — el `PLUGIN_API` del plugin no es compatible (se exige igualdad exacta con
  `SUPPORTED_PLUGIN_API`).
- `register-missing` — el plugin no expone un `register(ctx)` invocable.
- `register` — `register(ctx)` lanzó durante su ejecución.

El traceback completo va a stdout/stderr; el reporte solo guarda `str(exc)` (una línea).

## Reversión en fallo de `register` (NIT-8)

Si `register(ctx)` lanza **después** de haber registrado una o más tools, el cargador
**revierte** esas tools ya montadas (`mcp._tool_manager.remove_tool(name)`, best-effort)
para no dejar tools huérfanas visibles de un plugin que falló a medias. El plugin se reporta
como `failed` en fase `register`.

## Introspección síncrona y esquema `server_info['plugins']`

`server_info` **no** lleva una lista estática de plugins: lee el singleton de módulo
`plugin_loader.LAST_REPORT`, que `load_plugins` publica al terminar su pasada (HIGH-1). La
introspección es **síncrona**: el reporte ya está calculado en el arranque, así que
`server_info` solo lo clasifica. Si nunca se cargaron plugins (p. ej. en un `import` suelto
del módulo), `LAST_REPORT` arranca vacío y el bloque es coherente y vacío — comportamiento
idéntico al de hoy.

El bloque `plugins` de `server_info` tiene un **esquema cerrado** derivado del reporte: por
cada plugin descubierto se expone su nombre, su `status` (`loaded` / `degraded` / `failed`),
la fase alcanzada, las tools que registró, la skill declarada, los volúmenes anotados y las
colisiones detectadas.

## Las dos rutas del árbol `plugins/` (NIT-5)

El mismo árbol versionado `plugins/` del repo entra en el stack por **dos rutas
DISTINTAS**, que **no son la misma y no deben unificarse**:

1. **Congelada en la imagen de Kali — `/opt/kali-mcp/plugins`.**
   El `Dockerfile` hace `COPY plugins/ ./plugins/` (sobre el WORKDIR `/opt/kali-mcp`). Es la
   ruta que lee `load_plugins` para descubrir y cargar las **tools** del plugin en el
   servidor kali-mcp. Al copiarse en **build**, queda **congelada**: activar o desactivar un
   plugin (añadirlo, quitarlo o renombrar su `.disabled`) exige **reconstruir la imagen de
   Kali** para que el cambio tenga efecto en las tools.

2. **Viva por bind-mount en Hermes — `/opt/plugins`.**
   `docker-compose.yml` monta `./plugins:/opt/plugins:ro` en el contenedor `ooda-agent`. El
   `command` de ese servicio recorre esa ruta y copia la `skill/` de cada plugin a la carpeta
   de skills del perfil de Hermes. Al ser un bind-mount **vivo**, basta un **reinicio de
   `ooda-agent`** (sin rebuild) para que la **skill** de un plugin se recoja o deje de
   recogerse.

Consecuencia práctica: la capa de **tools** (Kali, congelada) y la capa de **skills**
(Hermes, viva) se activan por mecanismos diferentes. No unifiques las rutas ni asumas que un
solo cambio basta para ambas: una tool nueva necesita rebuild de la Kali, y una skill nueva
necesita reinicio de `ooda-agent`.
