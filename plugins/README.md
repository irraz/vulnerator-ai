# plugins/

Árbol versionado de plugins del servidor kali-mcp. Este directorio **siempre debe
existir** en el repo: el `Dockerfile` hace `COPY plugins/ ./plugins/` y, sin un árbol
versionado, el build fallaría. Por eso este `README.md` lo mantiene presente aunque no
haya ningún plugin activo.

## Qué es un plugin

Un plugin es un subdirectorio inmediato de `plugins/` con, al menos, un `plugin.py` que
expone:

- `PLUGIN_API = 1` — versión del contrato que el plugin implementa.
- `PLUGIN_NAME = "<nombre>"` — nombre del plugin.
- `register(ctx)` — función que recibe un `PluginContext` y declara tools, skill y
  volúmenes a través de él.

El cargador descubre los subdirectorios en orden alfabético y, por cada uno con
`plugin.py`, ejecuta su `register(ctx)`. Consulta `docs/plugins/` para el detalle del
contrato y del descubrimiento.

## Postura de confianza

El código de un plugin se ejecuta **con la misma confianza que el core**: corre en el
mismo proceso del servidor, con sus mismos privilegios, sin sandbox. Añade aquí solo
plugins de origen conocido y revisado. No hay aislamiento entre un plugin y el servidor.

## Habilitar / deshabilitar un plugin

Un directorio cuyo nombre termina en `.disabled` se **ignora** por completo (ni el
cargador ni el resto del sistema lo montan). Para activar un plugin entregado
deshabilitado, **renombra el directorio quitando el sufijo `.disabled`**:

```sh
mv plugins/example-hello.disabled plugins/example-hello
```

Para deshabilitarlo de nuevo, vuelve a añadir el sufijo. Tras activar o desactivar un
plugin hay que reconstruir la imagen de Kali (el árbol `plugins/` se copia en build);
consulta el `README.md` del propio plugin de ejemplo para el recordatorio completo.

## Ejemplo entregado

`example-hello.disabled/` es un plugin de ejemplo entregado **deshabilitado**. Demuestra
el contrato completo (una tool inocua, una skill y la declaración de un volumen) sin
cambiar el comportamiento por defecto del servidor. Léelo como plantilla para escribir
plugins propios.
