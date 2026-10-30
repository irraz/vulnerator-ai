# example-hello (plugin de ejemplo, entregado DESHABILITADO)

Plugin de ejemplo que demuestra el contrato de plugins de kali-mcp de principio a fin:

- Registra la tool **`hello`**, inocua: devuelve `{"status": "done", "greeting":
  "hello, <name>"}` y no toca red, filesystem ni target.
- Declara una **skill** (`skill/SKILL.md`).
- Declara (solo anota) que necesita el volumen **`kali-artifacts`**.

Se entrega dentro de un directorio terminado en `.disabled`, por lo que **por defecto no
se carga**: ni el cargador de plugins ni el bucle de skills lo montan. El comportamiento
del servidor es idéntico a no tener este plugin.

## Cómo activarlo

Renombra el directorio quitando el sufijo `.disabled`:

```sh
mv plugins/example-hello.disabled plugins/example-hello
```

Para deshabilitarlo de nuevo, vuelve a añadir el sufijo.

## Importante tras activar/desactivar

El árbol `plugins/` se copia dentro de la imagen de Kali en **tiempo de build**, de modo
que para que un cambio de activación surta efecto hay que **reconstruir la imagen de
Kali**. El contenedor del agente (ooda-agent) monta el árbol y recarga las skills al
**reiniciarse**. El detalle de este flujo (bind-mount `./plugins:/opt/plugins:ro` y el
bucle de skills) se documenta junto a la integración de runtime.
