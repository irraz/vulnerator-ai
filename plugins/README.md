# plugins/

Versioned tree of kali-mcp server plugins. This directory **must always exist** in the
repo: the `Dockerfile` runs `COPY plugins/ ./plugins/`, and without a versioned tree the
build would fail. That is why this `README.md` keeps it present even when there is no
active plugin.

## What a plugin is

A plugin is an immediate subdirectory of `plugins/` with, at minimum, a `plugin.py` that
exposes:

- `PLUGIN_API = 1` — version of the contract that the plugin implements.
- `PLUGIN_NAME = "<name>"` — name of the plugin.
- `register(ctx)` — function that receives a `PluginContext` and declares tools, skill, and
  volumes through it.

The loader discovers the subdirectories in alphabetical order and, for each one with a
`plugin.py`, runs its `register(ctx)`. See `docs/plugins/` for the details of the contract
and discovery.

## Trust posture

A plugin's code runs **with the same trust as the core**: it runs in the same server
process, with its same privileges, without a sandbox. Only add plugins of known and
reviewed origin here. There is no isolation between a plugin and the server.

## Enable / disable a plugin

A directory whose name ends in `.disabled` is **ignored** entirely (neither the loader nor
the rest of the system mounts it). To activate a plugin shipped disabled, **rename the
directory by removing the `.disabled` suffix**:

```sh
mv plugins/example-hello.disabled plugins/example-hello
```

To disable it again, add the suffix back. After enabling or disabling a plugin you must
rebuild the Kali image (the `plugins/` tree is copied at build time); see the example
plugin's own `README.md` for the full reminder.

## Shipped example

`example-hello.disabled/` is an example plugin shipped **disabled**. It demonstrates the
full contract (a harmless tool, a skill, and a volume declaration) without changing the
server's default behavior. Read it as a template for writing your own plugins.
