# Writing a kali-mcp plugin

Guide for plugin authors. For the details of discovery/loading and the two paths of the
`plugins/` tree, see [discovery.md](discovery.md).

## Structure of a plugin

A plugin is an **immediate subdirectory** of `plugins/` with, at minimum, a `plugin.py`:

```
plugins/
  mi-plugin/
    plugin.py          # obligatorio: PLUGIN_API, PLUGIN_NAME, register(ctx)
    vendor/            # opcional: dependencias de terceros empaquetadas
    skill/             # opcional: la skill que se copia al perfil de Hermes
      SKILL.md
    README.md          # recomendado
```

`plugin.py` must expose:

- `PLUGIN_API = 1` — version of the contract that the plugin implements. The loader
  requires **exact equality** with `plugin_api.SUPPORTED_PLUGIN_API`; if they do not match,
  the plugin is rejected in phase `api`.
- `PLUGIN_NAME = "mi-plugin"` — name of the plugin (for logs and `server_info`).
- `register(ctx)` — function that receives a `PluginContext` and declares tools, skill, and
  volumes through it.

## `register(ctx)`

It is the **only point** through which the plugin touches the server. It receives a
`PluginContext` already configured for the plugin's directory. Minimal example:

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

The example plugin `plugins/example-hello.disabled/` demonstrates the full contract and
serves as a template.

## `PluginContext` API

Fixed signatures, versioned with `PLUGIN_API = 1`:

- `ctx.tool(*args, **kwargs)` — **tool decorator with collision detection**. It resolves
  the target name (kwarg `name=` or `fn.__name__`) and queries the already-registered
  tools. If the name already exists, it does **not** delegate: it records the collision (the
  plugin ends up `degraded`) and returns the function untouched. If it does not exist, it
  delegates literally to `mcp.tool(*a, **k)` and records the name. If it cannot obtain the
  reliable list of names, the registration **fails** (it does not delegate blindly).
- `ctx.skill(path)` — declares the **single** skill of the plugin (path relative to the
  plugin's directory). It validates with `realpath` that the resolved path stays **under**
  the plugin's directory; if it escapes, it is ignored with a non-fatal warning. A second
  call is a contract error (at most one skill): it is ignored.
- `ctx.needs_volume(name)` — **only annotates** that the plugin needs a volume. It **does
  not mount or enable anything**; it is declarative for `server_info`.
- `ctx.plugin_dir()` — absolute path of the plugin's directory (always returns a path,
  whether it exists or not).
- `ctx.vendor_dir()` — absolute path of `<plugin_dir>/vendor` (always returns a path,
  whether it exists or not). **Contract**: it returns the path to `vendor/`; you decide
  whether it exists and whether to insert it into `sys.path`. It does not create the
  directory or verify its contents.

## Rule for PREFIXING modules (shadow in `sys.modules`)

The loader imports each `plugin.py` under a namespaced name (`vuln_plugin_<dir>`) and
inserts the plugin's directory into `sys.path` **only** while running its body, so that
`import <sibling>` resolves against the plugin's own directory.

Even so, the sibling modules you import (and any `vendor/` dependency) enter `sys.modules`
under their **name as is**. If two plugins (or a plugin and the core) use the same module
name, the second **shadows** the first in `sys.modules`. To avoid this, **prefix** the
names of your vendored modules and packages with something specific to the plugin (e.g.
`miplugin_utils` instead of `utils`). Do not assume that your `utils` is the one that gets
imported.

## The skill = directory name

The plugin's skill is copied into the Hermes profile under a directory **with the plugin's
name** (its directory name). It is the skills loop of the `ooda-agent` `command` in
`docker-compose.yml` that does the copy from the `/opt/plugins` bind-mount. Name the
plugin's directory carefully: it is also the name of its skill in Hermes.

## How to ship `vendor/` and `skill/`

- **`vendor/`**: package the plugin's third-party dependencies here. If you need Python to
  find them, insert `ctx.vendor_dir()` into `sys.path` **inside `register`** and remember
  the prefix rule. `vendor_dir()` does not add anything on its own.
- **`skill/`**: leave the skill's `SKILL.md` (and resources) here. Declare it with
  `ctx.skill(path="skill")`. It is copied to Hermes as described above; remember that this
  layer is **live** (bind-mount) and only needs a restart of `ooda-agent`, whereas the tools
  travel in the Kali's **frozen** image and need a rebuild (see
  [discovery.md](discovery.md)).

## Security posture (NIT-7)

A plugin's code runs with **full trust**: it runs in the **same process** as the kali-mcp
server, with its same privileges, **without a sandbox** and **without isolation** between
the plugin and the server. A plugin can do whatever the core does.

In addition, the Hermes profile **no longer whitelists** the Kali's tools
(`mcp_servers.kali.tools.include` was removed from `agent-ooda/profile/config.yaml`): the
**MCP server is the source of truth** and what the server exposes is what Hermes sees.
Therefore, a tool contributed by a third-party plugin enters Hermes's surface **without
passing through a gate**. Only install plugins of **known and reviewed origin**.

If you wanted to review tool by tool again, the way is to **manually re-add** an
`include:` with the exact whitelist of names (as the server exposes them) under
`mcp_servers.kali.tools` in the `config.yaml`. It is not set by default.

## `.disabled` as a single constant (NIT-6)

The suffix that turns off a plugin is `.disabled`, defined **only once** in the Python code
as `plugin_api.DISABLED_SUFFIX`. It is shared by the loader (tools layer) and the compose
skills loop (Hermes layer), and a parity test pins that they do not diverge. To turn off a
plugin, rename its directory by adding `.disabled`; to turn it on, remove it.

## How to test with a double `ctx`

The core tests do **not** import the `mcp` SDK nor the server: they use a **double** of
`mcp` that mimics the part of FastMCP's internal API that `PluginContext` touches —
`mcp.tool(*a, **k)` (decorator) and `mcp._tool_manager.list_tools()` (existing names). Follow
the same pattern for your plugin: build a `PluginContext` with that double and call your
`register(ctx)`, then assert on `ctx.tools`, `ctx.skill_path`, `ctx.volumes`, and
`ctx.collisions`. See `docker/kali/tests/test_plugin_api.py` and `test_example_hello.py` as
examples.
