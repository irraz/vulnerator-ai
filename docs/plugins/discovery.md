# Plugin discovery and loading

This document describes **how** the kali-mcp server discovers and loads plugins, and the
**two paths** by which the `plugins/` tree enters the stack. To write a plugin, see
[developing-plugins.md](developing-plugins.md).

## When they are loaded

Loading happens **only once, at server startup**, inside the
`if __name__ == "__main__":` guard of `docker/kali/kali_mcp_server.py`, BEFORE opening any
plane (data or control). It is never invoked at module level: that way `load_plugins` does
not run on every `import` of the server nor in the tests (which do not have the `mcp` SDK).
The call is:

```python
plugin_loader.load_plugins(mcp, os.environ.get("PLUGINS_DIR", "plugins"))
```

That is, the default plugins root is `plugins` **relative to the WORKDIR**
(`/opt/kali-mcp/plugins` inside the image), configurable with the `PLUGINS_DIR` environment
variable.

## Discovery order

The loader enumerates the **immediate subdirectories** of the plugins root in
**deterministic alphabetical order** (`sorted(os.listdir(...))`). A directory is a
candidate only if:

- it does not start with `.` (hidden ones are ignored);
- it does not end in `.disabled` (see below);
- it is a directory;
- it contains a `plugin.py` file.

The alphabetical order is stable across startups: two plugins that register tools in a
reproducible order will always see the same sequence.

## The `.disabled` suffix

A directory whose name ends in `.disabled` is **ignored entirely**. The suffix is a
**single constant** in the Python code: `plugin_api.DISABLED_SUFFIX = ".disabled"`
(NIT-6). That SAME string is shared by the plugin skills loop in the `ooda-agent` `command`
in `docker-compose.yml`, which skips `*.disabled` directories before copying their skill.
The `docker/kali/tests/test_disabled_parity.py` test pins that both layers use the same
suffix, so they cannot diverge (a plugin never ends up "off in one layer and alive in the
other").

To activate a plugin shipped disabled, remove the suffix from the directory name; to turn
it off again, add it back. (The impact of a rename on each path is detailed in "The two
paths" below.)

## Non-fatal errors (isolation)

Each plugin is processed inside its own `try/except`: **a broken plugin does not take down
the others or the server startup**. The loader applies a phased micro-algorithm and, on
each failure, records how far it got without propagating the exception:

- `name` — the directory name does not match the allowed regex.
- `import` — the body of `plugin.py` (or an `import` of a sibling module) raised.
- `api` — the plugin's `PLUGIN_API` is not compatible (exact equality with
  `SUPPORTED_PLUGIN_API` is required).
- `register-missing` — the plugin does not expose a callable `register(ctx)`.
- `register` — `register(ctx)` raised during its execution.

The full traceback goes to stdout/stderr; the report only stores `str(exc)` (a single
line).

## Rollback on `register` failure (NIT-8)

If `register(ctx)` raises **after** having registered one or more tools, the loader
**rolls back** those already-mounted tools (`mcp._tool_manager.remove_tool(name)`,
best-effort) so as not to leave orphan tools visible from a plugin that failed halfway. The
plugin is reported as `failed` in phase `register`.

## Synchronous introspection and the `server_info['plugins']` schema

`server_info` does **not** carry a static list of plugins: it reads the module singleton
`plugin_loader.LAST_REPORT`, which `load_plugins` publishes when its pass finishes (HIGH-1).
The introspection is **synchronous**: the report is already computed at startup, so
`server_info` only classifies it. If plugins were never loaded (e.g. in a bare `import` of
the module), `LAST_REPORT` starts empty and the block is coherent and empty — behavior
identical to today's.

The `plugins` block of `server_info` has a **closed schema** derived from the report: for
each discovered plugin it exposes its name, its `status` (`loaded` / `degraded` / `failed`),
the phase reached, the tools it registered, the declared skill, the annotated volumes, and
the detected collisions.

## The two paths of the `plugins/` tree (NIT-5)

The same versioned `plugins/` tree from the repo enters the stack through **two DIFFERENT
paths**, which **are not the same and must not be unified**:

1. **Frozen in the Kali image — `/opt/kali-mcp/plugins`.**
   The `Dockerfile` runs `COPY plugins/ ./plugins/` (onto the WORKDIR `/opt/kali-mcp`). It
   is the path that `load_plugins` reads to discover and load the plugin's **tools** in the
   kali-mcp server. Being copied at **build** time, it is **frozen**: enabling or disabling
   a plugin (adding it, removing it, or renaming its `.disabled`) requires **rebuilding the
   Kali image** for the change to take effect on the tools.

2. **Live by bind-mount in Hermes — `/opt/plugins`.**
   `docker-compose.yml` mounts `./plugins:/opt/plugins:ro` into the `ooda-agent` container.
   That service's `command` walks that path and copies each plugin's `skill/` into the
   Hermes profile's skills folder. Being a **live** bind-mount, a **restart of
   `ooda-agent`** (without a rebuild) is enough for a plugin's **skill** to be picked up or
   dropped.

Practical consequence: the **tools** layer (Kali, frozen) and the **skills** layer (Hermes,
live) are activated by different mechanisms. Do not unify the paths or assume that a single
change is enough for both: a new tool needs a rebuild of the Kali, and a new skill needs a
restart of `ooda-agent`.
