# example-hello (example plugin, shipped DISABLED)

Example plugin that demonstrates the kali-mcp plugin contract end to end:

- Registers the **`hello`** tool, which is harmless: it returns `{"status": "done", "greeting":
  "hello, <name>"}` and does not touch the network, filesystem, or target.
- Declares a **skill** (`skill/SKILL.md`).
- Declares (only annotates) that it needs the **`kali-artifacts`** volume.

It ships inside a directory ending in `.disabled`, so **by default it is not loaded**:
neither the plugin loader nor the skills loop mounts it. The server behavior is identical
to not having this plugin.

## How to enable it

Rename the directory by removing the `.disabled` suffix:

```sh
mv plugins/example-hello.disabled plugins/example-hello
```

To disable it again, add the suffix back.

## Important after enabling/disabling

The `plugins/` tree is copied into the Kali image at **build time**, so for an enable
change to take effect you must **rebuild the Kali image**. The agent container (ooda-agent)
mounts the tree and reloads the skills when it **restarts**. The details of this flow (the
`./plugins:/opt/plugins:ro` bind-mount and the skills loop) are documented alongside the
runtime integration.
