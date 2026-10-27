# Driving a pentest

Three ways to pilot an engagement, from simplest to most programmatic. All of them drive the same
OODA loop; pick by how you work.

## 1. Interactive TUI (`hermes chat`)

```sh
docker compose up -d --build
docker compose exec -it ooda-agent hermes chat
```

`hermes chat` opens the agent's REPL. Ask for a pentest in natural language; Hermes drives the OODA
and runs tools on Kali directly via `kali_run` (talking to `kali:8900`). The container's command
`hermes gateway run` also keeps Hermes' API server alive on `:8642`, which powers ways 2 and 3.

## 2. From an MCP client — recommended for assistants

If your tooling speaks **MCP** (Claude Code, Kiro, Cursor, BugTraceAI, …), the stack ships
**`vulnerator-mcp`** (`docker/mcp/`): a thin MCP server that wraps Hermes' runs API and exposes it
as MCP tools. It wraps, it does **not** replace, the HTTP API — it exposes **only** the runs
lifecycle, so the client stays a trigger/observer and never the brain. It never exposes
`/v1/chat/completions` or any raw `kali_run`.

**Five tools + a health check**, mapped 1:1 onto the runs API:

| Tool | Does |
| --- | --- |
| `start_pentest(input, scope, …)` | starts a run; returns `{run_id, status, replayed}` |
| `get_run_status(run_id)` | the full run object (status + `completed`/`partial`/`interrupted` + output + usage) |
| `stream_run_events(run_id, cursor, …)` | pages the lifecycle events with a `seq` cursor (`{events, next_cursor, done}`); also emits one MCP progress notification per page over streamable-HTTP |
| `steer_run(run_id, input)` | injects a correction mid-run; surfaces the `409 run_not_accepting_steer` verbatim |
| `stop_run(run_id)` | stops the run; returns the full run object |
| `health()` | upstream health (`{status, platform, version}`) |

Event/status/output payloads are forwarded verbatim as **untrusted data** (never interpreted).

### Local — stdio (recommended for Claude Code / Kiro)

Zero network surface: the client spawns the server as a subprocess over stdin/stdout — no listener,
no token, no port. Build the image once and add an `mcpServers` entry:

```sh
docker build -f docker/mcp/Dockerfile -t vulnerator-ai-mcp:dev .
```

```json
{
  "mcpServers": {
    "vulnerator-mcp": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--add-host", "host.docker.internal:host-gateway",
        "-e", "HERMES_API_SERVER_KEY",
        "-e", "HERMES_API_BASE_URL=http://host.docker.internal:8642",
        "vulnerator-ai-mcp:dev"
      ],
      "env": { "HERMES_API_SERVER_KEY": "<your HERMES_API_SERVER_KEY>" }
    }
  }
}
```

The upstream Bearer is a pass-through of `HERMES_API_SERVER_KEY` (no second secret for the hop). On
Docker Desktop `host.docker.internal` resolves out of the box; on stock Linux the `--add-host`
above is what makes it resolve (or point `HERMES_API_BASE_URL` at the host's reachable address).

### In-docker / remote — streamable-HTTP (up by default)

The streamable-HTTP service is part of the default stack, reachable on the internal network at
`http://vulnerator-mcp:8700` (an in-docker consumer like a BugTraceAI container reaches it there
with no extra steps). It is **fail-closed** on `VULNERATOR_MCP_INBOUND_TOKEN` (`docker compose up`
aborts without it) and every request must carry `Authorization: Bearer <VULNERATOR_MCP_INBOUND_TOKEN>`
(the `/healthz` route is the one exception). Host publication is **off by default** — set
`VULNERATOR_MCP_HOST_PORT` and uncomment the service's `ports:` block in `docker-compose.yml` to
publish on a controlled machine. See [`security.md`](security.md) for the threat model.

## 3. Raw HTTP API (`:8642`)

For CI scripts or plain `curl`, Hermes exposes an OpenAI-compatible API server directly on `:8642`
(the same endpoints `vulnerator-mcp` wraps). Full reference — access modes, the runs flow,
`chat/completions`, and the request/response contract — in [`http-api.md`](http-api.md).

# Recon & fingerprint tools

The Kali MCP server (`kali-mcp`) ships two dedicated recon tools alongside the raw shell
(`kali_run`/`kali_exec`). They are **blocking** tools: one call in, structured result out — no
`started → poll` dance. `server_info` reports which binaries are present (`recon_tools`) and
whether the DNSDumpster key is set (`dnsdumpster_key_present`).

## `dns_recon` — DNS + attack surface (DNSDumpster API)

Given a domain, enumerates its attack surface in one call: subdomains/hosts, **unique IPs**,
ASN/PTR and HTTP/HTTPS banners, plus TXT records. It is the usual first recon step — its IPs and
hosts feed the downstream fan-out (e.g. `webtech_scan` per live host).

- **Key:** set `DNSDUMPSTER_API_KEY` in `.env` (free key at <https://dnsdumpster.com/>; the
  installer offers to store it). Without a key the tool fails fail-closed and says so.
- **Rate limit:** the API allows 1 request / 2 s; the client throttles internally and retries once
  on HTTP 429, so paginating (`max_pages`) or fetching banners (`with_banners`) needs no manual
  sleeps. Free tier returns up to 50 records/domain; pagination beyond 200 needs a Plus plan.
- **Returns:** `{status, domain, pages, surface:{hosts, ips, cidrs, txt, counts}, banners?, warnings?}`.
  The API response is untrusted data — it is normalized in shape, never interpreted.

## `webtech_scan` — technology/version fingerprint by cross-reference

Runs **whatweb + webanalyze + wpscan** against a URL and **merges** what each one sees into a single
`technology → {versions per source, sources, best_version, version_conflict}` table. Cross-checking
three detectors raises confidence in a component's version and flags disagreements
(`version_conflict`) — a useful signal before choosing a version-dependent exploit.

- **Optional binaries, no faking:** any tool missing from the image is skipped and listed under
  `skipped` (the image installs all three). `wpscan` only contributes on WordPress; on a non-WP
  site it reports `wpscan.is_wordpress=false` **as a normal result, not an error**.
- **WPScan token (optional):** set `WPSCAN_API_TOKEN` in `.env` to add known-vulnerability (CVE)
  data; wpscan still enumerates core/plugin/theme versions without it.
- **Wappalyzer note:** the official Wappalyzer CLI is discontinued, so the Wappalyzer *fingerprint
  engine* is provided via [`webanalyze`](https://github.com/rverton/webanalyze) (Go port). Its
  fingerprint DB lives at `/opt/webanalyze/technologies.json` in the image.
- **Cross-reference caveat:** merging is by (normalized) technology name. whatweb and webanalyze use
  different naming vocabularies for some techs (e.g. whatweb encodes a CMS inside `MetaGenerator`'s
  value while webanalyze names the app directly), so not every detection auto-merges between those
  two. The cross-reference is most valuable where tools share a name (jQuery, nginx, PHP, WordPress,
  …) and for surfacing version conflicts.

# Practice against a lab target (Juice Shop)

To practice the `web-pentest` skill without going out to the internet or touching real systems,
the repo ships an **optional** target override, `docker-compose.target.yml`, that adds an
[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) service. Juice Shop is a
**deliberately-vulnerable** web application (OWASP project), the de facto standard for practicing
web pentesting (XSS, SQLi, broken auth, etc.).

The installer can bring it up for you:

```sh
./install.sh --with-juice-shop
```

Or layer both compose files by hand:

```sh
docker compose -f docker-compose.yml -f docker-compose.target.yml up -d --build
```

The target joins the **same internal docker network** and publishes **no port to the host**, so it
only exists inside the docker environment — scoping the exercise to a controlled lab. Hermes/Kali
reach it by its DNS name at **`http://juice-shop:3000`**. Point an engagement at that URL, e.g. via
the interactive TUI:

```sh
docker compose -f docker-compose.yml -f docker-compose.target.yml exec -it ooda-agent hermes chat
# then ask, in natural language:
#   "Authorized web pentest against http://juice-shop:3000 (scope: that host only).
#    Enumerate, fingerprint, and test for injection/auth flaws. Report confirmed findings."
```

This is the authorized target for practicing the `web-pentest` skill. Only the web lab is in scope
here (no AD or other labs for now).

# Start clean between exercises

So that each pentest starts without remembering anything from the previous one (conversation history
and Hermes' memory), bring the stack up from scratch. The cleanest and most deterministic way:

```sh
docker compose down -v   # stops the containers and DELETES Hermes' state volume
docker compose up -d     # starts with fresh state (the profile regenerates from agent-ooda/)
```

In a single line:

```sh
docker compose down -v && docker compose up -d
```

## What is deleted and what is kept

The `-v` flag deletes the named volume `hermes-data` (`/opt/data`), where Hermes' state
lives: the profile and its SQLite (`state.db`). That is where the history/memory you want to
forget between exercises resides. You don't lose configuration: the profile (`config.yaml`, `SOUL.md`,
`skills`) **regenerates** on each startup by copying the declarative template from `agent-ooda/`.

| What | Does it survive `down -v` + `up`? |
|---|---|
| Tools baked into the image by the Kali `Dockerfile` | **Yes** |
| Packages Hermes installed on the fly during a pentest | **No** (ephemeral layer of the `kali` container) |
| Hermes' state / memory / history (`hermes-data`) | **No** (exactly what `-v` deletes) |

Notes:

- The `kali` container **has no volume**: anything installed on the fly (e.g. an
  `apt install` Hermes does mid-engagement) lives in the container's ephemeral layer and
  disappears on the next `down`/`up`. If you want a tool to always be
  available without reinstalling it every session, **add it to the Kali `Dockerfile`** so
  it is baked into the image.
- To lose only the Kali packages you don't need `-v`: a plain `docker compose down`
  already recreates the `kali` container from the image. The `-v` adds the deletion of Hermes'
  state.
- `docker compose restart` does **not** recreate the containers, so it keeps both Hermes'
  state and whatever was installed on the fly in the Kali: it is not useful for starting clean.

## Alternative: new session without deleting the volume

If you prefer to keep the history but work in a clean conversation, open a
session with a new name instead of reusing the default one:

```sh
docker compose exec -it ooda-agent hermes chat --continue <new-session-name>
```

This does not delete the previous memory; it just avoids dragging it into the new conversation.
