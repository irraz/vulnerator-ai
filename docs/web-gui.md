# vulnerator-web — Vulnerator's web GUI

`vulnerator-web` is the operator console of the OODA loop: a fifth container, up by default, served at
**http://localhost:9100**. It shows what the agent is doing while it does it, keeps a per-run trace of
every tool call, and turns each confirmed finding into a replayable PoC.

It is an **observer**. It reads Hermes' session API and Caido's history; it never launches, steers or
stops a run. Driving an engagement stays where it was (TUI, Webapp, `:8642` runs API, or the
`vulnerator` MCP front door).

## Views

| View | What it shows |
|---|---|
| **Terminal** | The live loop: every `OODA — <PHASE> (step N)` status line (colored by phase), reasoning, the assistant's comments, each tool call with its command and its output, with a running timer until the result lands. Filters for reasoning / output / comments; "see all" fetches the full output of a long result. |
| **Copilot** | *Right now*: current OODA phase and step, the tools running at this moment with elapsed time, the last reasoning. Below: the tool timeline, the browser actions (playwright: navigate / click / type and the page they landed on), the HTTP traffic seen by **Caido** (method, status, URL, latency, size), and this session's findings. |
| **Traces** | Langfuse-style view of the run, kept in the GUI's own SQLite store: KPIs (tool calls, time in tools, errors, window, tokens, cost), a **waterfall** of every tool call (start relative to the first step, width = duration, color = tool family, red = error, striped green = running) and a per-tool table (calls, total, mean, max, errors). Click a row for its arguments, result, timings and OODA phase. |
| **PoC** | One entry per `record_finding`. For each: whether the findings store **accepted** or **rejected** it, the **OODA path** that led to it, the steps executed before it, and a **terminal replay** of the reproduction. When the evidence command matches a real `kali_run`/`kali_exec` of the session, the replay uses that execution's real output, exit code and duration instead of what the agent pasted. Download as asciinema `.cast` or Markdown. |
| **Screens** | Live screens for demos, in one place: a feed of **Hermes' actions** (every tool call with args/result, OODA line, reasoning); the **agent's browser** (the visible Chromium, via noVNC — watch it navigate, click and type); and **Caido operated live** by the `caido-director` (its UI moves on its own, re-enacting each `caido_*` action — opens the Replay session, types the HTTPQL filter, opens the packet). Each screen embeds in place, opens in a new tab, or goes fullscreen to project. Browser and director are view-only. |
| **Hermes** | Links to (and optional embed of) the Hermes **Dashboard** (`:9119`, Kanban, sessions, config) and **Webapp** (`:9120`, the Desktop workspace), with a live "online / unavailable" probe. |

Confirmed PoCs that the store accepted are **recorded automatically** to the `vulnerator-web-data`
volume (`/data/pocs/<session>/<finding>.cast|.md`) the moment the result arrives.

## Live screens (the "Screens" tab)

For presentations, the console can show what the agent does with its visual tools, in real time:

- **Agent browser** — a dedicated `browser-view` container runs a *visible* Chromium (Xvfb + x11vnc +
  **noVNC**). `playwright-mcp` no longer launches its own headless browser; it drives this one over CDP
  (`--cdp-endpoint`), through a tiny in-container proxy that rewrites the `Host` header so Chrome's
  anti-DNS-rebinding accepts the connection. The agent navigates exactly as before — only now it is on
  screen. The browser's debug port is never published; only noVNC (`:6080`) reaches the host.
- **Caido pre-authenticated as guest** — `vulnerator-web` reverse-proxies the internal Caido and
  injects a guest token (and bridges its GraphQL WebSocket), so Caido opens straight on the HTTP
  history with no login and no onboarding. This is handled in code (`caido_proxy.py`) and survives
  wiping Caido's volume. Whoever wants their own Caido account sets it at install time
  (`CAIDO_PAT`). The "Abrir ↗" button on the Caido screen opens this interactive real Caido.
- **Caido director (the Caido screen in Screens)** — the `caido-director` container runs its own
  *visible* Chromium on that pre-authenticated Caido UI and a controller (Playwright over CDP) that
  **subscribes to the console's event stream and re-enacts each `caido_*` action of the agent in the
  UI**: navigates to Replay/Automate/Intercept/HTTP History, types the HTTPQL filter, opens the
  session/packet, etc. The **data is real** (the agent's actual Caido calls); the UI walkthrough is
  choreographed by the director. It moves at the agent's pace (each action is an LLM inference,
  ~30-60 s), shown via noVNC and embedded as the Caido screen.
- **Making Caido show traffic** — set `BROWSER_VIEW_PROXY=http://caido:8080` (the visible browser's
  traffic goes through Caido) and `CAIDO_PROXY_CAPTURE=1` (kali HTTP tools too) in `.env`. For HTTPS
  targets the visible browser uses `--ignore-certificate-errors` (Caido MITMs TLS with its own CA).

Both are observers and opt-in; the browser is **view-only** by default (`BROWSER_VIEW_VIEWONLY=1`), so an
audience watches without taking control. "Fullscreen" projects a single screen.

To revert to the self-contained headless browser: in `docker-compose.yml` restore `playwright-mcp`'s
launch flags (`--headless/--browser/--no-sandbox/--isolated`), drop `--cdp-endpoint` and its
`depends_on`, and stop the `browser-view` service. The Caido embed is independent of this.

## Where the data comes from

```
Hermes :8642  GET /api/sessions (+ subagents)  ─┐
              GET /api/sessions/{id}/messages   ├─► ingest ─► SQLite (sessions · events · spans) ─► /api/* + SSE /api/stream ─► browser / vulnerator_watch
Caido  :8080  requests history (guest session) ─┘
```

* Hermes persists each tool call **before** running it and its result right after (Hermes ≥ 0.23,
  `agent/turn_tool_round.py`), so polling the session messages (every 1.5 s by default) shows a tool
  as *running* while it runs. Every session is covered, whatever started it.
* Each event gets the OODA phase/step of the last status line seen in the session, so tool calls,
  spans and findings are tagged with the phase they happened in.
* A span opens with the tool call and closes with its result (duration = result time − call time).
* Caido traffic includes whatever goes through its proxy: `caido_request`, and `kali_run` HTTP
  clients when `CAIDO_PROXY_CAPTURE=1`.

## Terminal client

The same live stream, in your terminal, standard library only:

```sh
# from the host (GUI published on :9100)
python3 docker/web/vulnerator_watch.py
python3 docker/web/vulnerator_watch.py --session <id> --record-dir ./pocs --web

# or inside the container
docker compose exec vulnerator-web python3 vulnerator_watch.py
```

When the agent confirms a PoC, `vulnerator_watch` prints it and **replays it in place** (command typed
out, output with its timing); with `--record-dir` it also saves the `.cast` and `.md`
(`asciinema play ./pocs/<file>.cast`). Credentials: `VULNERATOR_WEB_USER` / `VULNERATOR_WEB_PASSWORD`
or `--user` / `--password`.

## Configuration

All optional, in `.env` (see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `VULNERATOR_WEB_HOST_PORT` | `9100` | Host port of the GUI. |
| `VULNERATOR_WEB_USER` / `VULNERATOR_WEB_PASSWORD` | dashboard account (`admin` / `vulnerator`) | HTTP Basic sign-in. |
| `VULNERATOR_WEB_CAIDO_FEED` | `1` | `0` disables the Caido traffic feed. |
| `VULNERATOR_WEB_POLL_SECONDS` | `1.5` | Session poll interval (the GUI's latency). |
| `HERMES_IMAGE` | `nousresearch/hermes-agent:v0.23.0` | Hermes image; set an older tag to roll back. |

## Security

* HTTP Basic auth on every route except `/healthz`, compared in constant time. **Fail-closed**: the
  process does not start without a password or without `HERMES_API_SERVER_KEY`.
* Strict CSP (no inline scripts or styles), `nosniff`, `no-referrer`, the GUI cannot be framed.
* Everything coming from Hermes, the tools or Caido is **untrusted data**: the browser renders it with
  `textContent` only (never as HTML), and `vulnerator_watch` neutralizes terminal control sequences
  before printing. PoC file names are reduced to `[A-Za-z0-9_.-]` and cannot escape `/data/pocs`.
* The GUI shows raw tool output and engagement evidence. Publish `:9100` only on a controlled machine
  (prefer an SSH tunnel or a trusted VPN), and change the default password.

## Development

The logic lives in standard-library modules covered by tests that need no network and no running
stack (fixtures are synthetic: RFC 5737 addresses and `example.com`):

| Module | Role |
|---|---|
| `ooda_parse.py` | Parses the `OODA — <PHASE> (step N): …` status line. |
| `event_model.py` | Hermes session messages → GUI events (tool calls, results, reasoning, OODA). |
| `trace_store.py` | SQLite store: sessions, events (global cursor for the live stream), spans. |
| `poc_replay.py` | OODA path + reproduction + replay script; asciinema and Markdown export. |
| `ingest.py` | Async pollers (Hermes sessions, Caido) and automatic PoC recording. |
| `web_app.py` | Starlette layer: auth, security headers, REST API, SSE stream. |
| `vulnerator_watch.py` | Terminal client. |
| `../browser-view/cdp_proxy.py` | Host-rewriting CDP proxy for the visible browser (pure functions tested). |
| `caido_proxy.py` | Reverse-proxies Caido's UI and injects a guest token (auto-login, onboarding/analytics marked done) + WS bridge. |
| `../caido-director/director.py` | Controller that re-enacts the agent's `caido_*` actions in the Caido UI (Playwright/CDP). |
| `../browser-view/entrypoint.sh`, `../caido-director/entrypoint.sh` | Headed Chromium + Xvfb + x11vnc + noVNC launchers. |

```sh
cd docker/web
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt pytest
.venv/bin/python -m pytest -q tests
```

Build the image for the local platform (the compose file declares multi-arch, which needs buildx):

```sh
docker build -f docker/web/Dockerfile -t vulnerator-ai-web:dev .
docker compose up -d --no-build --no-deps vulnerator-web
```
