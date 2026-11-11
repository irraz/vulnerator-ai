# RUNBOOK — Vulnerator-AI with web console, live screens and Caido director

Guide to bring **everything up from scratch** (clean clone of the repo) and have it working. It covers
what's new: the **web console** (`vulnerator-web`), the **visible browser** (`browser-view`), the **Caido
director** (`caido-director`) and Hermes **v0.23.0**. Written for the operator.

> This documents the state of the working branch. Nothing has been pushed to GitHub yet.

---

## 1. What the stack brings up (9 services)

| Service | Image | Host port | What it is |
|---|---|---|---|
| `kali` | `vulnerator-ai-kali:dev` (build) | 8900 | Tools runtime (nmap, whatweb, sqlmap, Caido client…) via kali-mcp. |
| `ooda-agent` | `nousresearch/hermes-agent:v0.23.0` | 8642 (API), 9119 (dashboard), 9120 (webapp) | The OODA brain (Hermes). |
| `playwright-mcp` | `mcr.microsoft.com/playwright/mcp` | — (internal) | The agent's browser. **Drives the `browser-view` browser over CDP.** |
| `vulnerator-mcp` | `vulnerator-ai-mcp:dev` (build) | — (internal) | MCP front door over the runs API. |
| `vulnerator-web` | `vulnerator-ai-web:dev` (build) | **9100** (GUI), 7000 (Caido pre-auth) | **The web console.** It also serves the Caido UI pre-authenticated as a guest. |
| `browser-view` | `vulnerator-ai-browser-view:dev` (build) | 6080 (noVNC) | **Visible** Chromium the agent drives; watched over noVNC in the console. |
| `caido-director` | `vulnerator-ai-caido-director:dev` (build) | 6090 (noVNC) | Re-stages in the Caido UI what the agent does with it. |
| `caido` + `caido-init` | `caido/caido:0.59.0` | — (internal) | Web toolkit (proxy/Replay/Automate/Intercept). |
| `juice-shop` (optional, lab) | `bkimminich/juice-shop` | — (internal) | Practice target; only with `docker-compose.target.yml`. |

**Own images to build:** `kali`, `vulnerator-mcp`, `vulnerator-web`, `browser-view`,
`caido-director`. The rest are pulled.

---

## 2. Requirements

- **Docker** + **docker compose v2** (`docker compose version`).
- Internet access (to pull images and for Hermes to call OpenRouter).
- Disk: ~5-6 GB of images (Hermes v0.23.0 weighs ~3.2 GB).
- An **OpenRouter** key with credit (Hermes' brain). Alternative: Ollama (see §9).

---

## 3. Prepare the `.env` (one time only)

Copy the template and fill in the essentials:

```sh
cd ~/vulnerator-ai-work          # your clone of the repo
cp .env.example .env
chmod 600 .env
```

**REQUIRED variables** (without them the stack won't start — they are fail-closed):

```ini
# Key for Hermes' LLM provider (OpenRouter). Required in OpenRouter mode.
OPENROUTER_API_KEY=sk-or-v1-....................................................

# Bearer for the Hermes API (:8642). Generate one:  openssl rand -hex 32
HERMES_API_SERVER_KEY=<64 hex>

# Inbound token for the MCP front door. Generate a different one:  openssl rand -hex 32
VULNERATOR_MCP_INBOUND_TOKEN=<64 hex>
```

> Generate the two keys with `openssl rand -hex 32` (a different one for each).
> `install.sh` also generates them for you if you prefer that path (§5, option B).

**Recommended for Caido's live screens** (otherwise Caido won't see the agent's
traffic):

```ini
# The visible browser routes its traffic through Caido's proxy -> it shows up in Caido.
BROWSER_VIEW_PROXY=http://caido:8080
# kali's HTTP tools (curl/nuclei/ffuf…) also go through Caido's proxy.
CAIDO_PROXY_CAPTURE=1
```

**Optional** (they have sensible defaults; see `.env.example` for all of them):
`VULNERATOR_WEB_PASSWORD` (console login; defaults to `vulnerator`),
`HERMES_IMAGE` (defaults to `nousresearch/hermes-agent:v0.23.0`),
`CAIDO_DIRECTOR_STEP` (director pacing), `*_HOST_PORT` ports.

The `.env` is in `.gitignore` — **it is never committed**.

---

## 4. Build the own images

The `docker-compose.yml` declares multi-arch `platforms:` (for publishing), and a Docker **without
buildx/containerd** fails with *"Multi-platform build is not supported for the docker driver"*.
That's why the reliable path is to build each image for your architecture with the included script:

```sh
./build-local-images.sh
```

(Equivalent to `docker build -f docker/<x>/Dockerfile -t vulnerator-ai-<x>:dev .` for the 5 images.)

> If your Docker **does** have buildx/containerd, you can skip this and use `docker compose up -d
> --build` directly (or `./install.sh`).

---

## 5. Bring the stack up

**Option A — manual (recommended after `build-local-images.sh`):**

```sh
# Without the lab:
docker compose up -d --no-build
# With the OWASP Juice Shop practice lab:
docker compose -f docker-compose.yml -f docker-compose.target.yml up -d --no-build
```

**Option B — official installer** (generates the `.env` and runs `up -d --build`; requires that your
Docker build multi-platform, or adapt it):

```sh
./install.sh                     # asks for the OpenRouter key and generates keys
./install.sh --with-juice-shop   # also brings up the lab
```

---

## 6. Verify it's healthy

```sh
docker compose ps        # all "healthy" / "Up" (ooda-agent has no healthcheck: that's normal)
curl -s http://localhost:8642/health            # {"status":"ok",...,"version":"0.23.0"}
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:9100/healthz   # 200
```

`caido` takes ~30-60 s to be ready after a cold start. The **Caido director** needs
that margin to leave the UI pre-authenticated and without onboarding (it does this on its own, see §10/§11).

---

## 7. Enter the web console

The console is at **http://localhost:9100**.

- **Own login** (user `admin` / password `vulnerator`, or whatever you set in
  `VULNERATOR_WEB_USER`/`PASSWORD`). For credential-free access on a controlled machine,
  `VULNERATOR_WEB_AUTH=0`.

Tabs:
- **Terminal** — the live OODA loop: phases, reasoning, every command with its output.
- **Copilot** — "right now": running tool, browser, Caido traffic, findings.
- **Traces** — tool-call waterfall (duration, status, phase), Langfuse-style.
- **PoC** — for each confirmed finding: OODA path + recorded reproduction (`.cast`/`.md`).
- **Screens** — for demos: **Hermes' actions live** + **the agent's browser** (noVNC)
  + **Caido driving itself** (director) + links to Hermes' Dashboard/Webapp.
- **Hermes** — access to the Dashboard (`:9119`, Kanban) and Webapp (`:9120`).

---

## 8. Launch an engagement (as a user)

It is independent of the console (the console only observes). Ways:

```sh
# a) interactive TUI:
docker compose exec -it ooda-agent hermes chat

# b) runs API (what shows up live in the console):
KEY=$(grep '^HERMES_API_SERVER_KEY=' .env | cut -d= -f2-)
curl -s http://localhost:8642/v1/runs -H "Authorization: Bearer $KEY" \
  -H "Content-Type: application/json" \
  -d '{"input":"Authorized pentest against http://juice-shop:3000 (scope: that host only). ..."}'
```

The internal lab is reached as `http://juice-shop:3000`. For an authorized external target,
put its URL and narrow the scope to that host.

Follow it **from the terminal** (CLI, pure stdlib):
```sh
docker compose exec vulnerator-web python3 vulnerator_watch.py            # all sessions
# or from the host:  python3 docker/web/vulnerator_watch.py --record-dir ./pocs
```

---

## 9. Ollama mode (without OpenRouter)

Set `OLLAMA_BASE_URL=http://host.docker.internal:11434/v1` and `OLLAMA_MODEL=<model>` in `.env`;
then `OPENROUTER_API_KEY` is no longer required. (See `.env.example`.)

---

## 10. The live screens (how to watch what it does)

- **The agent's browser** (`browser-view`, noVNC on `:6080`): the agent controls that Chromium
  pixel by pixel; you watch it navigate/click. For **HTTPS targets through Caido's proxy** the
  browser uses `--ignore-certificate-errors` (the proxy does MITM with its own CA).
- **Caido (director)** (`caido-director`, noVNC on `:6090`): the Caido UI **moves on its own**
  replaying each `caido_request`/`caido_automate`/`caido_history`/scope from the agent: it opens the
  Replay session, types the HTTPQL filter, opens the packet, etc. The **data is real** (the
  agent's); the "walkthrough" of the UI is choreographed by the director. It runs at the **agent's
  pace** (each action is an LLM inference, ~30-60 s): it's the "slow but you see everything" live feed.
- For Caido to have traffic to show: `BROWSER_VIEW_PROXY=http://caido:8080` and
  `CAIDO_PROXY_CAPTURE=1` in `.env` (§3).

**Caido always enters as a guest, without onboarding** — it is handled in code: `vulnerator-web`
acts as a Caido proxy and injects a guest token and marks onboarding/analytics as done
(see `docker/web/caido_proxy.py`). It survives deleting Caido's volume. Whoever wants their own
Caido account configures it at install time (the `CAIDO_PAT` environment token).

---

## 11. Troubleshooting (things we already solved)

- **Caido shows "Learn the Essentials"/analytics when opened** → this only happens in the first ~30 s
  after a freshly created Caido volume (the proxy is still fixing the state). Refresh; it
  self-corrects on every load. It is handled in code, nothing needs to be touched by hand.
- **Caido captures nothing** → `BROWSER_VIEW_PROXY=http://caido:8080` and/or
  `CAIDO_PROXY_CAPTURE=1` are missing from `.env`, or you're looking at traffic from before the engagement started.
- **The visible browser gives a certificate error on HTTPS** → the
  `--ignore-certificate-errors` flag is already on `browser-view` (needed when going through Caido's proxy).
- **Caido panics with "Permission denied" after deleting its volume** → the one-shot
  `caido-init` service fixes it (it `chown`s the volume). If you recreate Caido by hand with `--no-deps`,
  run `docker compose run --rm caido-init` first.
- **`docker compose build` fails with "Multi-platform build is not supported"** → use
  `./build-local-images.sh` (§4).
- **Hermes rejects the LLM with `HTTP 401 User not found`** → the `OPENROUTER_API_KEY` is invalid
  or has no credit; set a valid one and recreate: `docker compose up -d ooda-agent`.
- **Hermes rollback** → `HERMES_IMAGE=nousresearch/hermes-agent:v0.22.7` in `.env` and
  `docker compose up -d ooda-agent`.
- **The Caido director is still** → the agent isn't using Caido tools at that moment
  (it's doing recon/browser). It only moves when the agent runs `caido_*`.

---

## 12. Start an exercise FROM 0 (clean slate)

For a demo from scratch with no trace of previous tests:

```sh
# 1) stop active runs (if any): via the /v1/runs/<id>/stop API, or restart ooda-agent.
# 2) delete state (Hermes sessions, the console's database, Caido traffic):
docker compose down                         # stops the stack (keeps volumes)
docker volume rm vulnerator-ai-work_hermes-data \
                 vulnerator-ai-work_vulnerator-web-data \
                 vulnerator-ai-work_caido-data
docker compose run --rm caido-init          # permissions for the new Caido volume
docker compose up -d --no-build             # (+ -f docker-compose.target.yml for the lab)
```

This leaves Hermes with no sessions, the console empty and Caido with no traffic. Caido's onboarding
is set up again on its own (code). Wait ~30-60 s for everything to be healthy before launching the engagement.

> Deleting `hermes-data` also resets Hermes' profile/Kanban (it is rebuilt on startup
> from `./agent-ooda`). If you only want to clear the console and the traffic, delete only
> `vulnerator-web-data` and `caido-data`.

---

## 13. Full reset (delete EVERYTHING, incl. images)

```sh
docker compose down -v                      # stops and deletes ALL volumes
# (optional) delete the own images:
docker image rm vulnerator-ai-kali:dev vulnerator-ai-mcp:dev vulnerator-ai-web:dev \
                vulnerator-ai-browser-view:dev vulnerator-ai-caido-director:dev
# then: ./build-local-images.sh && docker compose up -d --no-build
```

---

## 14. Repo status / what's missing

- Local working branch on top of `master`. **No commits yet; nothing pushed to GitHub.**
- New additions: `docker/web/`, `docker/browser-view/`, `docker/caido-director/`,
  `build-local-images.sh`, `docs/web-gui.md`, `docs/RUNBOOK.md`.
- Modified: `docker-compose.yml`, `.env.example`, `README.md`.
- Documentation for the console and the screens: **[`docs/web-gui.md`](web-gui.md)**.
