# Changelog

All notable changes to Vulnerator AI are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.7.0] - 2026-10-28

### Added

- **`dns_recon` tool (DNSDumpster API)** — New `kali-mcp` tool for DNS + attack-surface recon. Given a domain, enumerates hosts/subdomains, unique IPs, ASN/PTR, CIDRs and HTTP/HTTPS banners in a single blocking call, normalizing the response into a consumable attack surface for downstream scanning. Honors the API rate limit (1 req/2s) internally with pagination and a single 429 retry; fails closed without `DNSDUMPSTER_API_KEY`. Pure-stdlib module (`dnsdumpster_client.py`) with a thin `@mcp.tool` wrapper.
- **`webtech_scan` tool (whatweb + webanalyze + wpscan cross-reference)** — New `kali-mcp` tool that runs three fingerprinters and merges their output into a single `technology → {versions per source, best_version, version_conflict}` table, raising version confidence and surfacing discrepancies. Each binary is optional (skipped and reported, never faked); `wpscan` reports "not WordPress" as a normal result and uses `WPSCAN_API_TOKEN` for CVE data when present. Pure-stdlib module (`webtech_scan.py`) with a thin `@mcp.tool` wrapper.
- **Recon tooling wiring** — `kali_mcp_server` exposes both tools and reports real binary availability (`recon_tools`) and `dnsdumpster_key_present` in `server_info`. Dockerfile installs `wpscan` (apt) and `webanalyze` (pinned release, checksum-verified) with its fingerprint DB at `/opt/webanalyze/technologies.json`. `.env.example`, `docker-compose.yml` and `install.sh` wire the two optional API keys; `docs/usage.md` documents the tools. Backed by 37 new tests (204 total).
- **Automatic LLM fallback with GLM-5.3 Flash** — Configured native Hermes `fallback_providers` chain with `z-ai/glm-5.3-flash` as automatic fallback. When Mistral Large 4 fails (rate-limit 429, server error 500/502/503, auth failure 401/403), Hermes automatically switches mid-session without losing context. Per-turn failover: each message attempts primary first. Same Cyber Index as Mistral (50%) but 20x cheaper ($0.07/$0.21 vs $1.36/$4.18). Proven in production for end-to-end exploits and 0-day discovery. Top CyberGym score (84.5%). Manual override via `OPENROUTER_MODEL` env var or `hermes config set model.default`. See `docs/modelos-cyberseguridad-openrouter-CORRECTED.md` for full analysis.
- **Enhanced model documentation** — Updated `agent-ooda/profile/config.yaml` with detailed `fallback_providers` configuration and prompt cache cost warnings, `.env.example` with automatic fallback behavior, and README section on native Hermes fallback mechanism.

## [1.6.0] - 2026-10-22

### Added

- **Kanban board tracking (optional)** — Hermes Agent's Kanban system integrated as opt-in tracking layer for long pentests. Provides crash recovery, dependency DAG, and audit trail without changing default OODA loop behavior. Enabled via `kanban` toolset in `config.yaml`.
- **Increased delegation concurrency** — `max_concurrent_children` increased from 10 to 50 workers, validated by Nous 1,393-agent refactor (218 concurrent workers stable). Enables massive parallel scans for /24 networks.
- **Complete Kanban documentation** — New guides: `agent-ooda/KANBAN-USAGE.md` (usage patterns, workflow examples, troubleshooting) and `docs/KANBAN-INTEGRATION.md` (technical changes, design decisions, roadmap).
- **Extended SOUL.md** — New section "Loop state management with todo_list and Kanban" (74 lines) documenting when to use each tracking system and OODA+Kanban workflow patterns.

### Changed

- **Documentation language** — All repository documentation standardized to English for consistency.

## [1.5.0] - 2026-10-18

### Added

- **Hermes web dashboard** on `:9119` — built-in browser UI activated via `HERMES_DASHBOARD=1`
  with basic-auth and the Vulnerator-AI custom skin (dark red/green cyber theme, block ASCII
  banner, `⚡` prompt symbol, OODA spinner verbs).
- **`labs/looney-tunables-ctf`** — isolated CVE-2023-4911 (glibc 2.37 LPE) lab. Includes uname
  wrapper to mask linuxkit kernel false positives, tini as PID 1, and documented engagement
  prompts for both `mode: pentest` and `mode: ctf`.
- **`labs/pinguinazo-ssti`** — Flask/Jinja2 SSTI reverse-shell lab. Attack path: SSTI → RCE →
  reverse shell to kali → sudo java → root. Integrates with `vulnerator-ai_default` network for
  reverse shell routing. Inspired by dockerlabs.es "Pinguinazo".
- **`pentest-report` skill v0.3** — two-layer report: `report_gen.py` structured base + LLM
  narrative enrichment + standalone HTML with Vulnerator-AI visual theme.
- **Landing web** (`docs/`): CRT boot screen with lens/barrel effect, Whisper-synced karaoke
  lyrics, audio controls bar, VULNERATOR! page inversion flash, scroll reveal animations,
  content drawer, screenshot lightbox, CTF and pentest sample reports.
- **`todo` toolset** enabled so the agent uses `todo_list` for structured OODA state tracking
  across context compression and session restarts.

### Changed

- **SOUL.md** — multiple improvements:
  - `modo: pentest` vs `modo: redteam/ctf` engagement mode selection.
  - Evidence discipline: only real tool output counts; zero search results = "not found".
  - 3-step no-progress counter with concrete, exhaustive criteria.
  - ORIENT phase always calls `read_findings` to reload engagement state.
  - `todo_list` structured template (OBSERVE/ORIENT/DECIDE/ACT/REPORT).
  - Reverse shell guidance via `kali_exec` background listener.
  - Container environment awareness: userspace vulns work in containers.
  - OODA format label `OODA — <FASE> (paso <N>)` enforced as mandatory.
  - Ephemeral system prompt reinforces format on every turn.
- **`config.yaml`** — `todo` added to toolsets; `display.skin: vulnerator` activates custom skin.
- **`docker-compose.yml`** — `HERMES_DASHBOARD=1` + basic-auth env vars; port 9119 published.

## [1.4.0] - 2026-10-16

### Added
- **`install.sh` easy installer.** An interactive installer that reduces first-run setup to a single
  input: the `OPENROUTER_API_KEY`. It checks prerequisites (`docker`, `docker compose` v2,
  `openssl`), auto-generates the two secret tokens `HERMES_API_SERVER_KEY` and
  `VULNERATOR_MCP_INBOUND_TOKEN` as **separate** 32-byte hex values (`openssl rand -hex 32`), builds
  the `.env` from `.env.example` (filling in only those three keys and preserving every other default
  and the template comments), and brings the **default** stack up with `docker compose up -d --build`
  — **without** the Juice Shop lab. The OpenRouter key is read with no terminal echo, or taken from an
  exported `OPENROUTER_API_KEY` for non-interactive runs. Flags: `--with-juice-shop` (also start the
  OWASP Juice Shop practice lab), `--no-up` (write the `.env` only), `--force` (overwrite an existing
  `.env`; otherwise it refuses to clobber one). The manual `cp .env.example .env` path still works.
- **README "Let an AI assistant set it up for you" block.** A copy-paste prompt the user hands to an
  LLM coding assistant (Claude Code / Kiro / Cursor) with shell access, so the assistant runs
  `install.sh` and wires up the `vulnerator-mcp` stdio server end to end — the user only supplies the
  OpenRouter key when asked.

### Changed
- **README trimmed to a short Quick Start; detail moved into `docs/`.** The README now leads with the
  `./install.sh` Quick Start (plus a collapsed manual-setup fallback) and a documentation index,
  keeping only a condensed architecture summary and the authorized-use warning. The long-form content
  was split into new topic docs: `docs/configuration.md` (every `.env` variable, AWS credentials,
  local Ollama inference), `docs/usage.md` (driving a pentest via TUI / MCP client / raw HTTP, the
  Juice Shop lab, clean restarts between exercises), and `docs/security.md` (the no-guardrails model,
  the opt-in scope-guard, the MCP inbound token). No behavior changed; this is a documentation
  reorganization.
- **`pentest-report` now emits the report in English.** `docker/kali/report_gen.py` previously
  rendered the Markdown deliverable in Spanish; its output strings (section headings, status
  labels, executive summary, methodology, evidence labels, and the `main` summary line) are now
  English, aligned with the repo's public documentation. Logic is unchanged and the module's
  own code comments/docstrings stay in Spanish like the rest of `docker/kali/`. The unit tests
  in `docker/kali/tests/test_report_gen.py` were updated to assert the English output.
- Added a redacted English sample deliverable (`docs/example-report.md`) and its matching
  findings store (`docs/example-findings.jsonl`), linked from the README, showing the
  end-to-end OODA-over-MCP output (recon → recorded findings with ATT&CK `technique_id` and
  verbatim evidence → generated report). Target IP uses the RFC 5737 documentation address;
  device serial and hostname are redacted.

### Added
- **`vulnerator-mcp` MCP front door over the Hermes `:8642` runs API (up by default).** A thin
  FastMCP wrapper (`docker/mcp/`) that lets external MCP clients (Claude Code / Kiro locally
  over stdio; remote/containerized consumers like BugTraceAI over streamable-HTTP) trigger,
  observe, steer and stop a Hermes OODA pentest as MCP tools. It WRAPS, does not replace, the
  HTTP API: it exposes ONLY the runs lifecycle — five tools (`start_pentest`,
  `get_run_status`, `stream_run_events`, `steer_run`, `stop_run`) plus `health()` — so the
  client stays a trigger/observer and never the brain. It never exposes `/v1/chat/completions`
  or any raw `kali_run` pass-through. The wrapper is stateless and version-tolerant: the run
  object and events are forwarded opaquely and terminality is derived from the run booleans
  (`completed`/`interrupted`), never from the `status` string; the upstream version is read
  from `GET /health` and reported verbatim, never branched on. `stream_run_events` uses the
  event `seq` as a portable cursor (batched pages with `next_cursor`/`done`) and additionally
  emits MCP progress notifications over streamable-HTTP, degrading to pure batching on stdio.
  Shipped as a **4th service in the default `docker-compose.yml`** — the default stack is now
  4 containers (`kali`, `ooda-agent`, `playwright-mcp`, `vulnerator-mcp`), brought up with a
  plain `docker compose up -d --build` — because the product's intended UX is driving the
  engine from an MCP client. The streamable-HTTP service binds the internal docker network with
  host publication OFF by default (no `ports:` block; opt-in by setting
  `VULNERATOR_MCP_HOST_PORT` and uncommenting the service's `ports:` block) and is **fail-closed
  on a mandatory inbound token**
  (`VULNERATOR_MCP_INBOUND_TOKEN`): it refuses to start without one and rejects any request
  without the matching `Authorization: Bearer` (constant-time compare), with an exact-match
  carve-out for a dedicated `/healthz` route only. The same image also runs stdio for local
  Claude Code / Kiro with no token and no port (zero network surface). Upstream auth is a
  pass-through Bearer from `HERMES_API_SERVER_KEY` (no second secret for the `:8642` hop). The
  required `scope` argument is **advisory**, folded into the prompt for operator clarity — the
  MCP layer enforces NO scope and adds NO safety (the optional Kali-layer scope-guard from
  v1.3.0 is a separate, opt-in defense-in-depth layer). New `.env.example` entries
  (`VULNERATOR_MCP_INBOUND_TOKEN`, `VULNERATOR_MCP_HOST_PORT`), a README section with a
  copy-paste Claude Code / Kiro stdio `mcpServers` snippet and a loud no-guardrails warning,
  and unit tests for the SSE cursor parser and scope-folding/validation logic.
  `stream_run_events` paging is hardened: a batch cut short by any cap (`max_events`, the
  ~256 KiB byte budget, or the `wait_seconds` wall-clock budget) returns `done: false` and the
  confirming `get_run` runs ONLY on a genuine stream drain, so a client looping until `done`
  never drops the tail of a multi-page terminal run; the byte budget is checked BEFORE adding
  an event (never overshoots the transport limit by a whole event); the SSE read is async with
  a deadline-aware cancellation so a quiet upstream ends the batch at `wait_seconds` instead of
  stalling on the network timeout — the deadline now also wraps response acquisition and the
  error-body drain, so an upstream that accepts the connection but withholds headers is bounded
  by `wait_seconds` too (not just the connect timeout) — and if a non-2xx error body itself
  stalls past the deadline, the already-observed status is still reported as a bare
  `upstream_error` envelope (terminal for paging) instead of degrading to an empty deadline page
  that a loop-until-`done` client would re-issue; a single SSE event is bounded by an
  absolute per-event ceiling (~512 KiB) and, if a single event exceeds it, the batch fails loud:
  the event is NOT forwarded (neither verbatim — truncating an opaque event would break
  pass-through — nor as an in-`events` placeholder, which would drop the untrusted payload and
  consume the cursor) and the cursor is NOT advanced; instead a bare `{"error": {...}}` envelope
  with `code: "oversized_event"` carries the event metadata (seq/type/size, payload withheld),
  terminal for paging, and the real terminal state is recovered via `get_run_status` — so an
  oversized event can never exceed the transport message limit, never silently drops its payload,
  and never returns a `run.completed` marker with `done: false`; sub-ceiling events on the same
  page are delivered complete first; terminality requires the literal boolean `True`; a stream
  failure preserves the full `{"error": {...}}` envelope (surfaced under `stream_error` after
  partial events, or `terminality_error` for a failed confirming `get_run`), while a failure
  received BEFORE any event (invalid `run_id`, `run_not_found`, unreachable) returns the bare
  envelope — terminal for paging, like every other tool; and the untrusted `run_id` is encoded
  as a single path segment (route-traversal rejected before any upstream call). All six tools
  are async and offload their blocking `:8642` call to a worker thread, so a slow upstream never
  freezes the streamable-HTTP event loop (the MCP SDK runs sync tool bodies inline). `httpx` and
  `uvicorn` carry lower-bound pins in line with the repo's dependency discipline.

## [1.3.0] - 2026-10-16

### Added
- **Opt-in scope-guard for `kali_run` / `kali_exec`.** A deterministic (code, not prompt) layer
  that validates the DESTINATION of each raw-shell action BEFORE executing it. It is **opt-in**:
  with no `scope.json` present (path via `SCOPE_FILE`, default `/scope/scope.json`) and
  `enabled: true`, behavior is identical to before (no gate). When active it is **fail-closed**:
  Hermes must declare the new optional `targets` argument (the IP/host/URL the command touches),
  and any destination outside the allowed scope — or in `deny` — blocks the whole execution with a
  structured `SCOPE_VIOLATION` error WITHOUT running. `SCOPE_ENFORCE=0` is a kill-switch that
  force-disables the guard even if the file says `enabled: true`. Zero new dependencies (stdlib
  `json`/`ipaddress`/`urllib.parse`); validation is IP-against-CIDR plus LITERAL hostname match
  (no DNS) with optional ports, and `deny` takes priority over `allow`. Each violation is logged
  into the engagement findings store as a `discarded` `SCOPE_VIOLATION` record for an auditable
  trail. New `scope.example.json` template, a commented bind-mount in `docker-compose.yml`, and a
  README section document how to turn it on. Scope coverage: only `kali_run`/`kali_exec` (cloud
  and browser tools unchanged).

## [1.2.0] - 2026-10-16

### Added
- **Curated pentest CLIs baked into the Kali image.** The Kali `Dockerfile` now pre-installs a
  small, deliberate set the skills assume exist and invoke via `kali_run`: `nmap`, `whatweb`,
  `nuclei`, `ffuf`, `sqlmap`, `gobuster`, plus `impacket-scripts` and `bloodhound.py`. The base
  `kalilinux/kali-rolling` image ships none of these, so this fixes a latent runtime gap while
  keeping the image reasonably sized (curated, not the full `kali-linux-headless` metapackage).
- **Documented Juice Shop lab quickstart.** New README subsection documenting how to bring the
  stack up together with `docker-compose.target.yml` (OWASP Juice Shop) and point an engagement
  at `http://juice-shop:3000` — a deliberately-vulnerable web target on the internal network (not
  exposed to the host) for practicing the `web-pentest` skill.

### Changed
- The Ollama startup branch now **warns** (non-fatal, to stderr) when `OLLAMA_BASE_URL` is set but
  `OLLAMA_MODEL` is empty, since the profile default model name would otherwise be used against the
  Ollama endpoint (which almost certainly does not serve it). Behavior is otherwise unchanged.
- Added a regression test for the OpenRouter-vs-Ollama provider-selection startup logic in
  `docker-compose.yml`, protecting the optional `${...:-}` env form, the fail-closed OpenRouter
  guard and the new empty-`OLLAMA_MODEL` warning against silent regressions.

## [1.1.0] - 2026-10-16

### Added
- **Opt-in local / remote Ollama inference.** Set `OLLAMA_BASE_URL` in `.env` to point
  Hermes at an Ollama OpenAI-compatible endpoint (local `http://host.docker.internal:11434/v1`
  or a remote `http://<host>:11434/v1`) instead of OpenRouter. Leave it empty to keep the
  OpenRouter default behavior.
- `OLLAMA_MODEL` to set the Ollama model name used in Ollama mode (e.g. `qwen2.5-coder:32b`).
- `extra_hosts: host.docker.internal:host-gateway` on `ooda-agent` so a host-run Ollama is
  reachable on Linux as well.

### Changed
- `OPENROUTER_API_KEY` is no longer required when running in Ollama mode. The fail-closed
  guard (abort when the key is missing) is re-created in the startup script and now applies
  only to OpenRouter mode, so default behavior is unchanged.
- Documented the Ollama caveats: the endpoint must serve a context window of at least ~64K
  tokens (`OLLAMA_CONTEXT_LENGTH=64000`), and the model must support reliable tool/function
  calling and not refuse the authorized-offensive framing. Local parity with Mistral Large on
  OpenRouter is not guaranteed (experimental).

## [1.0.1] - 2026-10-16

### Added
- **Configurable OpenRouter model via `OPENROUTER_MODEL`.** Override the model Hermes reasons
  with from `.env`; empty falls back to the profile default (`mistralai/mistral-large-4-0`),
  so existing setups are unaffected.
- `VERSION` file.

### Notes
- The project deliberately uses Mistral Large because models like Claude (`anthropic/*`) refuse
  the authorized-offensive pentest framing; overriding with such a model may make the agent
  refuse to work.

[1.5.0]: https://github.com/irraz/vulnerator-ai/releases/tag/v1.5.0
[1.4.0]: https://github.com/irraz/vulnerator-ai/releases/tag/v1.4.0
[1.3.0]: https://github.com/irraz/vulnerator-ai/releases/tag/v1.3.0
[1.2.0]: https://github.com/irraz/vulnerator-ai/releases/tag/v1.2.0
[1.1.0]: https://github.com/irraz/vulnerator-ai/releases/tag/v1.1.0
[1.0.1]: https://github.com/irraz/vulnerator-ai/releases/tag/v1.0.1
