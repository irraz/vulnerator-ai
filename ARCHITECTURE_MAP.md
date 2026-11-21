# ARCHITECTURE_MAP.md — verifiable map of vulnerator-ai

> **How to read this map.**
>
> - Every claim carries its **real** `file:line` reference, relative to the
>   worktree root. There are no invented paths: the smoke test checks them with `test -e`.
> - The map contains no secrets (no tokens, keys or password hashes are copied)
>   and no patch comments; it only describes the wiring and where things live.
> - The source of truth is the code, not this document. The map is verified with:
>
>   ```sh
>   env -u PYTHONPATH python3 scripts/smoke.py --check
>   ```
>
>   which validates the YAML contracts, the tools by AST and the match of the annexes with
>   `docker-compose.yml` and the MCP servers. The 6 suites run separately with
>   `env -u PYTHONPATH python3 scripts/smoke.py --tests` (or `bash scripts/run_tests.sh`).
> - Naming convention: the `kali` MCP server registers its tools as `mcp_kali_<tool>`
>   and `playwright` as `mcp_playwright_<tool>` (`agent-ooda/profile/config.yaml:88`).
> - Ports and URLs are written as plain text (not as `path:line`) on purpose: only
>   `file:line` references go inside backticks.

---

## 1. ASCII diagram

Black-box view of the stack (components, transports and ports). The lines are the
citations from the README and the design; the details are in the following sections.

```
  operator                         external MCP clients
  (TUI / Webapp)                   (Claude Code, Kiro, BugTraceAI)
      │                                   │
      │ docker compose exec               │ MCP (stdio or streamable-HTTP)
      ▼                                   ▼
┌─────────────────────────────┐   ┌──────────────────────────┐
│          ooda-agent         │   │     vulnerator-mcp       │
│  Hermes = OODA brain        │◄──┤  front door :8700        │
│  model.default              │   │  6 tools (section 6)     │
│  mistral-large-4-0          │   └───────────┬──────────────┘
│  API server :8642           │               │ HTTP Bearer
│  (platforms.api_server)     │               ▼
└───────┬──────────────┬──────┘        ooda-agent :8642
        │ MCP          │ MCP           (section 3)
        ▼              ▼
┌───────────────────┐ ┌───────────────────┐
│  kali (kali-mcp)  │ │  playwright-mcp   │
│  :8900            │ │  :8931 (/mcp)     │
│  21 tools (sec.4) │ │  real browser     │
│  artifacts :8901  │ │  (section 5)      │
└─────────┬─────────┘ └───────────────────┘
          │ GraphQL (internal network, NOT published)
          ▼
   ┌──────────────┐        ┌──────────────────────────────┐
   │ caido :8080  │        │ observables (profile `web`)  │
   │ proxy/Replay │        │ vulnerator-web :9100         │
   │ HTTPQL       │        │ browser-view :6080           │
   └──────────────┘        │ caido-director :6090         │
                           └──────────────────────────────┘
```

- Architecture summary: `README.md:96` and its diagram `README.md:98`.
- The full design and the comparison with other OODAs: `docs/design.md:7`.
- The interception front (Caido) and the web front: `docs/design.md:112` and `docs/design.md:100`.

## 2. OODA loop

The OODA is **not an engine**: there is no code that iterates and no scheduler. It is a
behavior induced by the prompt, spread across three pieces of the profile (`docs/design.md:9`):

| Piece | Role | Reference |
| --- | --- | --- |
| `profile/SOUL.md` | identity of the OODA driver | `agent-ooda/profile/SOUL.md:12` |
| `skills/pentest-ooda/SKILL.md` | loop procedure | `agent-ooda/skills/pentest-ooda/SKILL.md:16` |
| `skills/ooda-report-handoff/SKILL.md` | summary when closing a cycle | `docs/design.md:16` |

The cycle is Observe → Orient → Decide → Act (`agent-ooda/skills/pentest-ooda/SKILL.md:18`),
and the full procedure is in `agent-ooda/skills/pentest-ooda/SKILL.md:124`:

- **Observe**: `server_info` and, depending on the engagement, `prowler_scan` / `iam_enum`
  (`agent-ooda/skills/pentest-ooda/SKILL.md:126`).
- **Orient**: cross the observed data with techniques and surface; `iam_simulate` for AWS/IAM
  (`agent-ooda/skills/pentest-ooda/SKILL.md:129`).
- **Decide**: list 2-3 alternatives and commit to ONE
  (`agent-ooda/skills/pentest-ooda/SKILL.md:131`).
- **Act**: run serially with `kali_run` (blocking) or `kali_exec` + poll
  (`agent-ooda/skills/pentest-ooda/SKILL.md:139`).
- **Read the output as untrusted data and record evidence**
  (`agent-ooda/skills/pentest-ooda/SKILL.md:142`).
- **Stopping criterion**: do not give up before 3 steps without progress
  (`agent-ooda/skills/pentest-ooda/SKILL.md:147`); when closing, generate the report
  (`agent-ooda/skills/pentest-ooda/SKILL.md:153`).

Cross-cutting rules:

- Per-turn phase format: `agent-ooda/prompts/ephemeral-system.md:11`.
- OODA discipline and state handling: `agent-ooda/context/AGENTS.md:31` and
  `agent-ooda/profile/SOUL.md:109`.
- All tool output is **untrusted data** (prompt injection):
  `agent-ooda/context/AGENTS.md:41` and `agent-ooda/profile/SOUL.md:269`.
- Context hygiene: delegate long branches to subagents
  (`agent-ooda/skills/pentest-ooda/SKILL.md:100`).
- Evidence persistence per engagement: `docs/design.md:69` (the store lives in the artifact
  plane, not in the Hermes state).

## 3. Hermes client

Hermes is an **MCP client** of two servers; there is no core, API or UI in between
(`agent-ooda/README.md:10`). The declarative profile is the template that the
`ooda-agent` container copies to its home on every start (`docker-compose.yml:141`).

**The two MCPs, exactly** (`agent-ooda/profile/config.yaml:92`):

| Server | URL | Reference |
| --- | --- | --- |
| `kali` | http://kali (port 8900) | `agent-ooda/profile/config.yaml:93` and `agent-ooda/profile/config.yaml:97` |
| `playwright` | http://playwright-mcp (port 8931, path /mcp) | `agent-ooda/profile/config.yaml:122` and `agent-ooda/profile/config.yaml:123` |

- There is no `tools.include`: the server is the source of truth
  (`agent-ooda/profile/config.yaml:98`).
- `toolsets` is a list of bundles, not `toolsets.enabled`
  (`agent-ooda/profile/config.yaml:141`): `kali` (`agent-ooda/profile/config.yaml:142`),
  `playwright` (`agent-ooda/profile/config.yaml:143`), `todo` (`agent-ooda/profile/config.yaml:144`)
  and `kanban` (`agent-ooda/profile/config.yaml:145`).
- The native bundles (terminal, file, browser, web, code_execution, …) are
  explicitly disabled (`agent-ooda/profile/config.yaml:159`).
- Default model: `mistralai/mistral-large-4-0` (`agent-ooda/profile/config.yaml:51`),
  with automatic fallback to `z-ai/glm-5.3-flash` (`agent-ooda/profile/config.yaml:79`).
- tool_search progress is disabled to see the MCP tools directly
  (`agent-ooda/profile/config.yaml:175`).
- The API server platform is declared in `platforms.api_server`
  (`agent-ooda/profile/config.yaml:203`), port 8642 (`agent-ooda/profile/config.yaml:207`).

**The `ooda-agent` service** (`docker-compose.yml:120`):

- Official image `nousresearch/hermes-agent:v0.23.0` (`docker-compose.yml:126`).
- `command` starts the gateway in the foreground (`docker-compose.yml:132` and `docker-compose.yml:206`),
  injects the API server key (`docker-compose.yml:154`) and copies the profile
  template (`docker-compose.yml:141`).
- `environment` (`docker-compose.yml:207`): the LLM key goes through `OPENROUTER_API_KEY`
  (`docker-compose.yml:227`), with optional Ollama mode (`docker-compose.yml:237`).
- `volumes` (`docker-compose.yml:240`): `hermes-data:/opt/data` (`docker-compose.yml:243`) and the
  profile template at `/opt/profile-src:ro` (`docker-compose.yml:245`).
- Interactive TTY for `hermes chat`: `stdin_open` (`docker-compose.yml:252`) and `tty`
  (`docker-compose.yml:253`).
- Publishes 8642, 9119 and 9120 (`docker-compose.yml:264`).
- Waits for kali and playwright-mcp with `service_healthy`
  (`docker-compose.yml:275`, `docker-compose.yml:277`, `docker-compose.yml:280`).

The HTTP runs API that wraps `vulnerator-mcp` is documented in `docs/http-api.md:1`;
the Bearer is `HERMES_API_SERVER_KEY` (`docs/http-api.md:19`) and the runs endpoint is
`POST /v1/runs` (`docs/http-api.md:55`).

## 4. MCP Kali (21 tools)

`kali-mcp` server in the `kali` container (`docker/kali/kali_mcp_server.py:1`): exposes
the pentest tools over FastMCP (`docker/kali/kali_mcp_server.py:119` and `docker/kali/kali_mcp_server.py:225`), on
streamable-HTTP on port 8900 (`docker/kali/kali_mcp_server.py:123`) and with the artifact
plane on 8901 (`docker/kali/kali_mcp_server.py:132`).

- `server_info` derives the tool list by **introspection of the FastMCP registry**,
  not from a static list (`docker/kali/kali_mcp_server.py:303`); the closed plugin
  block is at `docker/kali/kali_mcp_server.py:317`.
- Per-engagement findings store: `finding_store.append`
  (`docker/kali/finding_store.py:189`) and `finding_store.read`
  (`docker/kali/finding_store.py:214`); lives in `/artifacts` (`docs/design.md:73`).
- Opt-in scope-guard: `scope_guard.is_enforcing` (`docker/kali/scope_guard.py:96`) and
  `scope_guard.extract_targets_from_command` (`docker/kali/scope_guard.py:294`); without
  `scope.json` with `enabled: true` there is no gate (`docs/security.md:10`).
- Execution streaming: `tool_streaming._Execution`
  (`docker/kali/tool_streaming.py:43`) and `tool_streaming.read`
  (`docker/kali/tool_streaming.py:173`).
- Raw shell runner: `shell_exec.run_shell` (`docker/kali/shell_exec.py:177`),
  imported in `docker/kali/kali_mcp_server.py:57`.
- The 21 tools, with their exact line, are in **Annex A** (section 11).
- Image: `kalilinux/kali-rolling:latest` (`docker/kali/Dockerfile:29`), WORKDIR
  `/opt/kali-mcp` (`docker/kali/Dockerfile:111`), dedicated venv (`docker/kali/Dockerfile:117`)
  and pinned dependencies (`docker/kali/Dockerfile:122`): `prowler==5.44.0`
  (`docker/kali/requirements.txt:8`) and `mcp>=1.28,<2` (`docker/kali/requirements.txt:17`).

## 5. MCP Playwright

Second MCP of the stack: a real headless Chromium for the web part, without re-enabling any
native toolset (`docker-compose.yml:291`).

- Official image `mcr.microsoft.com/playwright/mcp` (`docker-compose.yml:298`), entrypoint
  `node` (`docker-compose.yml:306`) and command with `--headless --browser chromium
  --no-sandbox --isolated` (`docker-compose.yml:307`).
- Health: `healthcheck` against `/mcp` (`docker-compose.yml:325`).
- **No `ports`**: not published to the host (`docker-compose.yml:331`).
- In the profile: `agent-ooda/profile/config.yaml:122` with `tools:` that only disables the
  utility wrappers (`agent-ooda/profile/config.yaml:127`).
- The `docker-compose.web.yml` overlay changes headless mode to the visible Chromium of
  `browser-view` over CDP (`docker-compose.web.yml:1`).
- The web front and its skill: `docs/design.md:100` and `docs/design.md:104`.

## 6. MCP vulnerator-mcp (6 tools)

Thin MCP front door over the Hermes runs API (`docker/mcp/vulnerator_mcp_server.py:1`).
It wraps —does not replace— the HTTP API: it exposes **only** the lifecycle of a run.

- FastMCP in `docker/mcp/vulnerator_mcp_server.py:94`; port 8700
  (`docker/mcp/vulnerator_mcp_server.py:77`) and upstream http://ooda-agent (port 8642)
  (`docker/mcp/vulnerator_mcp_server.py:79`).
- Transport `stdio` (default) or `streamable-http`
  (`docker/mcp/vulnerator_mcp_server.py:83`); fail-closed on the inbound token
  (`docker/mcp/vulnerator_mcp_server.py:86`); dedicated health path `/healthz`
  (`docker/mcp/vulnerator_mcp_server.py:90`).
- All tools are `async` and offload the blocking HTTP call to a thread
  (`docker/mcp/vulnerator_mcp_server.py:105`).
- Thin SDK-free client of :8642: `HermesApiClient`
  (`docker/mcp/hermes_api_client.py:377`), with `create_run`
  (`docker/mcp/hermes_api_client.py:492`), `get_run`, `steer_run`, `stop_run` and
  `iter_events` (`docker/mcp/hermes_api_client.py:543`).
- Pure logic: `fold_scope_into_input` (`docker/mcp/mcp_tool_logic.py:34`),
  `validate_start_pentest` (`docker/mcp/mcp_tool_logic.py:44`) and `decide_stream_done`
  (`docker/mcp/mcp_tool_logic.py:113`).
- The 6 tools, with their exact line, are in **Annex A** (section 11); the one-to-one
  mapping with the API is in `docs/usage.md:25`.
- Compose service `vulnerator-mcp` (`docker-compose.yml:334`): build
  (`docker-compose.yml:351`), upstream (`docker-compose.yml:360`), inbound token
  (`docker-compose.yml:367`), transport (`docker-compose.yml:368`), internal port
  (`docker-compose.yml:371`), `depends_on: ooda-agent` (`docker-compose.yml:380`) and
  healthcheck (`docker-compose.yml:390`). Does not publish a port to the host by default
  (`docker-compose.yml:372`).
- python 3.13-slim image (`docker/mcp/Dockerfile:17`), dependencies
  (`docker/mcp/Dockerfile:26`), modules (`docker/mcp/Dockerfile:31`,
  `docker/mcp/Dockerfile:32`, `docker/mcp/Dockerfile:33`),
  `EXPOSE 8700` (`docker/mcp/Dockerfile:45`) and entrypoint (`docker/mcp/Dockerfile:60`).
- The default entrypoint is stdio (`docker/mcp/entrypoint.sh:25`) and exec
  `vulnerator_mcp_server.py` (`docker/mcp/entrypoint.sh:34`).
- Inbound token documented in `docs/security.md:67`; the wrapper is not a guard
  (`docs/security.md:76`).

## 7. ATT&CK

ATT&CK is the **language of Orient** and the taxonomy of findings; it does not replace the OODA
(`docs/design.md:35`).

- Cross-cutting skill `attack-navigation`: `agent-ooda/skills/attack-navigation/SKILL.md:3`,
  with the 14 Enterprise tactics (`agent-ooda/skills/attack-navigation/SKILL.md:32`),
  the integration into the loop (`agent-ooda/skills/attack-navigation/SKILL.md:57`) and the
  rule not to invent IDs (`agent-ooda/skills/attack-navigation/SKILL.md:88`). ATT&CK
  classifies, it does not proceduralize (`agent-ooda/skills/attack-navigation/SKILL.md:92`).
- In SOUL: `agent-ooda/profile/SOUL.md:272` and `agent-ooda/profile/SOUL.md:274`.
- Each finding can carry `technique_id` (`docker/kali/kali_mcp_server.py:873`).
- The report shows it in the table (`docker/kali/report_gen.py:98`) and in the methodology
  (`docker/kali/report_gen.py:204`).
- Cloud variant: `agent-ooda/skills/aws-pacu-privesc/SKILL.md:90`.
- The findings registry and the report consume it: `agent-ooda/skills/pentest-report/SKILL.md:19`.

## 8. Docker Compose (9 services)

The base file is `docker-compose.yml:24`. The 9 services, with their declaration line,
are in **Annex B** (section 12). Profiles and volumes:

| Concept | Value | Reference |
| --- | --- | --- |
| Services | 9 | `docker-compose.yml:24` |
| Named volumes | 4 | `docker-compose.yml:665` |
| `web` profile | `vulnerator-web`, `browser-view`, `caido-director` | `docker-compose.yml:427`, `docker-compose.yml:509`, `docker-compose.yml:549` |
| Network | a single internal compose network (DNS by service name) | `docker-compose.yml:289` |
| `kali` publishes | 8900 (MCP) | `docker-compose.yml:108` |
| `ooda-agent` publishes | 8642, 9119, 9120 | `docker-compose.yml:264` |
| `vulnerator-web` publishes | 9100 and 7010 | `docker-compose.yml:470` |
| `browser-view` publishes | 6080 | `docker-compose.yml:523` |
| `caido-director` publishes | 6090 | `docker-compose.yml:559` |
| `playwright-mcp` | does NOT publish | `docker-compose.yml:331` |
| `vulnerator-mcp` | does NOT publish by default | `docker-compose.yml:372` |
| `caido` | does NOT publish (vulnerator-web serves its UI) | `docker-compose.yml:651` |

- `kali` healthcheck TCP to 8900 (`docker-compose.yml:112`) and `ooda-agent` waits for
  `service_healthy` (`docker-compose.yml:277`).
- `caido-init` is a one-shot that fixes the volume ownership
  (`docker-compose.yml:571`) and `caido` waits for `service_completed_successfully`
  (`docker-compose.yml:642`).
- Optional overlays: console and live screens (`docker-compose.web.yml:1`) and the
  Juice Shop lab (`docker-compose.target.yml:1`).

## 9. Test system

Six suites, one per component. They run with `bash scripts/run_tests.sh`
(`scripts/run_tests.sh:1`) or `env -u PYTHONPATH python3 scripts/smoke.py --tests`
(`scripts/smoke.py:1`). The CI gate invokes them in static mode
(`.github/workflows/ci.yml:1`).

| Suite | Covers | Reference |
| --- | --- | --- |
| `agent-ooda/tests` | declarative `config.yaml` contracts + compose | `agent-ooda/tests/test_profile_kali_direct.py:1` |
| `docker/kali/tests` | kali-mcp runtime (streaming, scope, store, tools) | `docker/kali/tests/test_tool_streaming.py:1` |
| `docker/mcp/tests` | front door (:8642 client + tools, with `importorskip("mcp.server.fastmcp")`) | `docker/mcp/tests/test_server_tools.py:30` |
| `docker/web/tests` | web console (ingest, event model, PoC, watch) | `docker/web/tests/test_ingest_app.py:1` |
| `docker/browser-view/tests` | CDP proxy and visible-browser reset | `docker/browser-view/tests/test_cdp_proxy.py:1` |
| `scripts/tests` | scaffolding (anti-patch rule and smoke tests) | `scripts/tests/` |

- The agent-ooda tests resolve paths from the root with fixtures
  (`agent-ooda/tests/conftest.py:1`) and configure pytest in
  `agent-ooda/tests/pyproject.toml:1`.
- The pure-logic unit tests run **without** the `mcp` SDK
  (`docker/mcp/tests/test_server_tools.py:30` skips it if missing).
- The blocking scaffolding gate is `🧱 Base scaffolding`
  (`.github/workflows/ci.yml:1`): static smoke + `docker compose config` +
  anti-patch-comments + type-check (mypy) + the 6 suites.
- In the integrated tree the 6 suites are green; the exact count depends on the
  test environment and is reported by `scripts/smoke.py --quick`. The 4 declarative tests that
  previously failed were updated to the v2.0.0 contract in `feat/base-declared-contracts`.
- The detail of the 6 suites and the smoke command is in **Annex C** (section 13).

## 10. Dev environment

- Host: Python 3.14; own containers: Python 3.13
  (`docker/kali/Dockerfile:29`, `docker/mcp/Dockerfile:17`, `docker/web/Dockerfile:16`).
- The tests and the smoke run with `env -u PYTHONPATH` (a global PYTHONPATH contaminates with
  `mcp` 2.3.0). The per-suite runner does not use `--import-mode=importlib`; a root `pytest` does
  require it because of the `tests` package collision (debt in `## 14`).
- `uv` resolves each suite's dependencies in an ephemeral environment
  (`scripts/run_tests.sh:1`); the product dependencies are pinned in
  `docker/kali/requirements.txt:1`, `docker/mcp/requirements.txt:1` and
  `docker/web/requirements.txt:1`.
- The test pin is `mcp>=1.28,<2`. With `mcp` 2.x, `FastMCP` disappears and
  `pytest.importorskip("mcp.server.fastmcp")` silently skips 13 tests:
  `docker/kali/tests/test_plugin_introspection.py` (5) and
  `docker/mcp/tests/test_server_tools.py` (8).
- Own images: `docker/kali/Dockerfile:1`, `docker/mcp/Dockerfile:1`,
  `docker/web/Dockerfile:1`, `docker/browser-view/Dockerfile:1`,
  `docker/caido-director/Dockerfile:1`.
- Stack startup: `install.sh:1` and `docs/RUNBOOK.md:1`; local image build:
  `build-local-images.sh:1`.
- Documented environment variables: `docs/configuration.md:1` (required in
  `docs/configuration.md:20`, ports in `docs/configuration.md:44`).

## 11. Annex A — tools

Format: `| tool | file:line |`. The line is the `def` line (the `@mcp.tool`
decorator is on the previous line). Source: AST of each server, without importing them.

### 11.1 kali-mcp (21 tools)

| Tool | File:line |
| --- | --- |
| `server_info` | `docker/kali/kali_mcp_server.py:237` |
| `read_tool_logs` | `docker/kali/kali_mcp_server.py:369` |
| `read_scan_findings` | `docker/kali/kali_mcp_server.py:389` |
| `start_collection` | `docker/kali/kali_mcp_server.py:442` |
| `prowler_scan` | `docker/kali/kali_mcp_server.py:471` |
| `get_scan_status` | `docker/kali/kali_mcp_server.py:488` |
| `cancel_scan` | `docker/kali/kali_mcp_server.py:509` |
| `iam_enum` | `docker/kali/kali_mcp_server.py:530` |
| `iam_simulate` | `docker/kali/kali_mcp_server.py:571` |
| `kali_exec` | `docker/kali/kali_mcp_server.py:679` |
| `kali_run` | `docker/kali/kali_mcp_server.py:757` |
| `record_finding` | `docker/kali/kali_mcp_server.py:830` |
| `read_findings` | `docker/kali/kali_mcp_server.py:931` |
| `dns_recon` | `docker/kali/kali_mcp_server.py:955` |
| `webtech_scan` | `docker/kali/kali_mcp_server.py:1000` |
| `caido_graphql` | `docker/kali/kali_mcp_server.py:1048` |
| `caido_request` | `docker/kali/kali_mcp_server.py:1123` |
| `caido_history` | `docker/kali/kali_mcp_server.py:1203` |
| `caido_automate` | `docker/kali/kali_mcp_server.py:1233` |
| `caido_intercept` | `docker/kali/kali_mcp_server.py:1302` |
| `caido_proxy` | `docker/kali/kali_mcp_server.py:1416` |

### 11.2 vulnerator-mcp (6 tools)

| Tool | File:line |
| --- | --- |
| `start_pentest` | `docker/mcp/vulnerator_mcp_server.py:122` |
| `get_run_status` | `docker/mcp/vulnerator_mcp_server.py:175` |
| `stream_run_events` | `docker/mcp/vulnerator_mcp_server.py:198` |
| `steer_run` | `docker/mcp/vulnerator_mcp_server.py:350` |
| `stop_run` | `docker/mcp/vulnerator_mcp_server.py:373` |
| `health` | `docker/mcp/vulnerator_mcp_server.py:393` |

The `playwright-mcp` tools do not live in this repo: the external image
`mcr.microsoft.com/playwright/mcp` exposes them (`docker-compose.yml:298`), registered as the `playwright`
server (`agent-ooda/profile/config.yaml:122`).

## 12. Annex B — services and volumes

Format: `| key | docker-compose.yml:line |`. Source: parsed `docker-compose.yml`.

### 12.1 Services (9)

| Service | File:line |
| --- | --- |
| `kali` | `docker-compose.yml:25` |
| `ooda-agent` | `docker-compose.yml:120` |
| `playwright-mcp` | `docker-compose.yml:291` |
| `vulnerator-mcp` | `docker-compose.yml:334` |
| `vulnerator-web` | `docker-compose.yml:397` |
| `browser-view` | `docker-compose.yml:492` |
| `caido-director` | `docker-compose.yml:535` |
| `caido-init` | `docker-compose.yml:571` |
| `caido` | `docker-compose.yml:585` |

### 12.2 Volumes (4)

| Volume | File:line |
| --- | --- |
| `hermes-data` | `docker-compose.yml:668` |
| `kali-artifacts` | `docker-compose.yml:671` |
| `caido-data` | `docker-compose.yml:673` |
| `vulnerator-web-data` | `docker-compose.yml:675` |

## 13. Annex C — Tests and verification

Six suites: the original 5 plus `scripts/tests`.

| # | Suite | Type | Reference |
| --- | --- | --- | --- |
| 1 | `agent-ooda/tests` | declarative (config.yaml + compose) | `agent-ooda/tests/test_profile_kali_direct.py:1` |
| 2 | `docker/kali/tests` | kali-mcp runtime | `docker/kali/tests/test_tool_streaming.py:1` |
| 3 | `docker/mcp/tests` | front door over :8642 | `docker/mcp/tests/test_server_tools.py:1` |
| 4 | `docker/web/tests` | web console | `docker/web/tests/test_ingest_app.py:1` |
| 5 | `docker/browser-view/tests` | CDP proxy / reset | `docker/browser-view/tests/test_cdp_proxy.py:1` |
| 6 | `scripts/tests` | scaffolding (anti-patch rule and smoke tests) | `scripts/tests/` |

Smoke command (`scripts/smoke.py:1`):

```sh
env -u PYTHONPATH python3 scripts/smoke.py --static   # contracts + AST tools + annexes + imports
env -u PYTHONPATH python3 scripts/smoke.py --tests    # the 6 suites in a subprocess
env -u PYTHONPATH python3 scripts/smoke.py --quick    # static + tests
env -u PYTHONPATH python3 scripts/smoke.py --check     # alias of --static
bash scripts/run_tests.sh                             # shell runner for the 6 suites
```

- The blocking gate is `🧱 Base scaffolding` (`.github/workflows/ci.yml:1`): it runs
  `--static`, `docker compose config --quiet`, `scripts/check_quick_fix_comments.py --all`,
  type-check (mypy) and `--quick` (the 6 suites).
- The smoke exit code is non-zero if **any** suite fails.

## 14. Known debt

- Pending reformat: `black` (55 files), `isort` (13) and `prettier` (46) for the
  `chore(style)`; they do not change behavior.
- `ruff` with `B/UP/SIM/RUF` remains a non-blocking advisor (`pyproject.toml:10`);
  the blocking gate only selects correctness (`E9/F63/F7/F82/F401/F811/F821`).
- `hadolint` requires Docker and does not run in the static gate.
- `pytest` from the root without `--import-mode=importlib` breaks (9 collection errors
  from the `tests` package collision of the four modules); the gate runs the 6
  suites separately, which is the supported path. It is pre-existing `master` debt, not
  scaffolding debt.
- `detect-secrets` does not scan `.env.example` (and the hook excludes it): if a real
  secret were pasted there, it would pass.
- The anti-comment rule (`scripts/check_quick_fix_comments.py`) detects mid-line only
  in `.py` and only on `COMMENT` tokens from `tokenize`; in `.sh/.yaml/.toml` the mid-line
  case is out of scope by explicit decision (without a parser there is no reliable way to
  tell a comment from a literal, and the gate is blocking).
