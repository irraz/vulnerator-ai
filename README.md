<p align="center">
  <img src="media/vulnerator-ai-wallpaper-desktop.jpeg" alt="VULNERATOR AI — cyberpunk key art: a hacker astronaut floating in orbit around a 'DATA HAVEN' station amid drifting servers and circuit boards, with the death-metal 'Vulnerator AI' logo and the taglines 'Unholy Pentest', 'offerings to the Kali' and 'summoned from the depths of the OODA abyss · mmxxvi'." width="880">
</p>

<p align="center">
  <a href="https://github.com/irraz/vulnerator-ai/releases/latest">
    <img src="https://img.shields.io/github/v/release/irraz/vulnerator-ai?style=for-the-badge&label=version&color=b03a3a&labelColor=0a0a0a" alt="Latest release">
  </a>
  &nbsp;
  <a href="https://irraz.github.io/vulnerator-ai/">
    <img src="https://img.shields.io/badge/website-irraz.github.io%2Fvulnerator--ai-b03a3a?style=for-the-badge&labelColor=0a0a0a" alt="Website">
  </a>
</p>

<p align="center">
  <a href="https://github.com/irraz/vulnerator-ai/actions/workflows/security.yml">
    <img src="https://github.com/irraz/vulnerator-ai/workflows/Security%20Pipeline/badge.svg" alt="Security Pipeline">
  </a>
  &nbsp;
  <a href="https://github.com/irraz/vulnerator-ai/actions/workflows/pr-checks.yml">
    <img src="https://github.com/irraz/vulnerator-ai/workflows/PR%20Quality%20Checks/badge.svg" alt="PR Checks">
  </a>
  &nbsp;
  <a href="https://github.com/irraz/vulnerator-ai/security/code-scanning">
    <img src="https://img.shields.io/badge/CodeQL-enabled-success?style=flat-square&logo=github" alt="CodeQL">
  </a>
  &nbsp;
  <a href=".github/SECURITY-PIPELINE.md">
    <img src="https://img.shields.io/badge/security-pipeline-blue?style=flat-square&logo=security" alt="Security">
  </a>
</p>

<p align="center">
  <sub><b>Built with</b></sub>
</p>

<p align="center">
  <a href="https://www.docker.com/">
    <img src="https://img.shields.io/badge/Docker-containers-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker containers">
  </a>
  &nbsp;
  <a href="https://hermes-agent.nousresearch.com/">
    <img src="https://img.shields.io/badge/Hermes%20Agent-Nous%20Research-7A5CFF?style=for-the-badge&logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0xMiAyQzYuNDggMiAyIDYuNDggMiAxMnM0LjQ4IDEwIDEwIDEwIDEwLTQuNDggMTAtMTBTMTcuNTIgMiAxMiAyem0wIDE4Yy00LjQxIDAtOC0zLjU5LTgtOHMzLjU5LTggOC04IDggMy41OSA4IDgtMy41OSA4LTggOHoiLz48L3N2Zz4=&logoColor=white" alt="Hermes Agent — Nous Research">
  </a>
  &nbsp;
  <a href="https://www.kali.org/">
    <img src="https://img.shields.io/badge/Kali%20Linux-pentest%20runtime-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux">
  </a>
</p>

<p align="center">
  <sub>
    Containerized with <a href="https://www.docker.com/">Docker</a> &middot;
    driven by <a href="https://hermes-agent.nousresearch.com/">Hermes Agent</a> from
    <a href="https://nousresearch.com/">Nous Research</a> &middot;
    tooling on <a href="https://www.kali.org/">Kali Linux</a>
  </sub>
</p>

---

<p align="center">
  <a href="https://youtu.be/XpCRds5raVs">
    <img src="https://img.youtube.com/vi/XpCRds5raVs/maxresdefault.jpg" alt="Vulnerator-AI Demo Video" width="720">
  </a>
</p>

<p align="center">
  <sub>▶️ <a href="https://youtu.be/XpCRds5raVs"><b>Watch the demo</b></a> — OODA loop pentest in action</sub>
</p>

---

OODA pentest driven by **Hermes** talking **directly** to a **Kali** container via MCP.

## What it is

`vulnerator-ai` runs an OODA (Observe-Orient-Decide-Act) pentest loop where
the driving brain is [Hermes](https://github.com/NousResearch/hermes) and the
tools run on a Kali governed by an MCP server. Hermes decides what
to run and launches it **directly** against the target through the Kali MCP.

It is a deliberately minimal design: **no core, no REST API, no UI, no gates**.
Four containers (the agent, two tool MCP servers and the MCP front door) and the agent driving
end to end.

## Architecture (4 containers)

![Vulnerator AI system architecture: an MCP client (Claude Code / Kiro / BugTraceAI) drives a pentest THROUGH the vulnerator-mcp front door (MCP, :8700 internal), which forwards to Hermes' :8642 runs API over HTTP Bearer; an external assistant can still trigger/observe Hermes directly over :8642. Hermes is the OODA brain, reasoning with mistralai/mistral-large on OpenRouter and driving the kali-mcp (:8900) and playwright-mcp (:8931) servers over MCP; kali runs the pentest tools against the authorized target. ATT&CK is the Orient language of the loop.](docs/architecture.svg)

- **kali** — deterministic runtime for pentest and collection tools (nmap, whatweb, nuclei, ffuf,
  sqlmap, Prowler, ...) over a `kali-mcp` server (`:8900`).
- **playwright-mcp** — real browser (headless Chromium) over MCP (`:8931`), the web surface used by
  the `web-pentest` skill.
- **ooda-agent** — Hermes (`nousresearch/hermes-agent`) as the OODA loop driver and client of both
  MCPs. Keeps its OpenAI-compatible API server alive on `:8642`.
- **vulnerator-mcp** — thin MCP **front door** over Hermes' `:8642` runs API so MCP clients
  (Claude Code / Kiro, BugTraceAI, ...) can trigger/observe/steer/stop a run. **Up by default**;
  it exposes **only** the runs lifecycle, never raw `kali_run` or `/v1/chat/completions`.

No `api` or `ui` service: the agent talks directly to the MCPs. See
**[`docs/design.md`](docs/design.md)** for the full architecture and the curated Kali toolset.

## Quick Start

The installer is the fast path: the **only** thing you provide is your OpenRouter API key. It
checks prerequisites (`docker`, `docker compose` v2, `openssl`), auto-generates the two secret
tokens, writes the `.env` from the template, and brings the default stack up.

```sh
./install.sh
```

Then open the interactive TUI:

```sh
docker compose exec -it ooda-agent hermes chat
```

Useful flags: `--with-juice-shop` (also start the OWASP Juice Shop practice lab), `--no-up`
(just write the `.env`), `--force` (overwrite an existing `.env`).

### Let an AI assistant set it up for you

Don't want to read any of this? Paste the block below to an LLM coding assistant (Claude Code,
Kiro, Cursor, …) that has shell access in this repo. It tells the assistant everything it needs to
install the stack and wire up the MCP server — you provide only your OpenRouter key when asked.

```text
You are setting up the "vulnerator-ai" repo for me. Do the following, in order:

1. From the repo root, run the installer:  ./install.sh
   It is interactive and will ask for ONE value, OPENROUTER_API_KEY — ask me for it
   and pass it through (or run it non-interactively as
   `OPENROUTER_API_KEY=<the key> ./install.sh`). The installer auto-generates the two
   secret tokens (HERMES_API_SERVER_KEY, VULNERATOR_MCP_INBOUND_TOKEN), writes the .env,
   and brings the default 4-container stack up (no Juice Shop lab). Do NOT invent or ask
   me for the two tokens — the installer makes them.

2. Wait until the stack is healthy, then verify with:  docker compose ps

3. Register the local MCP server (stdio mode — zero network surface, no inbound token).
   First build the image once:
       docker build -f docker/mcp/Dockerfile -t vulnerator-ai-mcp:dev .
   Then add this entry to my assistant's MCP config (mcpServers), filling HERMES_API_SERVER_KEY
   with the value the installer wrote into the repo's .env (read it from there, do not print it):
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
             "env": { "HERMES_API_SERVER_KEY": "<value from .env>" }
           }
         }
       }

4. Confirm the MCP tools are available (health(), start_pentest, get_run_status,
   stream_run_events, steer_run, stop_run). Then tell me it's ready and remind me this engine
   has NO scope-guard/consent/audit by default: it must be used only against authorized targets.
```

<details>
<summary>Manual setup (without the installer)</summary>

```sh
cp .env.example .env
# edit .env: set OPENROUTER_API_KEY, and generate the two tokens with `openssl rand -hex 32`:
#   HERMES_API_SERVER_KEY, VULNERATOR_MCP_INBOUND_TOKEN
docker compose up -d --build
```

Every variable is documented in **[`docs/configuration.md`](docs/configuration.md)**.
</details>

## Documentation

The README is intentionally short. The detail lives under [`docs/`](docs/):

| Topic | Doc |
| --- | --- |
| Project website | [irraz.github.io/vulnerator-ai](https://irraz.github.io/vulnerator-ai/) |
| Every `.env` variable, AWS creds, local Ollama inference | [`docs/configuration.md`](docs/configuration.md) |
| Driving a pentest (TUI, MCP client, raw HTTP), the Juice Shop lab, clean restarts | [`docs/usage.md`](docs/usage.md) |
| The no-guardrails model, opt-in scope-guard, MCP inbound token | [`docs/security.md`](docs/security.md) |
| **Automatic LLM fallback** (Mistral Large 4 ↔ GLM-5.3 Flash) | [`docs/llm-fallback.md`](docs/llm-fallback.md) |
| Raw HTTP API reference (`:8642`) | [`docs/http-api.md`](docs/http-api.md) |
| Architecture, OODA design, findings-store schema | [`docs/design.md`](docs/design.md) |
| Sample redacted deliverable | [`docs/example-report.md`](docs/example-report.md) |

## Models

Hermes uses **Mistral Large 4** as primary with automatic fallback to **GLM-5.3 Flash** on rate limits or errors. Both models have the same Cyber Index (50%) but different cost/performance trade-offs. See [`docs/llm-fallback.md`](docs/llm-fallback.md) for configuration and comparison.

## ⚠️ Security & authorized use

> **By default this product has no guardrails: no scope-guard, no consent, no audit, no
> authorization gate.** Hermes runs directly whatever it decides against the target. This is
> **intentional.** Use it **only against explicitly authorized targets** and in a **controlled
> environment**. All responsibility for the scope and for lawful use rests with the operator.

There are two opt-in controls (a deterministic scope-guard for `kali_run`/`kali_exec`, and the MCP
inbound token). Neither is consent or a firewall. See **[`docs/security.md`](docs/security.md)** for
what each does and does **not** cover.

## Media & brand assets

Official artwork lives in [`media/`](media/) (see [`media/README.md`](media/README.md) for the
full catalog). Death-metal / cyberpunk identity — use it for wallpapers, stickers and shirts.
There's also a theme song ([`media/vulnerator-ai-song.mp3`](media/vulnerator-ai-song.mp3), lyrics
in [`docs/lyrics.md`](docs/lyrics.md)) — a nod to the project's death-metal band aesthetic.

<p align="center">
  <a href="media/vulnerator-ai-logo-transparent.png">
    <img src="media/vulnerator-ai-logo-transparent.png" alt="Transparent logo (stickers / shirts)" height="150">
  </a>
  &nbsp;&nbsp;
  <a href="media/vulnerator-ai-wallpaper-desktop.jpeg">
    <img src="media/vulnerator-ai-wallpaper-desktop.jpeg" alt="Desktop wallpaper" height="150">
  </a>
  &nbsp;&nbsp;
  <a href="media/vulnerator-ai-wallpaper-mobile.jpeg">
    <img src="media/vulnerator-ai-wallpaper-mobile.jpeg" alt="Smartphone wallpaper" height="150">
  </a>
</p>

<p align="center">
  <sub>transparent logo (stickers / shirts) &middot; desktop wallpaper &middot; smartphone wallpaper</sub>
</p>

## 🤝 Sponsors

We are grateful for the support of companies that believe in advancing cybersecurity
knowledge and making security insights accessible to the community.

<p align="center">
  <a href="https://aktios.com/">
    <img src="https://sjimnar.github.io/assets/images/aktios.avif" alt="Aktios" height="80">
  </a>
</p>

**Special thanks to [Aktios](https://aktios.com/):** `vulnerator-ai` was born inside the
Aktios cybersecurity team, and we extend our sincere gratitude for their continued support.
Their commitment to cybersecurity made this project possible.

## License

Released under the [MIT License](LICENSE). You are free to use, modify and distribute this
software, including commercially, as long as the copyright notice and permission notice are
preserved. The software is provided "as is", without warranty of any kind.

> **Note on responsible use.** The MIT license governs the *code*, not how you may use it. This is
> an offensive security tool with **no scope-guard, consent or authorization gate by default** (see
> the ⚠️ Warning above). Use it **only against explicitly authorized targets**; responsibility for
> the scope and for lawful use rests entirely with the operator.
