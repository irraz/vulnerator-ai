# Security Labs — Vulnerator AI

A collection of **local**, **intentionally vulnerable**, **authorized** labs for training, testing, and developing exploitation capabilities with Vulnerator.

> **WARNING — Authorized use only.** Every lab in this directory is designed to run **only on localhost** (bindings to `127.0.0.1` or a Docker network internal to the stack), never exposed to the public network. Do not run scans or exploits against external systems. Use only for local CTFs, authorized pentesting, and security-tool development.

---

## Lab index

| Lab | Vulnerability / CVE | Access | Docs |
| --- | --- | --- | --- |
| `php2shell-lab/` | PHP2Shell — CVE-2026-109618 / CVE-2026-109619: `session.upload_progress` file injection plus LFI / serialize-handler mismatch / OOM to RCE | nginx → PHP-FPM `127.0.0.1:18080`, Apache mod_php `127.0.0.1:18081`, direct PHP-FPM `127.0.0.1:9000` | [README](php2shell-lab/README.md), [CHAINS](php2shell-lab/CHAINS.md), [TESTING](php2shell-lab/TESTING.md), [MANIFEST](php2shell-lab/MANIFEST.md), [PROMPT](php2shell-lab/PROMPT.md), [examples/](php2shell-lab/examples/) |
| `looney-tunables-ctf/` | Looney Tunables — CVE-2023-4911: glibc 2.37-0ubuntu2 local privilege escalation via `GLIBC_TUNABLES` on Ubuntu 23.04 amd64 | Container/hostname `ubuntu-server-01` on the external `vulnerator-ai_default` network, no published ports; SSH `agent_user` / `agent_user` on port 22; goal: read `/root/flag.txt` | [README](looney-tunables-ctf/README.md), [pentest report example](looney-tunables-ctf/docs/pentest-report-example.html) |
| `pinguinazo-ssti/` | Flask/Jinja2 SSTI via `render_template_string` to RCE, reverse shell, `sudo java` to root and `/root/flag.txt` | Internal port `5000` on `vulnerator-ai_default`, no published ports; user `pinguinazo` | [README](pinguinazo-ssti/README.md), [pentest report example](pinguinazo-ssti/docs/pentest-report-example.html) |

---

## Available labs

### 1. `php2shell-lab/` — PHP2Shell (CVE-2026-109618 / CVE-2026-109619)

**Vulnerability:** Session file injection via `session.upload_progress` plus LFI / serialize-handler mismatch / OOM to RCE.

**Vulnerable version:** PHP 8.2.34 (fixed in 8.2.35, 8.3.36, 8.4.27 and 8.5.12).

**Services:**
- nginx → PHP-FPM (`127.0.0.1:18080`)
- Apache mod_php (`127.0.0.1:18081`)
- Direct PHP-FPM (`127.0.0.1:9000`)

**Reproducible chains:**
- **Chain A:** Session injection + LFI → RCE (fully reliable)
- **Chain B:** Not implemented
- **Chain C:** Handler mismatch (`php` vs `php_serialize`) → `__destruct`
- **Chain D:** Apache mod_php OOM → stale `EG()` → RCE (dependency-free 0-day)
- **Chain E:** Partial

**Docs:** [README.md](php2shell-lab/README.md), [CHAINS.md](php2shell-lab/CHAINS.md), [TESTING.md](php2shell-lab/TESTING.md), [MANIFEST.md](php2shell-lab/MANIFEST.md), [PROMPT.md](php2shell-lab/PROMPT.md), [examples/](php2shell-lab/examples/)

**References:**
- [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc) — original research
- [Ademking/php2shell-nuclei-templates](https://github.com/Ademking/php2shell-nuclei-templates) — Nuclei detection templates

**Quickstart:**
```bash
cd labs/php2shell-lab
docker compose up -d
curl -s http://127.0.0.1:18080/index.php  # Verify the service responds
```

### 2. `looney-tunables-ctf/` — Looney Tunables (CVE-2023-4911)

**Vulnerability:** glibc `ld.so` local privilege escalation through the `GLIBC_TUNABLES` environment variable (CVE-2023-4911), on Ubuntu 23.04 amd64 with glibc 2.37-0ubuntu2.

**Access:** Container and hostname `ubuntu-server-01` on the external `vulnerator-ai_default` network, with no published ports. Initial access is SSH as `agent_user` / `agent_user` on port 22. The goal is to escalate to root and read `/root/flag.txt`.

**Helper:** `run_agent_test.py` supports `status`, `exec`, `check-flag`, `shell` and `run-script`.

**Docs:** [README.md](looney-tunables-ctf/README.md), [pentest report example](looney-tunables-ctf/docs/pentest-report-example.html)

**Quickstart:**
```bash
cd labs/looney-tunables-ctf
docker compose up -d --build
python run_agent_test.py status
python run_agent_test.py check-flag
```

### 3. `pinguinazo-ssti/` — Flask/Jinja2 SSTI

**Vulnerability:** Server-side template injection (SSTI) in Flask/Jinja2 via `render_template_string`, leading to RCE, a reverse shell, `sudo java` privilege escalation to root, and `/root/flag.txt`.

**Access:** Internal port `5000` on the `vulnerator-ai_default` network, with no published ports; user `pinguinazo`. The Vulnerator/Kali container reaches the target as `pinguinazo-ssti:5000` over Docker DNS.

**Docs:** [README.md](pinguinazo-ssti/README.md), [pentest report example](pinguinazo-ssti/docs/pentest-report-example.html)

**Quickstart:**
```bash
# The Vulnerator-AI stack must be up first (creates the vulnerator-ai_default network)
cd /path/to/vulnerator-ai && docker compose up -d
cd labs/pinguinazo-ssti
docker compose up -d --build
```

---

## Common lab structure

Each lab follows this structure:

```
labs/<lab-name>/
├── README.md               # Overview, startup, configuration
├── CHAINS.md (optional)    # Technical detail of attack vectors
├── TESTING.md (optional)   # Verification guides and practical examples
├── docker-compose.yml      # Container orchestration
├── webroot/                # Vulnerable web application
├── *.ini                   # PHP/service configuration
└── fixtures/ (optional)    # Test data, payloads, etc.
```

---

## Adding a new lab

1. Create a directory under `labs/<lab-name>/`.
2. Include a `README.md` with:
   - The vulnerability description
   - The exact vulnerable version
   - Ports and services (all bound to `127.0.0.1` or an internal Docker network)
   - Startup and shutdown commands
3. Provide a `docker-compose.yml` bound **only** to `127.0.0.1` or an internal Docker network.
4. (Optional) Add `CHAINS.md` / `TESTING.md` for technical detail and verification.
5. Update this `labs/README.md` with an entry in the lab index and a section for the new lab.

---

## Using with Vulnerator

The labs are optimized for testing with Vulnerator/Hermes. When Vulnerator runs inside a Docker container (for example `vulnerator-ai-kali-1`), use `host.docker.internal` instead of `127.0.0.1` to reach labs published on the host:

```
Target: http://host.docker.internal:18080
```

Labs attached to the external `vulnerator-ai_default` network (`looney-tunables-ctf` and `pinguinazo-ssti`) are instead reachable from the Kali container by their container hostname, for example `ubuntu-server-01` or `pinguinazo-ssti:5000`.

---

## Safety and responsibility

- **Allowed:** local testing on your own machine, controlled lab environments, authorized local CTFs.
- **Prohibited:** running against external hosts, production infrastructure, or systems without explicit authorization.

**These labs are educational and research code.** The author is not responsible for misuse of these materials. Use them ethically and legally.

---

## General references

- [OWASP WebGoat](https://owasp.org/www-project-webgoat/) — generic web labs
- [VulnHub](https://www.vulnhub.com/) — vulnerable virtual machines
- [HackTheBox](https://www.hackthebox.com/) — online CTF platform
- [Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA)

---

**Last updated:** 24 November 2026
