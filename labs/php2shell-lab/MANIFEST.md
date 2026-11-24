# Manifest — PHP2Shell Lab

Complete inventory of the lab's files and configurations.

---

## Documentation files

| File             | Purpose                                                                 |
|------------------|-------------------------------------------------------------------------|
| `README.md`     | Overview, vulnerable version, start/stop, endpoints                     |
| `CHAINS.md`     | Technical detail of the five attack chains (A, B, C, D, E)              |
| `TESTING.md`    | Step-by-step verification guides with test scripts                      |
| `MANIFEST.md`   | This file — complete lab inventory                                      |
| `.gitignore`    | Exclude temporary files, logs and sessions from version control         |

---

## Infrastructure files

| File                 | Purpose                                                             |
|----------------------|-----------------------------------------------------------------------|
| `docker-compose.yml` | Orchestration of 3 containers: nginx, php-fpm, apache mod_php        |
| `nginx.conf`         | nginx reverse-proxy configuration to php-fpm                         |
| `php.ini`            | Vulnerable PHP-FPM configuration (`upload_progress=On`, `cleanup=Off`) |
| `php-apache.ini`     | Apache mod_php configuration (`memory_limit=32M` for Chain D)        |

---

## Vulnerable web application (`webroot/`)

| File / Directory     | Purpose                                                                |
|----------------------|--------------------------------------------------------------------------|
| `index.php`          | Main endpoint with `session_start()`, reports version/SAPI              |
| `nosession.php`      | Variant without `session_start()`, reports version                      |
| `vuln.php`           | **Simulated LFI** for Chain A (`include($_GET['page'])` unsanitized)   |
| `app/.user.ini`      | `php_serialize` handler (Chain C write)                                 |
| `app/upload.php`     | Copy of `nosession.php` with the `php_serialize` handler                |
| `api/.user.ini`      | `php` handler (Chain C read/deserialization)                           |
| `api/endpoint.php`   | Copy of `nosession.php` with the `php` handler                          |

---

## Docker containers

| Name               | Image               | Binding               | SAPI             | Purpose                            |
|--------------------|---------------------|-----------------------|------------------|------------------------------------|
| `php2shell-nginx`  | `nginx:alpine`      | `127.0.0.1:18080→80`  | (proxy)          | nginx front end to php-fpm         |
| `php2shell-fpm`    | `php:8.2.34-fpm`    | `127.0.0.1:9000→9000` | `fpm-fcgi`       | Vulnerable PHP-FPM (Chains A, C, E) |
| `php2shell-apache` | `php:8.2.34-apache` | `127.0.0.1:18081→80`  | `apache2handler` | Vulnerable Apache mod_php (Chain D)|

---

## Key vulnerable configuration

### PHP-FPM (`php.ini`)

```ini
session.upload_progress.enabled = On
session.upload_progress.cleanup = Off
session.use_strict_mode = 0
session.use_only_cookies = 0
session.save_path = /tmp/sessions
display_errors = On
error_reporting = E_ALL
```

### Apache mod_php (`php-apache.ini`)

```ini
memory_limit = 32M           # Low to facilitate OOM in Chain D
post_max_size = 256M
upload_max_filesize = 256M
session.upload_progress.enabled = On
session.upload_progress.cleanup = Off
display_errors = On
```

---

## Attack surface by chain

| Chain | Endpoint(s)                          | Key config                                   | Severity  |
|-------|--------------------------------------|----------------------------------------------|-----------|
| A     | `:18080/vuln.php` + `:18080/index.php`| `upload_progress=On`, `cleanup=Off`, LFI    | High      |
| B     | (not implemented)                    | Requires `unserialize()` endpoint + gadget   | High      |
| C     | `:18080/app/` + `:18080/api/`        | Handler mismatch via `.user.ini`             | High      |
| D     | `:18081/` (Apache mod_php)           | `memory_limit=32M`, OOM at startup           | Critical  |
| E     | `:18080/` (PHP-FPM)                  | Requires a large pre-populated session       | High      |

---

## Quick verification

```bash
# 1. Start the lab
docker compose up -d

# 2. Verify the vulnerable version
curl -s http://127.0.0.1:18080/index.php
# Expected output: PHP 8.2.34, SAPI fpm-fcgi, upload_progress 1

# 3. Confirm the containers are up
docker ps --filter "name=php2shell"

# 4. Stop the lab
docker compose down
```

For deeper chain-by-chain verification (multipart injection and LFI checks with curl), see **[TESTING.md](TESTING.md)**.

---

## Approximate sizes

- **Docker images:** ~150MB (`nginx:alpine`) + ~500MB (`php:8.2.34-fpm`) + ~500MB (`php:8.2.34-apache`) = ~1.15GB total
- **Webroot:** <10KB (minimal PHP files)
- **Configuration:** <5KB (`.ini` and `nginx.conf`)

---

## Technical references

- **CVE-2026-109618:** RCE via OOM corruption — `longjmp()` leaves request state invalid
- **CVE-2026-109619:** RCE via stale global state — worker retains freed request memory
- **Official patch:** [Commit 3584a98](https://github.com/php/php-src/commit/3584a98bda) — 300 files changed, replaces `longjmp()` with delayed soft OOM + hard `_exit()`
- **Original research:** [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc)
- **Detection templates:** [Ademking/php2shell-nuclei-templates](https://github.com/Ademking/php2shell-nuclei-templates)
- **Patched versions:** PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12 (canonical list from `README.md`)

---

**Lab created:** 21 October 2026
**Pinned vulnerable version:** PHP 8.2.34
**Authorized use:** local CTF, authorized pentesting, security tool development
**Prohibited:** use against external systems without explicit authorization
