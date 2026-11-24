# php2shell-lab — Local vulnerable Docker lab (PHP2Shell)

A **local**, **vulnerable** and **authorized** lab environment for investigating the
PHP2Shell vulnerability (**CVE-2026-109618 / CVE-2026-109619**) in a controlled CTF
context. It is an adapted replica of the researcher's official lab at `ikow/php2shell-poc/lab`.

> **For use only in an authorized local CTF.** All services listen only on
> `127.0.0.1` and are never exposed to the network. Do not run scans or exploits against
> external systems. This lab is only for testing exploitation locally in a controlled way.

## What is the lab?

The vulnerability lives in PHP's `session.upload_progress` handler (enabled by
default) combined with the memory allocator's OOM bailout. It affects PHP from
version 5.4.0 up to 8.5.11, and is **fixed** in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.

To make the lab **actually vulnerable**, a pre-patch affected version is pinned. The
floating tags `php:8.2-fpm` / `php:8.2-apache` are not used because they now resolve
to the patched version (8.2.35+).

## PHP version running (verified)

Pinned tags: **`php:8.2.34-fpm`** and **`php:8.2.34-apache`**.

Exact version confirmed with `docker exec php2shell-fpm php -v`:

```
PHP 8.2.34 (cli) (built: Oct 21 2026 00:37:31) (NTS)
```

`8.2.34 < 8.2.35` → **vulnerable**.

## Endpoints and ports (all on 127.0.0.1)

| Service      | Container          | Binding                   | SAPI             | Description                       |
|--------------|--------------------|---------------------------|------------------|-----------------------------------|
| nginx → fpm  | `php2shell-nginx`  | `127.0.0.1:18080` → 80    | `fpm-fcgi`       | nginx as front end to php-fpm     |
| apache       | `php2shell-apache` | `127.0.0.1:18081` → 80    | `apache2handler` | Apache with mod_php               |
| php-fpm      | `php2shell-fpm`    | `127.0.0.1:9000` → 9000   | `fpm-fcgi`       | Direct FastCGI php-fpm            |

Quick check:

```bash
curl -s http://127.0.0.1:18080/index.php   # nginx -> php-fpm
curl -s http://127.0.0.1:18081/index.php   # apache mod_php
```

Expected output (version < 8.2.35 and `upload_progress 1`):

```
PHP 8.2.34
SAPI fpm-fcgi
upload_progress 1
OK
```

## Vulnerable configuration

`session.upload_progress` is **enabled** and cleanup is **disabled**, which allows
upload progress data to persist in session files:

- `session.upload_progress.enabled = On`
- `session.upload_progress.cleanup = Off`

See `php.ini` (FPM) and `php-apache.ini` (Apache mod_php). The Apache service also uses
`memory_limit = 32M` to expose the OOM surface needed for Chain D.

## Attack chain to endpoint mapping

| Chain    | Endpoint / file                                      | What it enables                                                          |
|----------|------------------------------------------------------|--------------------------------------------------------------------------|
| Chain A  | `vuln.php?page=...` (via :18080 / :18081)             | Simulated LFI (`include($_GET['page'])`) into the session file           |
| Chain C  | `app/` (`.user.ini` → `php_serialize`) and `api/` (`.user.ini` → `php`) | Different `session.serialize_handler` per directory   |
| Chain D  | Apache `:18081` (`memory_limit = 32M`)                | Allocator OOM (bailout) surface with reduced memory                      |

Supporting files:

- `webroot/index.php` — reports version, SAPI and `upload_progress` status.
- `webroot/nosession.php` — variant without `session_start`.
- `webroot/vuln.php` — simulated LFI for Chain A.
- `webroot/app/.user.ini` → `session.serialize_handler = php_serialize` (Chain C).
- `webroot/app/upload.php` — copy of `nosession.php`.
- `webroot/api/.user.ini` → `session.serialize_handler = php` (Chain C).
- `webroot/api/endpoint.php` — copy of `nosession.php`.

## Start and stop

```bash
# Start (from php2shell-lab/)
docker compose up -d

# Stop and remove containers + network
docker compose down
```

The initial image `pull` may take a while; use a generous timeout the first time.

## Additional documentation

- **[CHAINS.md](CHAINS.md)** — Technical detail of the five attack chains (A, B, C, D, E), full mechanics and example requests.
- **[TESTING.md](TESTING.md)** — Step-by-step verification guides with ready-to-run test scripts.
- **[MANIFEST.md](MANIFEST.md)** — Complete inventory of files, configurations and attack surface.
- **[examples/](examples/)** — Real reports of successful exploits run by Vulnerator against the lab (e.g. Chain A → confirmed RCE).

## External references

- Researcher's PoC repo: [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc)
- Nuclei templates: [Ademking/php2shell-nuclei-templates](https://github.com/Ademking/php2shell-nuclei-templates)
- CVE-2026-109618 (OOM corruption)
- CVE-2026-109619 (stale global state)
