# Caido integration

kali-mcp can drive [Caido](https://caido.io) — a web security toolkit (intercepting proxy, Replay,
HTTPQL history search, scope, workflows, findings). The goal: **anything Caido can do, Vulnerator
can do**, without wrapping every operation by hand.

## Tools

| Tool | What it does | Scope-guard |
|---|---|---|
| `caido_graphql` | Passthrough to Caido's **entire** public GraphQL API (Replay, scope, workflows, projects, intercept, findings, schema introspection…). Version-agnostic: if a query does not match the running Caido version, the server's GraphQL error is returned verbatim. | **Partial.** With `scope.json` active, documents that *send traffic* (Replay/Automate/workflows/intercept) are rejected and redirected to `caido_request`, because the destination is opaque inside a query. This is a best-effort denylist of send-capable fields (Caido's schema changes every release), not a proof. Without an active scope the passthrough is total. |
| `caido_request` | Sends an HTTP request to a target **through Caido's Replay**, waits for and returns the response: `status_code`, `length`, `roundtrip_ms` and the full `raw` response (headers + body, capped at `max_response_bytes`, default 20000, with `raw_truncated`). Traffic is logged in Caido (reproducible, searchable). Method, path and header names/values are validated (CR/LF/NUL are rejected, never sanitized) to prevent request injection. | **Yes** — same gate as `kali_run`/`kali_exec`. The full `scheme://host:port` is validated, so `allow`, `deny` and `ports` in `scope.json` are all honored. Blocked requests send **no traffic**. |
| `caido_history` | Searches captured traffic with an [HTTPQL](https://docs.caido.io) expression (e.g. `resp.code.eq:401`, `req.host.cont:"juice-shop"`). Read-only. | No (read-only) |

### Known limitations

- **`caido_graphql` scope filter** is a heuristic over mutation verbs, not a proof: a send-capable
  field whose name has none of them would pass while a scope is active, and a harmless mutation that
  contains one is rejected. Blocked calls are not written to the findings store (the tool has no
  `engagement_id`), unlike `caido_request`.
- **Response correlation** matches the replayed request by method/host/port/path and a history-id
  baseline taken before sending. Other traffic to the *same* method+path+host going through Caido's
  proxy at the same moment (e.g. a browser pointed at it) could be mistaken for the replay's response.
- **IPv6:** IPv4-mapped IPv6 literals (`::ffff:a.b.c.d`) are normalized to the IPv4 address before the
  scope check. `scope_guard` itself compares CIDRs only within one address family, which also affects
  `kali_run`; that is outside this change.

All data returned by Caido is **untrusted**: it is transported verbatim, never interpreted.

## Deployment

The `caido` service in `docker-compose.yml` runs the official `caido/caido` image on the internal
docker network only (`http://caido:8080`, **not** published to the host), with a persistent named
volume and a one-shot `caido-init` that fixes the volume's ownership (Caido runs as uid 996).

No configuration is needed — the defaults work out of the box:

```bash
docker compose up -d --build
```

## Authentication (zero-touch by default)

Caido's API only serves schema introspection unauthenticated; every real operation needs a
`Bearer` token **and a selected project**. `caido_client` handles both:

1. **Token** — `CAIDO_PAT` / `CAIDO_ACCESS_TOKEN` if set; otherwise the `loginAsGuest` mutation
   (the service starts with `--allow-guests`), which needs no account and no GUI.
2. **Project** — selects the first `READY` project, or creates one if there is none.

The session is cached, and renewed automatically (once) if Caido is recreated and the cached
token/project go stale.

**Security trade-off.** `--allow-guests` means *anything that can reach `http://caido:8080`* can obtain
a full-privilege token (read all captured traffic, send arbitrary Replay requests). "Not published
to the host" does **not** isolate Caido from other containers on the compose network — including a
deliberately vulnerable lab target, or an SSRF in one. That is fine for a local lab and for engagements
whose targets are external. If you run untrusted workloads on the same network, or publish the Caido
port, remove `--allow-guests` from the service command, set `CAIDO_ALLOW_GUEST=0` and use a
`CAIDO_PAT` (mint it once through an SSH tunnel to the GUI). `CAIDO_ALLOW_GUEST` is fail-closed: only
`1/true/yes/on` (or empty) enable the guest login; anything else (`0`, `no`, `off`, typos) disables it.

`CAIDO_PAT` lives in the kali container's environment, so the agent can read it through `kali_exec`.

Failure modes are explicit, never faked: `unauthenticated`, `unreachable`, `graphql_error`,
`timeout`, `failed`. `server_info` reports the configured Caido URL and whether a token is set.

## Schema versions

Caido states that its GraphQL schema changes on every release. The documents used by
`caido_request` / `caido_history` were verified end-to-end against **Caido 0.59.0**, which is the
default image tag (`caido/caido:0.59.0`). Override it with `CAIDO_IMAGE` to try another release;
`caido_graphql` keeps working across versions.

## Verifying the integration

Bring up Caido plus the OWASP Juice Shop lab target (internal network only) and call the tools:

```bash
docker compose -f docker-compose.yml -f docker-compose.target.yml up -d caido juice-shop
```

> **Gotcha, already fixed in the compose file:** Caido's own anti-DNS-rebinding protection
> rejects requests whose `Host` isn't `localhost` by default (same mechanism as
> `playwright-mcp`'s `--allowed-hosts`). The `caido` service command passes
> `--ui-domain caido` so it accepts the internal DNS name kali-mcp connects with; without it
> every call fails with `unauthenticated` and Caido logs `Domain caido not allowed`.

Then, from an MCP client connected to kali-mcp: `caido_request` with `url=http://juice-shop:3000/`
(expect `status_code: 200`), a `POST` to `/rest/user/login` with bad credentials (expect `401`),
and `caido_history` with `resp.code.eq:401` (expect that login entry). With a `scope.json` that
does not allow `juice-shop`, `caido_request` must fail with `SCOPE_VIOLATION` and the history
count must not change.

Unit tests: `docker/kali/tests/test_caido_client.py` and `test_caido_scope.py` (stdlib-only; no
Caido or network needed).
