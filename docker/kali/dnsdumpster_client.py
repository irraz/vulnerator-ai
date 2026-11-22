"""Cliente de la API de DNSDumpster (STDLIB PURA) — recon DNS + superficie de ataque.

It is the testable LOGIC of the ``dns_recon`` runner that ``kali_mcp_server`` exposes as
``@mcp.tool``. Igual que ``shell_exec`` / ``finding_store`` / ``scope_guard``, vive en un
separate module that uses ONLY the standard library (``urllib``, no ``mcp`` or ``requests``)
so it can be covered by unit tests in the dev venv, where the SDK is not installed.

What it solves: DNSDumpster offers a paid API that, given a domain, returns its
superficie de ataque (registros A/CNAME/MX/NS con sus IPs, ASN, PTR y banners HTTP/HTTPS,
plus TXT). The OODA loop uses it to enumerate target hosts and IPs in one shot, and
the services they expose, without running raw DNS. This module encapsulates the REAL contract of
la API (aprendido de la doc oficial, ver ``docs/``):

  - Endpoint dominio:   ``GET https://api.dnsdumpster.com/domain/{domain}``
  - Banners endpoint:   ``GET https://api.dnsdumpster.com/banners/{CIDR}`` (max /24 = 254 hosts)
  - Auth:               header ``X-API-Key: <key>`` (la key vive en el dashboard de la cuenta)
  - Pagination:         ``?page=N`` (>200 records requires a Plus membership)
  - Mapa:               ``?map=1`` (Plus; base64 muy pesado — NO se pide por defecto)
  - Account limits:  free 50 records, Plus 200
  - Rate limit:         1 request / 2s -> HTTP 429 ``{"error":"Rate limit exceeded"}``

Rate-limit discipline: the API is strict (1 req/2s). This module SERIALIZES its calls
with a module-level throttle (monotonic clock) so that ``recon_domain`` can
fan out over several pages/CIDRs without the caller having to sleep manually, and also
reintenta una vez ante un 429. Dato NO confiable: la respuesta de la API se transporta
verbatim; here only its shape is normalized, its content is never interpreted.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

# --- Contrato de la API (overridable por entorno para tests / self-hosting) ----------
API_BASE = os.environ.get("DNSDUMPSTER_API_BASE", "https://api.dnsdumpster.com").rstrip(
    "/"
)
API_KEY_HEADER = "X-API-Key"  # pragma: allowlist secret
API_KEY_ENV = "DNSDUMPSTER_API_KEY"  # pragma: allowlist secret

# Rate limit oficial: 1 request / 2s. Se respeta con margen para no comernos un 429 en
# bursts (fan-out of pages or CIDRs). Overridable in case the account changes plan.
MIN_INTERVAL_S = float(os.environ.get("DNSDUMPSTER_MIN_INTERVAL", "2.1"))
DEFAULT_TIMEOUT_S = int(os.environ.get("DNSDUMPSTER_TIMEOUT", "30"))

# Record types that the response groups by section; normalized into the same schema.
_RECORD_SECTIONS = ("a", "cname", "mx", "ns")

# Clock of the last request (monotonic, module-level). The throttle is best-effort and
# is NOT thread-safe by design: the MCP server runs these runners in the background in a
# serialized manner per execution; it is not shared across processes.
_last_request_ts = 0.0


class DnsDumpsterError(ValueError):
    """Invalid input for the client (fail-closed; no request is made)."""


def _throttle() -> None:
    """Duerme lo justo para respetar ``MIN_INTERVAL_S`` entre requests consecutivas."""
    global _last_request_ts
    now = time.monotonic()
    wait = MIN_INTERVAL_S - (now - _last_request_ts)
    if wait > 0:
        time.sleep(wait)
    _last_request_ts = time.monotonic()


def _validate_domain(domain: Any) -> str:
    """Validates that ``domain`` is a non-empty string with no scheme/spaces.

    It does not resolve or check existence: it only fail-closed rejects what is unusable as a
    API path (non-string, empty, with ``/`` or spaces) to avoid building a broken URL.
    """
    if not isinstance(domain, str) or not domain.strip():
        raise DnsDumpsterError("invalid domain: expected a non-empty domain.")
    d = domain.strip().lower()
    if d.startswith(("http://", "https://")):
        d = d.split("://", 1)[1]
    d = d.strip("/")
    if "/" in d or " " in d or not d:
        raise DnsDumpsterError(f"invalid domain: {domain!r}")
    return d


def _resolve_key(api_key: str | None) -> str:
    """Returns the explicit API key or the environment one, or fails closed."""
    key = (api_key or os.environ.get(API_KEY_ENV, "")).strip()
    if not key:
        raise DnsDumpsterError(
            f"Missing DNSDumpster API key: pass it or export {API_KEY_ENV}."
        )
    return key


def _get(path: str, api_key: str, timeout: int) -> dict[str, Any]:
    """GET autenticado a ``API_BASE + path`` con throttle y manejo de errores HTTP.

    Returns un dict de estado uniforme (nunca lanza por un error HTTP; fail-closed con
    ``status='failed'``):
      - ``{'status':'ok','data':<json>}``
      - ``{'status':'rate_limited','error':...}``       (HTTP 429)
      - ``{'status':'unauthorized','error':...}``        (HTTP 401/403 — invalid key/plan)
      - ``{'status':'failed','error':...,'http_status':n}`` (otros)
    """
    url = f"{API_BASE}{path}"
    req = urllib.request.Request(url, headers={API_KEY_HEADER: api_key}, method="GET")
    _throttle()
    try:
        # nosec B310: el esquema es https FIJO (API_BASE) y el dominio se valida
        # (no own scheme or '/'), so there is no file:// opening or exotic schemes.
        with urllib.request.urlopen(
            req, timeout=timeout
        ) as resp:  # noqa: S310 - https fijo
            raw = resp.read().decode("utf-8", errors="replace")
        return {"status": "ok", "data": json.loads(raw)}
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")[:500]
        except Exception:  # noqa: BLE001 - informativo
            pass
        if exc.code == 429:
            return {"status": "rate_limited", "error": body or "Rate limit exceeded"}
        if exc.code in (401, 403):
            return {
                "status": "unauthorized",
                "error": body
                or f"HTTP {exc.code}: invalid API key or insufficient plan.",
            }
        return {"status": "failed", "http_status": exc.code, "error": body or str(exc)}
    except urllib.error.URLError as exc:
        return {"status": "failed", "error": f"Error de red: {exc.reason}"}
    except (ValueError, json.JSONDecodeError) as exc:
        return {"status": "failed", "error": f"Respuesta no-JSON de la API: {exc}"}


def query_domain(
    domain: str,
    api_key: str | None = None,
    page: int = 1,
    include_map: bool = False,
    timeout: int = DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """Queries ``/domain/{domain}`` (one page) and returns the raw API JSON.

    ``page`` maps to parameter ``?page=N`` (Plus for >200 records); ``include_map``
    adds ``?map=1`` (Plus, heavy base64). Retries ONCE on a 429 (respecting the
    rate limit). Dato NO confiable: ``data`` se devuelve verbatim.
    """
    d = _validate_domain(domain)
    key = _resolve_key(api_key)
    params = []
    if page and page > 1:
        params.append(f"page={int(page)}")
    if include_map:
        params.append("map=1")
    qs = f"?{'&'.join(params)}" if params else ""
    path = f"/domain/{d}{qs}"

    result = _get(path, key, timeout)
    if result["status"] == "rate_limited":
        # A single retry after waiting the full interval (the _get throttle already
        # separates them, but the 429 may come from an earlier burst of the plan itself).
        time.sleep(MIN_INTERVAL_S)
        result = _get(path, key, timeout)
    return result


def query_banners(
    cidr: str,
    api_key: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """Queries ``/banners/{CIDR}`` (network banners; max /24 = 254 hosts).

    It does not validate the CIDR beyond being a non-empty string (the API rejects invalid ones):
    se transporta tal cual. Mismo dict de estado que ``query_domain``.
    """
    if not isinstance(cidr, str) or not cidr.strip():
        raise DnsDumpsterError(
            "invalid cidr: expected a non-empty CIDR (e.g. 1.2.3.0/24)."
        )
    key = _resolve_key(api_key)
    return _get(f"/banners/{cidr.strip()}", key, timeout)


# --------------------------------------------------------------- output normalization


def _iter_ip_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Aplana A/CNAME/MX/NS en una lista de registros {record_type, host, ip, ...}.

    The response groups by section and each host has an ``ips`` list; here it is flattened
    a una fila por IP, conservando el tipo de registro y los campos de banner si existen.
    Robusto a secciones ausentes o con forma inesperada (dato NO confiable).
    """
    rows: list[dict[str, Any]] = []
    for section in _RECORD_SECTIONS:
        entries = data.get(section)
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            host = entry.get("host", "")
            ips = entry.get("ips")
            if not isinstance(ips, list):
                continue
            for ipobj in ips:
                if not isinstance(ipobj, dict):
                    continue
                banners = (
                    ipobj.get("banners")
                    if isinstance(ipobj.get("banners"), dict)
                    else {}
                )
                http = (
                    banners.get("http") if isinstance(banners.get("http"), dict) else {}
                )
                https = (
                    banners.get("https")
                    if isinstance(banners.get("https"), dict)
                    else {}
                )
                apps = []
                for b in (http, https):
                    for a in (
                        b.get("apps", []) if isinstance(b.get("apps"), list) else []
                    ):
                        if a and a not in apps:
                            apps.append(a)
                rows.append(
                    {
                        "record_type": section.upper(),
                        "host": host,
                        "ip": ipobj.get("ip", ""),
                        "asn": ipobj.get("asn", ""),
                        "asn_name": ipobj.get("asn_name", ""),
                        "asn_range": ipobj.get("asn_range", ""),
                        "country": ipobj.get("country", ""),
                        "country_code": ipobj.get("country_code", ""),
                        "ptr": ipobj.get("ptr", ""),
                        "http_server": http.get("server", ""),
                        "http_title": http.get("title", ""),
                        "https_cn": https.get("cn", ""),
                        "https_server": https.get("server", ""),
                        "apps": apps,
                    }
                )
    return rows


def extract_surface(data: dict[str, Any]) -> dict[str, Any]:
    """Normaliza el JSON de ``/domain`` en una superficie de ataque consumible.

    Devuelve ``{hosts:[...], ips:[...], cidrs:[...], txt:[...], counts:{...}}`` donde:
      - ``hosts``  : una fila por (host, IP) con ASN/PTR/banners (``_iter_ip_entries``).
      - ``ips``    : lista DEDUPLICADA de IPs vistas (para abanicar escaneos aguas abajo).
      - ``cidrs``  : lista DEDUPLICADA de ``asn_range`` (para el endpoint de banners).
      - ``txt``    : registros TXT verbatim (SPF/verificaciones).
      - ``counts`` : quick counts (hosts, ips, by record type).
    """
    if not isinstance(data, dict):
        return {"hosts": [], "ips": [], "cidrs": [], "txt": [], "counts": {}}
    hosts = _iter_ip_entries(data)
    ips: list[str] = []
    cidrs: list[str] = []
    for row in hosts:
        if row["ip"] and row["ip"] not in ips:
            ips.append(row["ip"])
        if row["asn_range"] and row["asn_range"] not in cidrs:
            cidrs.append(row["asn_range"])
    txt = (
        [t for t in data.get("txt", []) if isinstance(t, str)]
        if isinstance(data.get("txt"), list)
        else []
    )
    by_type: dict[str, int] = {}
    for row in hosts:
        by_type[row["record_type"]] = by_type.get(row["record_type"], 0) + 1
    return {
        "hosts": hosts,
        "ips": ips,
        "cidrs": cidrs,
        "txt": txt,
        "counts": {"hosts": len(hosts), "ips": len(ips), "by_record_type": by_type},
    }


def recon_domain(
    domain: str,
    api_key: str | None = None,
    max_pages: int = 1,
    with_banners: bool = False,
    timeout: int = DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """Recon de alto nivel: pagina ``/domain``, normaliza y (opcional) abanica banners.

    Flujo:
      1) Query ``/domain`` up to ``max_pages`` (stopping when a page brings no
         new hosts; respects the rate limit via ``_get``'s throttle).
      2) Normalizes with ``extract_surface`` (hosts, unique IPs, CIDRs, TXT).
      3) Si ``with_banners`` y la cuenta lo permite, consulta ``/banners/{CIDR}`` por cada
         single CIDR found and attaches the raw output (UNTRUSTED data, verbatim).

    Returns ``{'status':'done', 'domain':..., 'surface':..., 'pages':n, 'banners':[...]}``
    o un dict de error de ``query_domain`` (``unauthorized``/``rate_limited``/``failed``)
    if the FIRST page fails. Later pages/banners that fail are noted in
    ``warnings`` without aborting (what was already collected remains useful for the OODA loop).
    """
    d = _validate_domain(domain)
    key = _resolve_key(api_key)

    merged: dict[str, Any] = {}
    warnings: list[str] = []
    pages_read = 0
    prev_host_count = -1

    for page in range(1, max(1, int(max_pages)) + 1):
        res = query_domain(d, key, page=page, timeout=timeout)
        if res["status"] != "ok":
            if page == 1:
                return res  # el primer fallo es fatal: no hay nada que devolver
            warnings.append(f"page {page}: {res['status']} - {res.get('error', '')}")
            break
        data = res["data"]
        pages_read += 1
        if page == 1:
            merged = data
        else:
            # Concatenate the record sections of the following pages.
            for section in _RECORD_SECTIONS:
                if isinstance(data.get(section), list):
                    merged.setdefault(section, [])
                    merged[section].extend(data[section])
        surface_so_far = extract_surface(merged)
        if surface_so_far["counts"]["hosts"] == prev_host_count:
            break  # the page brought no new hosts: do not keep paginating
        prev_host_count = surface_so_far["counts"]["hosts"]

    surface = extract_surface(merged)

    banners: list[dict[str, Any]] = []
    if with_banners:
        for cidr in surface["cidrs"]:
            bres = query_banners(cidr, key, timeout=timeout)
            if bres["status"] == "ok":
                banners.append({"cidr": cidr, "data": bres["data"]})
            else:
                warnings.append(
                    f"banners {cidr}: {bres['status']} - {bres.get('error', '')}"
                )

    out: dict[str, Any] = {
        "status": "done",
        "domain": d,
        "pages": pages_read,
        "surface": surface,
    }
    if with_banners:
        out["banners"] = banners
    if warnings:
        out["warnings"] = warnings
    return out
