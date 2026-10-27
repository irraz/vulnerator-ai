"""Cliente de la API de DNSDumpster (STDLIB PURA) — recon DNS + superficie de ataque.

Es la LÓGICA testeable del runner ``dns_recon`` que ``kali_mcp_server`` expone como
``@mcp.tool``. Igual que ``shell_exec`` / ``finding_store`` / ``scope_guard``, vive en un
módulo aparte que usa SOLO la librería estándar (``urllib``, sin ``mcp`` ni ``requests``)
para poder cubrirse con tests unitarios en el venv de dev, donde el SDK no está instalado.

Qué resuelve: DNSDumpster publica una API de pago que, dado un dominio, devuelve su
superficie de ataque (registros A/CNAME/MX/NS con sus IPs, ASN, PTR y banners HTTP/HTTPS,
más TXT). El bucle OODA la usa para, de un solo tiro, enumerar hosts e IPs del objetivo y
los servicios que exponen, sin lanzar DNS bruto. Este módulo encapsula el contrato REAL de
la API (aprendido de la doc oficial, ver ``docs/``):

  - Endpoint dominio:   ``GET https://api.dnsdumpster.com/domain/{domain}``
  - Endpoint banners:   ``GET https://api.dnsdumpster.com/banners/{CIDR}`` (máx. /24 = 254 hosts)
  - Auth:               header ``X-API-Key: <key>`` (la key vive en el dashboard de la cuenta)
  - Paginación:         ``?page=N`` (>200 registros requiere membresía Plus)
  - Mapa:               ``?map=1`` (Plus; base64 muy pesado — NO se pide por defecto)
  - Límites de cuenta:  free 50 registros, Plus 200
  - Rate limit:         1 request / 2s -> HTTP 429 ``{"error":"Rate limit exceeded"}``

Disciplina de rate limit: la API es estricta (1 req/2s). Este módulo SERIALIZA sus llamadas
con un throttle a nivel de módulo (reloj monotónico) de modo que ``recon_domain`` pueda
abanicar varias páginas/CIDRs sin que el llamante tenga que dormir a mano, y además
reintenta una vez ante un 429. Dato NO confiable: la respuesta de la API se transporta
verbatim; aquí sólo se normaliza su forma, nunca se interpreta su contenido.
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
API_KEY_HEADER = "X-API-Key"
API_KEY_ENV = "DNSDUMPSTER_API_KEY"

# Rate limit oficial: 1 request / 2s. Se respeta con margen para no comernos un 429 en
# ráfagas (abanico de páginas o de CIDRs). Overridable por si la cuenta cambia de plan.
MIN_INTERVAL_S = float(os.environ.get("DNSDUMPSTER_MIN_INTERVAL", "2.1"))
DEFAULT_TIMEOUT_S = int(os.environ.get("DNSDUMPSTER_TIMEOUT", "30"))

# Tipos de registro que la respuesta agrupa por sección; se normalizan en el mismo esquema.
_RECORD_SECTIONS = ("a", "cname", "mx", "ns")

# Reloj del último request (monotónico, a nivel de módulo). El throttle es best-effort y
# NO es thread-safe por diseño: el servidor MCP corre estos runners en background de forma
# serializada por ejecución; no se comparte entre procesos.
_last_request_ts = 0.0


class DnsDumpsterError(ValueError):
    """Entrada inválida para el cliente (fail-closed; no se hace ninguna request)."""


def _throttle() -> None:
    """Duerme lo justo para respetar ``MIN_INTERVAL_S`` entre requests consecutivas."""
    global _last_request_ts
    now = time.monotonic()
    wait = MIN_INTERVAL_S - (now - _last_request_ts)
    if wait > 0:
        time.sleep(wait)
    _last_request_ts = time.monotonic()


def _validate_domain(domain: Any) -> str:
    """Valida que ``domain`` sea un string no vacío y sin esquema/espacios.

    NO resuelve ni comprueba que exista: sólo rechaza fail-closed lo que no sirve como
    path de la API (no-string, vacío, con ``/`` o espacios) para no construir una URL rota.
    """
    if not isinstance(domain, str) or not domain.strip():
        raise DnsDumpsterError("domain inválido: se espera un dominio no vacío.")
    d = domain.strip().lower()
    if d.startswith(("http://", "https://")):
        d = d.split("://", 1)[1]
    d = d.strip("/")
    if "/" in d or " " in d or not d:
        raise DnsDumpsterError(f"domain inválido: {domain!r}")
    return d


def _resolve_key(api_key: str | None) -> str:
    """Devuelve la API key explícita o la del entorno, o lanza fail-closed."""
    key = (api_key or os.environ.get(API_KEY_ENV, "")).strip()
    if not key:
        raise DnsDumpsterError(
            f"Falta la API key de DNSDumpster: pásala o exporta {API_KEY_ENV}."
        )
    return key


def _get(path: str, api_key: str, timeout: int) -> dict[str, Any]:
    """GET autenticado a ``API_BASE + path`` con throttle y manejo de errores HTTP.

    Returns un dict de estado uniforme (nunca lanza por un error HTTP; fail-closed con
    ``status='failed'``):
      - ``{'status':'ok','data':<json>}``
      - ``{'status':'rate_limited','error':...}``       (HTTP 429)
      - ``{'status':'unauthorized','error':...}``        (HTTP 401/403 — key inválida/plan)
      - ``{'status':'failed','error':...,'http_status':n}`` (otros)
    """
    url = f"{API_BASE}{path}"
    req = urllib.request.Request(url, headers={API_KEY_HEADER: api_key}, method="GET")
    _throttle()
    try:
        # nosec B310: el esquema es https FIJO (API_BASE) y el dominio se valida
        # (sin esquema propio ni '/'), así que no hay apertura de file:// ni esquemas raros.
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
                or f"HTTP {exc.code}: API key inválida o plan insuficiente.",
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
    """Consulta ``/domain/{domain}`` (una página) y devuelve el JSON crudo de la API.

    ``page`` mapea al parámetro ``?page=N`` (Plus para >200 registros); ``include_map``
    añade ``?map=1`` (Plus, base64 pesado). Reintenta UNA vez ante un 429 (respetando el
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
        # Un único reintento tras esperar el intervalo completo (el throttle del _get ya
        # separa, pero el 429 puede venir de una ráfaga previa del propio plan).
        time.sleep(MIN_INTERVAL_S)
        result = _get(path, key, timeout)
    return result


def query_banners(
    cidr: str,
    api_key: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """Consulta ``/banners/{CIDR}`` (banners de red; máx. /24 = 254 hosts).

    No valida el CIDR salvo que sea string no vacío (la API lo rechaza si es inválido):
    se transporta tal cual. Mismo dict de estado que ``query_domain``.
    """
    if not isinstance(cidr, str) or not cidr.strip():
        raise DnsDumpsterError(
            "cidr inválido: se espera un CIDR no vacío (p. ej. 1.2.3.0/24)."
        )
    key = _resolve_key(api_key)
    return _get(f"/banners/{cidr.strip()}", key, timeout)


# --------------------------------------------------------------- normalización de salida


def _iter_ip_entries(data: dict[str, Any]) -> list[dict[str, Any]]:
    """Aplana A/CNAME/MX/NS en una lista de registros {record_type, host, ip, ...}.

    La respuesta agrupa por sección y cada host lleva una lista ``ips``; aquí se desdobla
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
      - ``counts`` : conteos rápidos (hosts, ips, por tipo de registro).
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
      1) Consulta ``/domain`` hasta ``max_pages`` (parando cuando una página no aporta
         hosts nuevos; respeta el rate limit vía el throttle de ``_get``).
      2) Normaliza con ``extract_surface`` (hosts, IPs únicas, CIDRs, TXT).
      3) Si ``with_banners`` y la cuenta lo permite, consulta ``/banners/{CIDR}`` por cada
         CIDR único hallado y adjunta la salida cruda (dato NO confiable, verbatim).

    Returns ``{'status':'done', 'domain':..., 'surface':..., 'pages':n, 'banners':[...]}``
    o un dict de error de ``query_domain`` (``unauthorized``/``rate_limited``/``failed``)
    si la PRIMERA página falla. Las páginas/banners posteriores que fallen se anotan en
    ``warnings`` sin abortar (lo ya recolectado sigue siendo útil para el bucle OODA).
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
            # Concatena las secciones de registro de las páginas siguientes.
            for section in _RECORD_SECTIONS:
                if isinstance(data.get(section), list):
                    merged.setdefault(section, [])
                    merged[section].extend(data[section])
        surface_so_far = extract_surface(merged)
        if surface_so_far["counts"]["hosts"] == prev_host_count:
            break  # la página no aportó hosts nuevos: no seguimos paginando
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
