"""Cliente de la API GraphQL de Caido (STDLIB PURA) — el canal del agente hacia Caido.

It is the testable LOGIC of the ``caido_graphql`` / ``caido_request`` / ``caido_history`` tools
que ``kali_mcp_server`` expone como ``@mcp.tool``. Igual que ``dnsdumpster_client`` /
``shell_exec`` / ``scope_guard``, it lives in a separate module with ONLY the standard library
(sin ``mcp`` ni ``requests``; HTTP por ``urllib``) para cubrirse con tests unitarios en el
venv de dev, sin el SDK.

What it solves: give the OODA loop access to the ENTIRE Caido surface (the modern toolkit
web, proxy + Replay + HTTPQL + workflows + scope + findings). Caido publica su API GraphQL
intentionally for third-party tools, but WARNS that it CHANGES on every release. That is why
the centerpiece is a generic passthrough (``graphql``): Hermes sends the query/mutation and
works against any schema version. On top, two ergonomic orchestrators for
the hot paths —send a request via Replay (``send_request``) and search the
historial por HTTPQL (``search_history``)— construidos sobre el flujo REAL del esquema,
VERIFICADO EN VIVO contra una instancia + OWASP Juice Shop (ver docs/caido.md). Si el esquema
differs in another version, the server's GraphQL error is transported VERBATIM (not faked).

Auth model (live-verified): schema introspection does NOT need a token, but
EVERY real operation (Replay, history) requires ``Authorization: Bearer *** and, in addition,
a PROJECT selected (the data store is per-project). There are two token sources:
  - Token del operador por entorno: ``CAIDO_PAT`` (Personal Access Token) o
    ``CAIDO_ACCESS_TOKEN`` (GUI session token). For a Caido with an account/license.
  - Headless guest: if the instance runs with ``--allow-guests`` (as the
    compose starts it), ``loginAsGuest`` issues a token WITHOUT account or GUI login -> integration
    ZERO-TOUCH. This is the default path for the autonomous lab.
``ensure_session`` handles both: it uses the environment token if present; otherwise it logs in as
invitado (cacheada), y en ambos casos SELECCIONA un proyecto (crea uno si no hay). Sin token
y sin invitados permitidos, las operaciones devuelven ``unauthenticated`` fail-closed (no se
finge; ``server_info`` refleja el estado).

Dato NO confiable: todo lo que devuelve Caido (``data``/``errors``) se transporta verbatim;
here only the transport shape (HTTP/JSON/GraphQL errors) is NORMALIZED, it is never
interpreta el contenido. Las funciones ``build_*``/``normalize_*``/``split_target_url`` son
PURE and are the core covered by tests; ``graphql``/``ensure_session``/``send_request``/``
``search_history`` son los orquestadores con I/O de red.
"""

from __future__ import annotations

import base64
import http.client
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlsplit

# --- Environment configuration (overridable; defaults for the docker internal network) -------

DEFAULT_URL = os.environ.get("CAIDO_URL", "http://caido:8080")
GRAPHQL_PATH = os.environ.get("CAIDO_GRAPHQL_PATH", "/graphql")
TOKEN_ENV = "CAIDO_PAT"
ALT_TOKEN_ENV = "CAIDO_ACCESS_TOKEN"


def _env_int(name: str, default: int) -> int:
    """TOLERANT environment integer: empty or garbage -> ``default`` (does not abort the server)."""
    try:
        return int((os.environ.get(name) or "").strip() or default)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    """TOLERANT environment float: empty or garbage -> ``default``."""
    try:
        return float((os.environ.get(name) or "").strip() or default)
    except ValueError:
        return default


DEFAULT_TIMEOUT_S = _env_int("CAIDO_TIMEOUT", 60)

# Login de invitado headless (loginAsGuest). On por defecto: el compose levanta Caido con
# --allow-guests, so tools work without the operator setting up an account. It can be
# disabled (CAIDO_ALLOW_GUEST=0) to force only an environment token to be valid.
# FAIL-CLOSED: only explicitly affirmative values (or empty = default) enable it; any
# other (0/false/no/off/garbage) DISABLES it, so "no" never silently leaves the guest open.
ALLOW_GUEST = os.environ.get("CAIDO_ALLOW_GUEST", "1").strip().lower() in (
    "",
    "1",
    "true",
    "yes",
    "on",
)

# Nombre del proyecto que el cliente crea si la instancia no tiene ninguno (idempotente:
# si ya hay proyectos, selecciona el primero READY en vez de crear).
PROJECT_NAME = (os.environ.get("CAIDO_PROJECT") or "").strip() or "vulnerator"

# Polling of the Replay response (it is async: startReplayTask launches and the response
# aparece en el historial). Tope y cadencia del polling.
REPLAY_POLL_TRIES = _env_int("CAIDO_REPLAY_POLL_TRIES", 30)
REPLAY_POLL_INTERVAL_S = _env_float("CAIDO_REPLAY_POLL_INTERVAL", 1.0)

# Tope (bytes) del raw de la respuesta que se devuelve al agente (cabeceras + cuerpo); el resto
# se corta con ``raw_truncated=True``. Evita que una descarga enorme reviente el contexto.
DEFAULT_MAX_RESPONSE_BYTES = _env_int("CAIDO_MAX_RESPONSE_BYTES", 20000)

# Tope defensivo del cuerpo que leemos de una respuesta de error (evita tragar MB de HTML).
_MAX_ERROR_BODY = 2000


class CaidoError(ValueError):
    """Invalid input to a build_* (fail-closed: the tool never calls Caido)."""


# --- Endpoint / token resolution (environment I/O, no network) ---------------------------


def resolve_url(url: str | None = None) -> str:
    """Normaliza la base de la instancia Caido (sin barra final), de arg o entorno."""
    base = (url or DEFAULT_URL or "").strip()
    if not base:
        raise CaidoError(
            "Missing Caido URL: pass it or export CAIDO_URL (e.g. http://caido:8080)."
        )
    if "://" not in base:
        base = "http://" + base
    # Only http/https: `urlopen` would accept file://, ftp://... and CAIDO_URL is operator config
    # pero no debe poder abrir ficheros locales por un descuido (bandit B310).
    try:
        scheme = urlsplit(base).scheme.lower()
    except ValueError as exc:
        raise CaidoError(f"invalid CAIDO_URL ({exc}): {base!r}") from exc
    if scheme not in ("http", "https"):
        raise CaidoError(
            f"CAIDO_URL with disallowed scheme ({scheme!r}): only http/https."
        )
    return base.rstrip("/")


def resolve_url_safe(url: str | None = None) -> str:
    """Como ``resolve_url`` pero NO lanza: devuelve "" si no hay URL. Para ``server_info``."""
    try:
        return resolve_url(url)
    except CaidoError:
        return ""


def env_token() -> str | None:
    """Token del operador por entorno (PAT > access token), o ``None`` si no hay ninguno."""
    for candidate in (os.environ.get(TOKEN_ENV), os.environ.get(ALT_TOKEN_ENV)):
        if candidate and candidate.strip():
            return candidate.strip()
    return None


def token_present() -> bool:
    """Is an environment token configured? Used by ``server_info`` (without calling Caido)."""
    return env_token() is not None


def graphql_endpoint(url: str | None = None) -> str:
    """URL completa del endpoint GraphQL (``<base><GRAPHQL_PATH>``)."""
    return resolve_url(url) + GRAPHQL_PATH


# --- Response normalization (PURE: transport dict -> status dict) ----------


def normalize_graphql_response(payload: dict[str, Any]) -> dict[str, Any]:
    """Clasifica una respuesta GraphQL YA parseada (HTTP 200) en un estado uniforme.

    GraphQL returns 200 even with resolver errors (``errors`` array). Caido marks
    los fallos de auth dentro de ``errors[].extensions.CAIDO.code == 'AUTHORIZATION'``; se
    detects to return ``unauthenticated`` (an actionable signal for the OODA), without interpreting
    el resto. DATO NO CONFIABLE: ``data``/``errors`` verbatim.
      - ``{'status':'ok','data':...}``                           sin ``errors``.
      - ``{'status':'unauthenticated','error':...,'errors':...}`` if any error is auth-related.
      - ``{'status':'graphql_error','errors':...,'data':...}``    otros errores GraphQL.
    """
    errors = payload.get("errors")
    if not errors:
        return {"status": "ok", "data": payload.get("data")}
    for e in errors:
        ext = (e or {}).get("extensions") or {}
        caido = ext.get("CAIDO") or {}
        if (
            caido.get("code") == "AUTHORIZATION"
            or caido.get("reason") == "INVALID_TOKEN"
        ):
            return {
                "status": "unauthenticated",
                "error": "Caido rejected the token (AUTHORIZATION/INVALID_TOKEN).",
                "errors": errors,
            }
    return {"status": "graphql_error", "errors": errors, "data": payload.get("data")}


# --- Orquestador de red: transporte GraphQL (auth OPCIONAL) -----------------------------


def graphql(
    query: str,
    variables: dict[str, Any] | None = None,
    *,
    url: str | None = None,
    token: str | None = None,
    operation_name: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """POST al endpoint GraphQL de Caido. Nunca lanza por un error de red/HTTP.

    Transporte puro: si se pasa ``token`` adjunta ``Authorization: Bearer``; si no, va sin
    auth (introspection and ``loginAsGuest`` do not need it; operations will return
    ``unauthenticated``). It is the generic passthrough all tools rely on.

    Devuelve un dict de estado uniforme (fail-closed; el bloqueo/errores prevalecen):
      - ``{'status':'ok','data':...}``
      - ``{'status':'unauthenticated',...}``   (no valid token / 401/403 / auth error)
      - ``{'status':'graphql_error',...}``     (200 con errores GraphQL no-auth)
      - ``{'status':'unreachable','error':...}`` (no se pudo conectar)
      - ``{'status':'failed','http_status':n,'error':...}`` (otros HTTP / respuesta no-JSON)
    """
    try:
        endpoint = graphql_endpoint(url)
    except CaidoError as exc:
        return {"status": "failed", "error": str(exc)}

    body: dict[str, Any] = {"query": query, "variables": variables or {}}
    if operation_name:
        body["operationName"] = operation_name
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        # The scheme comes from CAIDO_URL (operator) and `resolve_url` only allows http/https: there is no
        # file:// ni esquemas raros, y ninguna entrada de Hermes llega a esta URL.
        with urllib.request.urlopen(  # noqa: S310  # nosec B310
            req, timeout=timeout
        ) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        err_body = ""
        try:
            err_body = exc.read().decode("utf-8", errors="replace")[:_MAX_ERROR_BODY]
        except Exception:  # noqa: BLE001 - informativo
            pass
        if exc.code in (401, 403):
            return {
                "status": "unauthenticated",
                "error": err_body
                or f"HTTP {exc.code}: Caido token invalid or expired.",
            }
        return {
            "status": "failed",
            "http_status": exc.code,
            "error": err_body or str(exc),
        }
    except urllib.error.URLError as exc:
        return {
            "status": "unreachable",
            "error": f"No se pudo conectar a Caido ({endpoint}): {exc.reason}",
        }
    except (OSError, http.client.HTTPException) as exc:
        # Connection cut mid-way, READ timeout, truncated/garbage response...: Caido
        # restarting or a slow body. A reportable status, never a tool exception.
        return {
            "status": "unreachable",
            "error": f"Fallo de transporte con Caido ({endpoint}): {type(exc).__name__}: {exc}",
        }
    except (
        ValueError
    ) as exc:  # invalid URL in CAIDO_URL (InvalidURL/spaces/brackets)
        return {
            "status": "failed",
            "error": f"invalid Caido URL ({endpoint}): {exc}",
        }

    try:
        parsed = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        return {"status": "failed", "error": f"Respuesta no-JSON de Caido: {exc}"}
    if not isinstance(parsed, dict):
        return {
            "status": "failed",
            "error": "Respuesta GraphQL inesperada (no es objeto).",
        }
    return normalize_graphql_response(parsed)


# --- GraphQL documents of the REAL flow (live-verified; version-dependent) ---
#
# Caido warns that the schema changes every release. These documents are VERIFIED
# against a real instance (see docs/caido.md); if a version breaks them, ``graphql``
# returns ``graphql_error`` with the server's error verbatim (success is not faked), and
# ``caido_graphql`` (passthrough) still reaches the new schema without touching this module.

_GUEST_LOGIN = (
    "mutation{ loginAsGuest{ token{ accessToken expiresAt } error{ __typename } } }"
)
_PROJECTS = "query{ projects{ id name status } }"
_SELECT_PROJECT = (
    "mutation($id:ID!){ selectProject(id:$id){ currentProject{ __typename } "
    "error{ __typename } } }"
)
_CREATE_PROJECT = (
    "mutation($i:CreateProjectInput!){ createProject(input:$i){ project{ id } "
    "error{ __typename } } }"
)
CREATE_REPLAY_SESSION = (
    "mutation($i:CreateReplaySessionInput!){ createReplaySession(input:$i){ "
    "session{ id } error{ __typename } } }"
)
START_REPLAY_TASK = "mutation($id:ID!){ startReplayTask(sessionId:$id){ task{ id } error{ __typename } } }"
REQUEST_RAW_QUERY = "query($id:ID!){ request(id:$id){ raw response{ raw } } }"
HISTORY_QUERY = (
    "query($f:HTTPQLInput,$n:Int!,$o:RequestResponseOrderInput){ "
    "requests(first:$n, filter:$f, order:$o){ count{ value } edges{ node{ "
    "id method host port path isTls length createdAt "
    "response{ id statusCode roundtripTime length createdAt } } } } }"
)


# --- Session management (guest/environment token + project), cached and thread-safe ------

_SESSION: dict[str, Any] = {"token": None, "project_id": None}
_SESSION_LOCK = threading.Lock()


def reset_session() -> None:
    """Clears the cached session (token + project). For tests and re-auth after expiry."""
    with _SESSION_LOCK:
        _SESSION["token"] = None
        _SESSION["project_id"] = None


def _guest_login(url: str | None, timeout: int) -> dict[str, Any]:
    """loginAsGuest -> ``{'status':'ok','token':...}`` o un dict de error de ``graphql``."""
    out = graphql(_GUEST_LOGIN, url=url, timeout=timeout)
    if out["status"] != "ok":
        return out
    payload = (out.get("data") or {}).get("loginAsGuest") or {}
    tok = (payload.get("token") or {}).get("accessToken")
    if not tok:
        return {
            "status": "unauthenticated",
            "error": (
                "loginAsGuest issued no token (%s). Is Caido running with --allow-guests?"
                % (payload.get("error") or "sin detalle")
            ),
        }
    return {"status": "ok", "token": tok}


def _ensure_project(token: str, url: str | None, timeout: int) -> dict[str, Any]:
    """Garantiza un proyecto SELECCIONADO (crea uno si no hay). Devuelve estado uniforme.

    El repositorio de datos de Caido es por-proyecto: sin proyecto seleccionado, Replay e
    historial fallan con un error interno de base de datos. Idempotente: si ya hay proyectos
    selecciona el primero READY; si no, crea ``PROJECT_NAME`` (temporary) y lo selecciona.
    """
    listing = graphql(_PROJECTS, url=url, token=token, timeout=timeout)
    if listing["status"] != "ok":
        return listing
    projects = (listing.get("data") or {}).get("projects") or []
    project_id = None
    for p in projects:
        if p.get("status") == "READY":
            project_id = p.get("id")
            break
    if project_id is None and projects:
        project_id = projects[0].get("id")
    if project_id is None:
        created = graphql(
            _CREATE_PROJECT,
            {"i": {"name": PROJECT_NAME, "temporary": True}},
            url=url,
            token=token,
            timeout=timeout,
        )
        if created["status"] != "ok":
            return created
        cp = (created.get("data") or {}).get("createProject") or {}
        if not cp.get("project"):
            return {
                "status": "failed",
                "error": "No se pudo crear proyecto en Caido: %s"
                % (cp.get("error") or "?"),
            }
        project_id = cp["project"]["id"]
    selected = graphql(
        _SELECT_PROJECT, {"id": project_id}, url=url, token=token, timeout=timeout
    )
    if selected["status"] != "ok":
        return selected
    return {"status": "ok", "project_id": project_id}


def ensure_session(
    url: str | None = None, timeout: int = DEFAULT_TIMEOUT_S, force: bool = False
) -> dict[str, Any]:
    """Resuelve (token, project_id) listos para operar. Cacheado y thread-safe.

    Orden: token de entorno (``CAIDO_PAT``/``CAIDO_ACCESS_TOKEN``) si hay; si no y
    ``ALLOW_GUEST``, ``loginAsGuest``; en ambos casos asegura un proyecto seleccionado.
    Sin token y sin invitados -> ``unauthenticated`` (no se finge).

    Returns ``{'status':'ok','token':...,'project_id':...}`` o un dict de error uniforme.
    """
    with _SESSION_LOCK:
        if not force and _SESSION["token"] and _SESSION["project_id"]:
            return {
                "status": "ok",
                "token": _SESSION["token"],
                "project_id": _SESSION["project_id"],
            }

        token = env_token()
        if token is None:
            if not ALLOW_GUEST:
                return {
                    "status": "unauthenticated",
                    "error": (
                        "Caido sin token y login de invitado desactivado "
                        "(CAIDO_ALLOW_GUEST=0): exporta CAIDO_PAT o CAIDO_ACCESS_TOKEN."
                    ),
                }
            guest = _guest_login(url, timeout)
            if guest["status"] != "ok":
                return guest
            token = guest["token"]

        proj = _ensure_project(token, url, timeout)
        if proj["status"] != "ok":
            return proj

        _SESSION["token"] = token
        _SESSION["project_id"] = proj["project_id"]
        return {"status": "ok", "token": token, "project_id": proj["project_id"]}


# --- Builders PUROS (testables) ---------------------------------------------------------


def split_target_url(url: str) -> dict[str, Any]:
    """Descompone una URL de objetivo en ``{host, port, is_tls, path}``. PURA.

    Deriva el esquema (``https`` -> tls y puerto 443 por defecto; ``http`` -> 80); un puerto
    explicit one wins. Without a scheme, ``https`` is assumed. ``path`` keeps the query to reproduce
    the request as-is. Fail-closed: a URL without a host is a ``CaidoError``.
    """
    raw = (url or "").strip()
    if not raw:
        raise CaidoError("empty target URL.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        host = parts.hostname
        explicit_port = (
            parts.port
        )  # raises ValueError if non-numeric / out of range
    except ValueError as exc:
        raise CaidoError(f"invalid target URL ({exc}): {url!r}") from exc
    if not host:
        raise CaidoError(f"URL sin host: {url!r}")
    host = host.rstrip(".")  # `example.com.` y `example.com` son el MISMO destino
    if not host:
        raise CaidoError(f"URL sin host: {url!r}")
    # Un IPv6 "IPv4-mapped" (::ffff:a.b.c.d, o ::ffff:a9fe:a9fe) CONECTA por IPv4 pero un CIDR
    # IPv4 of `deny` would not match (different families in the guard): it is normalized to the IPv4
    # actual, so gate and connection see EXACTLY the same destination (bypass found in review).
    try:
        _ip = ipaddress.ip_address(host)
    except ValueError:
        _ip = None
    if isinstance(_ip, ipaddress.IPv6Address) and _ip.ipv4_mapped is not None:
        host = str(_ip.ipv4_mapped)
    is_tls = parts.scheme == "https"
    port = explicit_port or (443 if is_tls else 80)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return {"host": host, "port": port, "is_tls": is_tls, "path": path}


def _utf8(text: str) -> bytes:
    """``text`` a bytes UTF-8; un surrogate suelto (p. ej. JSON ``"\\ud800"``) es ``CaidoError``."""
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CaidoError(
            f"texto no codificable en UTF-8 (surrogate suelto): {exc}"
        ) from exc


_METHOD_RE = re.compile(r"^[A-Za-z]{1,32}$")
_CTL_RE = re.compile(r"[\r\n\x00]")


def host_header_value(host: str, port: int, is_tls: bool) -> str:
    """Correct ``Host`` value: brackets for IPv6 and port only if NOT the default."""
    h = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default = 443 if is_tls else 80
    return h if int(port) == default else f"{h}:{int(port)}"


def scope_target(target: dict[str, Any]) -> str:
    """Destino ``esquema://host:puerto`` que se declara al scope-guard (IPv6 con corchetes). PURA.

    It is the ONLY source of truth of the validated target: built from the same thing that is
    used to connect (``split_target_url``), never re-parsing the user's URL, so the
    gate and the connection cannot disagree.
    """
    scheme = "https" if target["is_tls"] else "http"
    host = target["host"]
    host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{host}:{target['port']}"


def build_raw_request(
    method: str,
    path: str,
    host: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    http_version: str = "HTTP/1.1",
    host_header: str | None = None,
) -> str:
    """Builds a RAW HTTP request (CRLF lines). PURE.

    Ensures ``Host`` (from ``host`` if not in ``headers``), adds ``Content-Length`` if
    there is a body and it was not declared, and forces ``Connection: close`` if unspecified (so the
    Replay does not wait on keep-alive). Everything else: what is passed and nothing more (the target
    ve exactamente lo pedido; DATO NO confiable transportado verbatim).
    """
    m = (method or "GET").strip().upper()
    if not _METHOD_RE.match(m):
        raise CaidoError(f"invalid HTTP method: {method!r}")
    p = (path or "/").strip() or "/"
    if not p.startswith("/"):
        p = "/" + p
    if _CTL_RE.search(p) or " " in p:
        raise CaidoError("invalid path: contains CR/LF/NUL or spaces.")
    hdrs = {k: v for k, v in (headers or {}).items() if k and v is not None}
    # CRLF/NUL in a header name or value would allow injecting a second request (request
    # smuggling/pipelining) hacia vhosts o rutas no previstas. Se rechaza, no se sanea.
    for k, v in hdrs.items():
        if _CTL_RE.search(str(k)) or _CTL_RE.search(str(v)) or ":" in str(k):
            raise CaidoError(f"invalid header (CR/LF/NUL or ':' in the name): {k!r}")
    if not any(k.lower() == "host" for k in hdrs):
        hdrs["Host"] = host_header or host
    if body and not any(k.lower() == "content-length" for k in hdrs):
        hdrs["Content-Length"] = str(len(_utf8(body)))
    if not any(k.lower() == "connection" for k in hdrs):
        hdrs["Connection"] = "close"
    lines = [f"{m} {p} {http_version}"]
    lines.extend(f"{k}: {v}" for k, v in hdrs.items())
    return "\r\n".join(lines) + "\r\n\r\n" + (body or "")


def build_replay_input(
    host: str, port: int, is_tls: bool, raw_request: str
) -> dict[str, Any]:
    """Arma las ``variables`` de ``CREATE_REPLAY_SESSION``. PURA (sin red).

    Encodes the raw request to base64 (the schema's ``Blob`` scalar requires it) and uses the
    nombre REAL del campo del esquema: ``isTLS`` (no ``isTls``). Valida host/puerto fail-closed.
    """
    h = (host or "").strip()
    if not h:
        raise CaidoError("empty host: Replay needs a destination.")
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise CaidoError(f"invalid port: {port!r}")
    if not (1 <= p <= 65535):
        raise CaidoError(f"puerto fuera de rango (1..65535): {p}")
    blob = base64.b64encode(_utf8(raw_request or "")).decode("ascii")
    return {
        "i": {
            "kind": "HTTP",
            "requestSource": {
                "raw": {
                    "connectionInfo": {"host": h, "port": p, "isTLS": bool(is_tls)},
                    "raw": blob,
                }
            },
        }
    }


def build_history_vars(httpql: str = "", limit: int = 50) -> dict[str, Any]:
    """Arma las ``variables`` de ``HISTORY_QUERY``. PURA.

    ``httpql`` is Caido's expression (e.g. ``resp.code.eq:200``); empty brings the latest
    ``limit`` sin filtrar. El filtro va en el campo REAL del esquema ``HTTPQLInput.code``.
    Order by descending id (most recent first). ``limit`` is bounded to 1..1000.
    """
    try:
        n = int(limit)
    except (TypeError, ValueError):
        n = 50
    n = max(1, min(n, 1000))
    expr = (httpql or "").strip()
    return {
        "f": {"code": expr} if expr else None,
        "n": n,
        "o": {"by": "ID", "ordering": "DESC"},
    }


def decode_blob(blob: str | None) -> str:
    """Decodifica un ``Blob`` base64 de Caido a texto (best-effort). PURA.

    Los ``raw`` de request/response viajan como base64; esta ayuda los vuelve legibles para
    the OODA. If not valid base64 it is returned as-is (UNTRUSTED data, no crash).
    """
    if not blob:
        return ""
    try:
        return base64.b64decode(blob).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - dato no confiable; best-effort
        return blob


# --- Ergonomic orchestrators (I/O): send via Replay / search history --------------


_STALE_RE = re.compile(
    r"connection to the database|no project|project not|not selected", re.I
)


def _graphql_reauth(
    query: str,
    variables: dict[str, Any] | None,
    session: dict[str, Any],
    url: str | None,
    timeout: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """``graphql`` with the cached session and ONE retry if it became stale.

    Si Caido se recrea (volumen nuevo -> secretos nuevos) o el proyecto temporal desaparece,
    the cached token/project stop being valid and ALL calls would fail until the session is
    kali-mcp (reproducido en vivo). Ante ``unauthenticated``/``graphql_error`` se renueva la
    restarted (``force=True``), and it is retried ONCE. Only used in stages WITHOUT side effects on
    the target (create Replay session, query history); never after sending traffic, so as
    not to resend. Returns ``(result, current_session)``.
    """
    out = graphql(query, variables, url=url, token=session["token"], timeout=timeout)
    # Se renueva ante rechazo de auth, o ante el error interno de "sin proyecto/BD" (proyecto
    # temporary disappearance). A LEGITIMATE graphql_error (bad HTTPQL, invalid input) must NOT
    # forzar un login de invitado nuevo en cada llamada.
    stale_project = out["status"] == "graphql_error" and bool(
        _STALE_RE.search(json.dumps(out.get("errors") or []))
    )
    if out["status"] != "unauthenticated" and not stale_project:
        return out, session
    fresh = ensure_session(url=url, timeout=timeout, force=True)
    if fresh["status"] != "ok":
        return (
            out,
            session,
        )  # no se pudo renovar: devuelve el error original, informativo
    again = graphql(query, variables, url=url, token=fresh["token"], timeout=timeout)
    return again, fresh


def _latest_request_id(token: str, url: str | None, timeout: int) -> int | None:
    """Last request id in history: 0 if empty, ``None`` if the query FAILS.

    Baseline for correlating a Replay response: only entries with an id
    GREATER are accepted, so an old response from the same URL is never confused with the new one.
    """
    out = graphql(
        HISTORY_QUERY,
        build_history_vars("", limit=1),
        url=url,
        token=token,
        timeout=timeout,
    )
    if out["status"] != "ok":
        return None
    edges = ((out.get("data") or {}).get("requests") or {}).get("edges") or []
    try:
        return max(
            (int((e.get("node") or {}).get("id") or 0) for e in edges), default=0
        )
    except (TypeError, ValueError):
        return None


def _fetch_response_raw(
    request_id: Any, token: str, url: str | None, timeout: int, max_bytes: int
) -> tuple[str, bool]:
    """Raw (cabeceras + cuerpo) de la respuesta, decodificado y acotado a ``max_bytes``.

    Best-effort: si la consulta falla devuelve ``("", False)`` (el resto del resultado ya es
    valid). UNTRUSTED data: transported verbatim (only decoded and truncated).
    """
    out = graphql(
        REQUEST_RAW_QUERY,
        {"id": str(request_id)},
        url=url,
        token=token,
        timeout=timeout,
    )
    if out["status"] != "ok":
        return "", False
    resp = ((out.get("data") or {}).get("request") or {}).get("response") or {}
    text = decode_blob(resp.get("raw"))
    limit = max(0, int(max_bytes))
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text, False
    return encoded[:limit].decode("utf-8", errors="ignore"), True


def send_request(
    url_target: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    *,
    url: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_S,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> dict[str, Any]:
    """Sends a request to the target THROUGH Caido's Replay and RETURNS its response.

    Flujo REAL (verificado en vivo): ``ensure_session`` (token invitado/entorno + proyecto)
    -> ``createReplaySession`` with the raw request (base64) and the target -> ``startReplayTask``
    -> SONDEA el historial hasta que aparece la respuesta correlacionada por host/puerto/path.
    Traffic stays in Caido's proxy (reproducible, searchable via ``search_history``).

    Returns on success ``{'status':'done','session_id':..,'request':{...},'response':{status_code,
    length,roundtrip_ms,raw}}``; o el dict de error de la etapa que falle
    (``unauthenticated``/``unreachable``/``graphql_error``/``failed``); o ``timeout`` si la
    respuesta no llega dentro del polling.
    """
    try:
        target = split_target_url(url_target)
        raw_request = build_raw_request(
            method,
            target["path"],
            target["host"],
            headers=headers or {},
            body=body or "",
            host_header=host_header_value(
                target["host"], target["port"], target["is_tls"]
            ),
        )
        variables = build_replay_input(
            target["host"], target["port"], target["is_tls"], raw_request
        )
    except (
        CaidoError,
        UnicodeError,
    ) as exc:  # invalid input: fail-closed, nothing is sent
        return {"status": "failed", "error": str(exc)}

    session = ensure_session(url=url, timeout=timeout)
    if session["status"] != "ok":
        return session
    # Stage WITHOUT side effects: if the cached session is stale, it is renewed and retried.
    created, session = _graphql_reauth(
        CREATE_REPLAY_SESSION, variables, session, url, timeout
    )
    token = session["token"]
    if created["status"] != "ok":
        return created
    baseline_id = _latest_request_id(token, url, timeout)
    if baseline_id is None:
        # Without a baseline, correlation is unsafe (it would accept an old
        # response as new). Fail-closed BEFORE sending traffic.
        return {
            "status": "failed",
            "error": "Could not read Caido history (baseline); not sending.",
        }
    cs = (created.get("data") or {}).get("createReplaySession") or {}
    if not cs.get("session"):
        return {
            "status": "failed",
            "error": "createReplaySession returned no session: %s"
            % (cs.get("error") or "?"),
        }
    session_id = cs["session"]["id"]

    started = graphql(
        START_REPLAY_TASK, {"id": session_id}, url=url, token=token, timeout=timeout
    )
    if started["status"] != "ok":
        return started

    # The response is async: polls history by host/port/path for a response.
    hv = build_history_vars("", limit=20)
    for _ in range(REPLAY_POLL_TRIES):
        time.sleep(REPLAY_POLL_INTERVAL_S)
        hist = graphql(HISTORY_QUERY, hv, url=url, token=token, timeout=timeout)
        if hist["status"] != "ok":
            return hist
        edges = ((hist.get("data") or {}).get("requests") or {}).get("edges") or []
        for e in edges:
            n = e.get("node") or {}
            resp = n.get("response")
            try:
                is_new = int(n.get("id") or 0) > baseline_id
            except (TypeError, ValueError):
                is_new = False
            if (
                resp
                and is_new
                and (n.get("method") or "").upper() == (method or "GET").strip().upper()
                and n.get("host") == target["host"]
                and int(n.get("port") or 0) == int(target["port"])
                and (n.get("path") or "").split("?")[0] == target["path"].split("?")[0]
            ):
                raw_text, truncated = _fetch_response_raw(
                    n.get("id"), token, url, timeout, max_response_bytes
                )
                return {
                    "status": "done",
                    "session_id": session_id,
                    "request": {
                        "id": n.get("id"),
                        "method": n.get("method"),
                        "host": n.get("host"),
                        "port": n.get("port"),
                        "path": n.get("path"),
                        "is_tls": n.get("isTls"),
                    },
                    "response": {
                        "id": resp.get("id"),
                        "status_code": resp.get("statusCode"),
                        "length": resp.get("length"),
                        "roundtrip_ms": resp.get("roundtripTime"),
                        "raw": raw_text,
                        "raw_truncated": truncated,
                    },
                }
    return {
        "status": "timeout",
        "session_id": session_id,
        "error": (
            "Replay response did not appear in history after "
            f"{REPLAY_POLL_TRIES * REPLAY_POLL_INTERVAL_S:.0f}s. Consulta con caido_history."
        ),
    }


def search_history(
    httpql: str = "",
    limit: int = 50,
    *,
    url: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """Searches Caido traffic history by HTTPQL. Returns a uniform status.

    ``ensure_session`` (token + proyecto) -> query ``requests`` filtrada. DATO NO confiable:
    los nodos se transportan verbatim. Returns ``{'status':'done','count':n,'entries':[...]}``
    on success, or the error dict of the stage that fails.
    """
    session = ensure_session(url=url, timeout=timeout)
    if session["status"] != "ok":
        return session
    out, session = _graphql_reauth(
        HISTORY_QUERY,
        build_history_vars(httpql=httpql, limit=limit),
        session,
        url,
        timeout,
    )
    if out["status"] != "ok":
        return out
    conn = (out.get("data") or {}).get("requests") or {}
    entries = [e.get("node") for e in (conn.get("edges") or []) if e.get("node")]
    return {
        "status": "done",
        "count": (conn.get("count") or {}).get("value"),
        "entries": entries,
    }


# With an active scope, `caido_graphql` cannot validate the target of an opaque query, so it
# rejects documents that SEND traffic and refers to `caido_request` (which does pass through the
# scope-guard). In Caido, sending traffic is ALWAYS a mutation (Replay/Automate/workflows/
# intercept/plugins), so read queries are never touched (no false positives from
# mencionar `connectionInfo` o `automate` en un select). Dentro de una mutation se rechaza por
# SEND VERBS (substring, not exact names), to also cover fields Caido adds or
# renames in another release. It is still a heuristic (not a proof): it fails safe
# with "executable-looking" mutations and may let through a send field with a
# name lacking any of these verbs; this is documented in docs/caido.md.
_MUTATION_RE = re.compile(r"\bmutation\b", re.IGNORECASE)
_SENDING_RE = re.compile(
    r"start|send|run|forward|replay|automate|connect|execute|fire|trigger|invoke|test|"
    r"workflow|plugin|pipeline|intercept",
    re.IGNORECASE,
)


def graphql_sends_traffic(query: str) -> bool:
    """Is the GraphQL document a mutation that appears to send traffic? PURE (heuristic)."""
    doc = query or ""
    return bool(_MUTATION_RE.search(doc) and _SENDING_RE.search(doc))
