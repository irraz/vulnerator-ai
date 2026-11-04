"""Cliente de la API GraphQL de Caido (STDLIB PURA) — el canal del agente hacia Caido.

Es la LÓGICA testeable de las tools ``caido_graphql`` / ``caido_request`` / ``caido_history``
que ``kali_mcp_server`` expone como ``@mcp.tool``. Igual que ``dnsdumpster_client`` /
``shell_exec`` / ``scope_guard``, vive en un módulo aparte con SOLO la librería estándar
(sin ``mcp`` ni ``requests``; HTTP por ``urllib``) para cubrirse con tests unitarios en el
venv de dev, sin el SDK.

Qué resuelve: darle al bucle OODA acceso a TODA la superficie de Caido (el moderno toolkit
web, proxy + Replay + HTTPQL + workflows + scope + findings). Caido publica su API GraphQL
a propósito para herramientas de terceros, pero AVISA de que CAMBIA en cada release. Por eso
la pieza central es un passthrough genérico (``graphql``): Hermes manda la query/mutación y
funciona contra cualquier versión del esquema. Encima, dos orquestadores ergonómicos para
los caminos calientes —enviar una petición por Replay (``send_request``) y buscar en el
historial por HTTPQL (``search_history``)— construidos sobre el flujo REAL del esquema,
VERIFICADO EN VIVO contra una instancia + OWASP Juice Shop (ver docs/caido.md). Si el esquema
difiere en otra versión, el error GraphQL del servidor se transporta VERBATIM (no se finge).

Modelo de auth (verificado en vivo): la introspección del esquema NO necesita token, pero
TODA operación real (Replay, historial) exige ``Authorization: Bearer <token>`` y, además,
un PROYECTO seleccionado (el repositorio de datos es por-proyecto). Hay dos orígenes de token:
  - Token del operador por entorno: ``CAIDO_PAT`` (Personal Access Token) o
    ``CAIDO_ACCESS_TOKEN`` (token de sesión del GUI). Para un Caido con cuenta/licencia.
  - Invitado headless: si la instancia corre con ``--allow-guests`` (así la levanta el
    compose), ``loginAsGuest`` emite un token SIN cuenta ni login GUI -> integración
    ZERO-TOUCH. Es el camino por defecto para el lab autónomo.
``ensure_session`` resuelve ambos: usa el token de entorno si está; si no, inicia sesión de
invitado (cacheada), y en ambos casos SELECCIONA un proyecto (crea uno si no hay). Sin token
y sin invitados permitidos, las operaciones devuelven ``unauthenticated`` fail-closed (no se
finge; ``server_info`` refleja el estado).

Dato NO confiable: todo lo que devuelve Caido (``data``/``errors``) se transporta verbatim;
aquí sólo se NORMALIZA la forma del transporte (HTTP/JSON/errores GraphQL), nunca se
interpreta el contenido. Las funciones ``build_*``/``normalize_*``/``split_target_url`` son
PURAS y son el núcleo cubierto por tests; ``graphql``/``ensure_session``/``send_request``/
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

# --- Configuración por entorno (overridable; defaults para la red interna docker) -------

DEFAULT_URL = os.environ.get("CAIDO_URL", "http://caido:8080")
GRAPHQL_PATH = os.environ.get("CAIDO_GRAPHQL_PATH", "/graphql")
TOKEN_ENV = "CAIDO_PAT"
ALT_TOKEN_ENV = "CAIDO_ACCESS_TOKEN"


def _env_int(name: str, default: int) -> int:
    """Entero de entorno TOLERANTE: vacío o basura -> ``default`` (no aborta el servidor)."""
    try:
        return int((os.environ.get(name) or "").strip() or default)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    """Float de entorno TOLERANTE: vacío o basura -> ``default``."""
    try:
        return float((os.environ.get(name) or "").strip() or default)
    except ValueError:
        return default


DEFAULT_TIMEOUT_S = _env_int("CAIDO_TIMEOUT", 60)

# Login de invitado headless (loginAsGuest). On por defecto: el compose levanta Caido con
# --allow-guests, así las tools funcionan sin que el operador monte una cuenta. Se puede
# desactivar (CAIDO_ALLOW_GUEST=0) para forzar que sólo valga un token de entorno.
# FAIL-CLOSED: sólo valores explícitamente afirmativos (o vacío = default) lo activan; cualquier
# otro (0/false/no/off/basura) lo DESACTIVA, así "no" nunca deja el invitado abierto en silencio.
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

# Sondeo de la respuesta de Replay (es asíncrona: startReplayTask lanza y la respuesta
# aparece en el historial). Tope y cadencia del polling.
REPLAY_POLL_TRIES = _env_int("CAIDO_REPLAY_POLL_TRIES", 30)
REPLAY_POLL_INTERVAL_S = _env_float("CAIDO_REPLAY_POLL_INTERVAL", 1.0)

# Tope (bytes) del raw de la respuesta que se devuelve al agente (cabeceras + cuerpo); el resto
# se corta con ``raw_truncated=True``. Evita que una descarga enorme reviente el contexto.
DEFAULT_MAX_RESPONSE_BYTES = _env_int("CAIDO_MAX_RESPONSE_BYTES", 20000)

# Tope defensivo del cuerpo que leemos de una respuesta de error (evita tragar MB de HTML).
_MAX_ERROR_BODY = 2000


class CaidoError(ValueError):
    """Entrada inválida a una build_* (fail-closed: la tool no llega a llamar a Caido)."""


# --- Resolución de endpoint / token (I/O de entorno, sin red) ---------------------------


def resolve_url(url: str | None = None) -> str:
    """Normaliza la base de la instancia Caido (sin barra final), de arg o entorno."""
    base = (url or DEFAULT_URL or "").strip()
    if not base:
        raise CaidoError(
            "Falta la URL de Caido: pásala o exporta CAIDO_URL (p. ej. http://caido:8080)."
        )
    if "://" not in base:
        base = "http://" + base
    # Sólo http/https: `urlopen` aceptaría file://, ftp://... y CAIDO_URL es config del operador
    # pero no debe poder abrir ficheros locales por un descuido (bandit B310).
    try:
        scheme = urlsplit(base).scheme.lower()
    except ValueError as exc:
        raise CaidoError(f"CAIDO_URL inválida ({exc}): {base!r}") from exc
    if scheme not in ("http", "https"):
        raise CaidoError(
            f"CAIDO_URL con esquema no permitido ({scheme!r}): sólo http/https."
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
    """¿Hay token de entorno configurado? Lo usa ``server_info`` (sin llamar a Caido)."""
    return env_token() is not None


def graphql_endpoint(url: str | None = None) -> str:
    """URL completa del endpoint GraphQL (``<base><GRAPHQL_PATH>``)."""
    return resolve_url(url) + GRAPHQL_PATH


# --- Normalización de la respuesta (PURA: dict de transporte -> dict de estado) ----------


def normalize_graphql_response(payload: dict[str, Any]) -> dict[str, Any]:
    """Clasifica una respuesta GraphQL YA parseada (HTTP 200) en un estado uniforme.

    GraphQL devuelve 200 incluso con errores de resolución (array ``errors``). Caido marca
    los fallos de auth dentro de ``errors[].extensions.CAIDO.code == 'AUTHORIZATION'``; se
    detecta para devolver ``unauthenticated`` (señal accionable para el OODA), sin interpretar
    el resto. DATO NO CONFIABLE: ``data``/``errors`` verbatim.
      - ``{'status':'ok','data':...}``                           sin ``errors``.
      - ``{'status':'unauthenticated','error':...,'errors':...}`` si algún error es de auth.
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
                "error": "Caido rechazó el token (AUTHORIZATION/INVALID_TOKEN).",
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
    auth (la introspección y ``loginAsGuest`` no la necesitan; las operaciones devolverán
    ``unauthenticated``). Es el passthrough genérico sobre el que se apoyan todas las tools.

    Devuelve un dict de estado uniforme (fail-closed; el bloqueo/errores prevalecen):
      - ``{'status':'ok','data':...}``
      - ``{'status':'unauthenticated',...}``   (sin token válido / 401/403 / error de auth)
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
        # El esquema sale de CAIDO_URL (operador) y `resolve_url` sólo admite http/https: no hay
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
                or f"HTTP {exc.code}: token de Caido inválido o expirado.",
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
        # Conexión cortada a mitad, timeout de LECTURA, respuesta truncada/basura...: Caido
        # reiniciándose o un cuerpo lento. Estado reportable, nunca una excepción de la tool.
        return {
            "status": "unreachable",
            "error": f"Fallo de transporte con Caido ({endpoint}): {type(exc).__name__}: {exc}",
        }
    except (
        ValueError
    ) as exc:  # URL inválida en CAIDO_URL (InvalidURL/espacios/corchetes)
        return {
            "status": "failed",
            "error": f"URL de Caido inválida ({endpoint}): {exc}",
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


# --- Documentos GraphQL del flujo REAL (verificados en vivo; dependientes de versión) ---
#
# Caido avisa de que el esquema cambia en cada release. Estos documentos están VERIFICADOS
# contra una instancia real (ver docs/caido.md); si una versión los rompe, ``graphql``
# devuelve ``graphql_error`` con el error del servidor verbatim (no se finge éxito), y
# ``caido_graphql`` (passthrough) sigue alcanzando el esquema nuevo sin tocar este módulo.

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


# --- Gestión de sesión (token invitado/entorno + proyecto), cacheada y thread-safe ------

_SESSION: dict[str, Any] = {"token": None, "project_id": None}
_SESSION_LOCK = threading.Lock()


def reset_session() -> None:
    """Limpia la sesión cacheada (token + proyecto). Para tests y re-auth tras expirar."""
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
                "loginAsGuest no emitió token (%s). ¿Corre Caido con --allow-guests?"
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
    explícito gana. Sin esquema se asume ``https``. ``path`` conserva la query para reproducir
    la petición tal cual. Fail-closed: una URL sin host es ``CaidoError``.
    """
    raw = (url or "").strip()
    if not raw:
        raise CaidoError("URL de objetivo vacía.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        host = parts.hostname
        explicit_port = (
            parts.port
        )  # lanza ValueError si es no numérico / fuera de rango
    except ValueError as exc:
        raise CaidoError(f"URL de objetivo inválida ({exc}): {url!r}") from exc
    if not host:
        raise CaidoError(f"URL sin host: {url!r}")
    host = host.rstrip(".")  # `example.com.` y `example.com` son el MISMO destino
    if not host:
        raise CaidoError(f"URL sin host: {url!r}")
    # Un IPv6 "IPv4-mapped" (::ffff:a.b.c.d, o ::ffff:a9fe:a9fe) CONECTA por IPv4 pero un CIDR
    # IPv4 de `deny` no lo casaría (familias distintas en el guard): se normaliza a la IPv4
    # real, así gate y conexión ven EXACTAMENTE el mismo destino (bypass hallado en revisión).
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
    """Valor correcto de ``Host``: corchetes para IPv6 y puerto sólo si NO es el por defecto."""
    h = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default = 443 if is_tls else 80
    return h if int(port) == default else f"{h}:{int(port)}"


def scope_target(target: dict[str, Any]) -> str:
    """Destino ``esquema://host:puerto`` que se declara al scope-guard (IPv6 con corchetes). PURA.

    Es la ÚNICA fuente de verdad del destino que se valida: se construye de lo mismo que se
    usa para conectar (``split_target_url``), nunca re-parseando la URL del usuario, así el
    gate y la conexión no pueden discrepar.
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
    """Construye una petición HTTP CRUDA (líneas CRLF). PURA.

    Garantiza ``Host`` (de ``host`` si no viene en ``headers``), añade ``Content-Length`` si
    hay cuerpo y no se declaró, y fuerza ``Connection: close`` si no se especifica (así el
    Replay no se queda esperando keep-alive). Lo demás, lo que se pasa y nada más (el objetivo
    ve exactamente lo pedido; DATO NO confiable transportado verbatim).
    """
    m = (method or "GET").strip().upper()
    if not _METHOD_RE.match(m):
        raise CaidoError(f"método HTTP inválido: {method!r}")
    p = (path or "/").strip() or "/"
    if not p.startswith("/"):
        p = "/" + p
    if _CTL_RE.search(p) or " " in p:
        raise CaidoError("path inválido: contiene CR/LF/NUL o espacios.")
    hdrs = {k: v for k, v in (headers or {}).items() if k and v is not None}
    # CRLF/NUL en nombre o valor de cabecera permitiría inyectar una segunda petición (request
    # smuggling/pipelining) hacia vhosts o rutas no previstas. Se rechaza, no se sanea.
    for k, v in hdrs.items():
        if _CTL_RE.search(str(k)) or _CTL_RE.search(str(v)) or ":" in str(k):
            raise CaidoError(f"cabecera inválida (CR/LF/NUL o ':' en el nombre): {k!r}")
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

    Codifica la petición cruda a base64 (el escalar ``Blob`` del esquema lo exige) y usa el
    nombre REAL del campo del esquema: ``isTLS`` (no ``isTls``). Valida host/puerto fail-closed.
    """
    h = (host or "").strip()
    if not h:
        raise CaidoError("host vacío: Replay necesita un destino.")
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise CaidoError(f"puerto inválido: {port!r}")
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

    ``httpql`` es la expresión de Caido (p. ej. ``resp.code.eq:200``); vacío trae los últimos
    ``limit`` sin filtrar. El filtro va en el campo REAL del esquema ``HTTPQLInput.code``.
    Orden por id descendente (lo más reciente primero). ``limit`` se acota a 1..1000.
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
    el OODA. Si no es base64 válido se devuelve tal cual (DATO NO confiable, no se revienta).
    """
    if not blob:
        return ""
    try:
        return base64.b64decode(blob).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - dato no confiable; best-effort
        return blob


# --- Orquestadores ergonómicos (I/O): enviar por Replay / buscar historial --------------


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
    """``graphql`` con la sesión cacheada y UN reintento si ésta quedó obsoleta.

    Si Caido se recrea (volumen nuevo -> secretos nuevos) o el proyecto temporal desaparece,
    el token/proyecto cacheados dejan de valer y TODAS las llamadas fallarían hasta reiniciar
    kali-mcp (reproducido en vivo). Ante ``unauthenticated``/``graphql_error`` se renueva la
    sesión (``force=True``) y se repite UNA vez. Sólo se usa en etapas SIN efecto lateral sobre
    el objetivo (crear sesión de Replay, consultar historial); nunca tras enviar tráfico, para
    no reenviar. Devuelve ``(resultado, sesión_vigente)``.
    """
    out = graphql(query, variables, url=url, token=session["token"], timeout=timeout)
    # Se renueva ante rechazo de auth, o ante el error interno de "sin proyecto/BD" (proyecto
    # temporal desaparecido). Un graphql_error LEGÍTIMO (HTTPQL malo, input inválido) NO debe
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
    """Último id de petición del historial: 0 si está vacío, ``None`` si la consulta FALLA.

    Línea base para correlacionar la respuesta de un Replay: sólo se aceptan entradas con id
    MAYOR, así una respuesta antigua de la misma URL nunca se confunde con la nueva.
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
    válido). DATO NO confiable: se transporta verbatim (sólo se decodifica y se corta).
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
    """Envía una petición al objetivo POR el Replay de Caido y DEVUELVE su respuesta.

    Flujo REAL (verificado en vivo): ``ensure_session`` (token invitado/entorno + proyecto)
    -> ``createReplaySession`` con la petición cruda (base64) y el destino -> ``startReplayTask``
    -> SONDEA el historial hasta que aparece la respuesta correlacionada por host/puerto/path.
    El tráfico queda en el proxy de Caido (reproducible, buscable por ``search_history``).

    Returns en éxito ``{'status':'done','session_id':..,'request':{...},'response':{status_code,
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
    ) as exc:  # entrada inválida: fail-closed, no se envía
        return {"status": "failed", "error": str(exc)}

    session = ensure_session(url=url, timeout=timeout)
    if session["status"] != "ok":
        return session
    # Etapa SIN efecto lateral: si la sesión cacheada está obsoleta, se renueva y repite.
    created, session = _graphql_reauth(
        CREATE_REPLAY_SESSION, variables, session, url, timeout
    )
    token = session["token"]
    if created["status"] != "ok":
        return created
    baseline_id = _latest_request_id(token, url, timeout)
    if baseline_id is None:
        # Sin línea base no se puede correlacionar con seguridad (aceptaría una respuesta
        # vieja como nueva). Fail-closed ANTES de enviar tráfico.
        return {
            "status": "failed",
            "error": "No se pudo leer el historial de Caido (línea base); no se envía.",
        }
    cs = (created.get("data") or {}).get("createReplaySession") or {}
    if not cs.get("session"):
        return {
            "status": "failed",
            "error": "createReplaySession no devolvió sesión: %s"
            % (cs.get("error") or "?"),
        }
    session_id = cs["session"]["id"]

    started = graphql(
        START_REPLAY_TASK, {"id": session_id}, url=url, token=token, timeout=timeout
    )
    if started["status"] != "ok":
        return started

    # La respuesta es asíncrona: sondea el historial por host/puerto/path con respuesta.
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
            "La respuesta de Replay no apareció en el historial tras "
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
    """Busca en el historial de tráfico de Caido por HTTPQL. Devuelve estado uniforme.

    ``ensure_session`` (token + proyecto) -> query ``requests`` filtrada. DATO NO confiable:
    los nodos se transportan verbatim. Returns ``{'status':'done','count':n,'entries':[...]}``
    en éxito, o el dict de error de la etapa que falle.
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


# Con scope activo `caido_graphql` no puede validar el destino de una query opaca, así que
# rechaza los documentos que ENVÍAN tráfico y remite a `caido_request` (que sí pasa por el
# scope-guard). En Caido enviar tráfico es SIEMPRE una mutation (Replay/Automate/workflows/
# intercept/plugins), así que las queries de lectura nunca se tocan (sin falsos positivos por
# mencionar `connectionInfo` o `automate` en un select). Dentro de una mutation se rechaza por
# VERBOS de envío (substring, no nombres exactos), para cubrir también campos que Caido añada o
# renombre en otra release. Sigue siendo una heurística (no una prueba): falla del lado seguro
# con las mutaciones de aspecto "ejecutable" y puede dejar pasar un campo de envío con un
# nombre sin ninguno de estos verbos; está documentado en docs/caido.md.
_MUTATION_RE = re.compile(r"\bmutation\b", re.IGNORECASE)
_SENDING_RE = re.compile(
    r"start|send|run|forward|replay|automate|connect|execute|fire|trigger|invoke|test|"
    r"workflow|plugin|pipeline|intercept",
    re.IGNORECASE,
)


def graphql_sends_traffic(query: str) -> bool:
    """¿El documento GraphQL es una mutation que parece enviar tráfico? PURA (heurística)."""
    doc = query or ""
    return bool(_MUTATION_RE.search(doc) and _SENDING_RE.search(doc))
