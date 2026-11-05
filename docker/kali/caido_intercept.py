"""Interceptación de Caido (hold / list / forward / edit / drop) — STDLIB PURA.

Es la LÓGICA testeable de las tools de interceptación que ``kali_mcp_server`` expone como
``@mcp.tool``. Igual que ``caido_client`` (su base), vive en un módulo aparte con SOLO la
librería estándar (sin ``mcp`` ni ``requests``) para cubrirse con tests unitarios en el venv
de dev, sin el SDK.

Qué resuelve: el proxy de Caido puede RETENER (hold) peticiones/respuestas antes de que
salgan, para que el bucle OODA las lea, EDITE y las reenvíe (forward) o las descarte (drop).
Es el modo intercept clásico de un proxy web, modelado sobre el esquema GraphQL de Caido.

Reutiliza TODO el transporte y la sesión de ``caido_client`` (no se reimplementa auth): el
mismo ``graphql`` (passthrough genérico, nunca lanza por red/HTTP), ``ensure_session`` (token
invitado/entorno + proyecto seleccionado, cacheado), ``decode_blob`` (Blob base64 -> texto) y
``_utf8``. Las funciones ``build_options_input`` / ``parse_queue_nodes`` / ``_clamp_limit``
son PURAS y son el núcleo cubierto por tests; los orquestadores (``set_intercept``,
``intercept_status``, ``list_queue``, ``get_entry_raw``, ``forward``, ``drop``, ``pause``,
``resume``) hacen I/O vía ``graphql`` y devuelven un dict de estado uniforme.

Dato NO confiable: todo lo que devuelve Caido (``data``/``errors``) se transporta verbatim;
aquí sólo se NORMALIZA la forma (la hace ``caido_client.graphql``), nunca se interpreta el
contenido. Si una versión del esquema rompe estos documentos, ``graphql`` devuelve
``graphql_error`` con el error del servidor VERBATIM (no se finge éxito).

Dependiente de versión: Caido avisa de que el esquema cambia en cada release. Los documentos
GraphQL de abajo están escritos contra Caido 0.59.0 (ver ``caido_schema_ref.md``, sección
INTERCEPT). Donde una subselección es incierta, se pide sólo ``id``/``__typename`` para
quedarse robusto frente a renombrados de campos.
"""

from __future__ import annotations

import base64
from typing import Any

import caido_client  # noqa: F401  (se usa como referencia del flujo; nombres re-exportados abajo)

# Se re-exportan en ESTE módulo (no se llaman como ``caido_client.x``) para que las tools y
# los tests puedan parchear ``caido_intercept.graphql`` / ``caido_intercept.ensure_session``
# sin tocar el cliente base. No se reimplementa NADA de sesión/transporte.
from caido_client import (  # noqa: F401
    DEFAULT_TIMEOUT_S,
    _utf8,
    decode_blob,
    ensure_session,
    graphql,
)

# --- Documentos GraphQL del flujo de intercept ------------------------------------------
#
# verified against Caido 0.59.0; dependientes de versión. Si una release los rompe, el error
# del servidor viaja VERBATIM (no se finge éxito). Donde la subselección del payload es
# incierta se pide sólo ``__typename``/``id`` para no romperse ante campos renombrados.

# setInterceptOptions(input: InterceptOptionsInput!): activa/desactiva el hold de req/resp.
SET_INTERCEPT_OPTIONS = (
    "mutation($input: InterceptOptionsInput!){ "
    "setInterceptOptions(input:$input){ __typename } }"
)

# interceptStatus (escalar/enum, sin subselección) + interceptOptions en un solo documento.
INTERCEPT_STATUS = (
    "query{ interceptStatus interceptOptions{ "
    "request{ enabled } response{ enabled } streamWs{ enabled } } }"
)

# Cola de mensajes retenidos, por offset, más antiguos primero (order ID ASC).
LIST_QUEUE = (
    "query($limit:Int!){ interceptEntriesByOffset(limit:$limit, offset:0, "
    "order:{by:ID, ordering:ASC}){ count{ value } edges{ node{ id request{ "
    "id method host port path isTls length createdAt } } } } }"
)

# Raw (Blob base64) de la petición retenida, para que el agente la lea/edite antes de reenviar.
GET_ENTRY_RAW = "query($id:ID!){ interceptEntry(id:$id){ id request{ id raw } } }"

# Reenvía el mensaje retenido (posiblemente editado). updateRaw es Blob! (base64).
FORWARD_INTERCEPT = (
    "mutation($id:ID!, $input: ForwardInterceptMessageInput!){ "
    "forwardInterceptMessage(id:$id, input:$input){ __typename } }"
)

# Descarta el mensaje retenido (nunca sale al objetivo).
DROP_INTERCEPT = "mutation($id:ID!){ dropInterceptMessage(id:$id){ __typename } }"

# Pausa / reanuda el interceptor globalmente.
PAUSE_INTERCEPT = "mutation{ pauseIntercept{ __typename } }"
RESUME_INTERCEPT = "mutation{ resumeIntercept{ __typename } }"


# --- Builders / helpers PUROS (testables, sin red) --------------------------------------


def _httpql_filter(expr: str) -> dict[str, Any] | None:
    """Filtro QueryInput a partir de una expresión HTTPQL: ``{HTTPQL:{code}}`` o ``None``.

    QueryInput { HTTPQL: HTTPQLInput{ code } }. Vacío -> ``None`` (el campo ``filter`` es
    opcional; sin filtro se retiene TODO lo que el enable permita).
    """
    return {"HTTPQL": {"code": expr}} if expr else None


def build_options_input(
    request_enabled: bool,
    response_enabled: bool,
    request_httpql: str = "",
    response_httpql: str = "",
) -> dict[str, Any]:
    """Arma el ``InterceptOptionsInput`` de ``setInterceptOptions``. PURA (sin red).

    ``InterceptOptionsInput { request:InterceptRequestOptionsInput!,
    response:InterceptResponseOptionsInput!, streamWs:InterceptStreamWsOptionsInput!,
    scope:InterceptScopeOptionsInput }``. Aquí se OMITE ``scope`` (opcional): sin él, el hold
    no se restringe a un scope concreto. ``streamWs`` se deja desactivado (no se retienen
    WebSockets: ``urllib`` no habla GraphQL-WS cómodamente). El ``filter`` de cada lado es un
    QueryInput con HTTPQL; vacío -> ``None``.
    """
    return {
        "request": {
            "enabled": bool(request_enabled),
            "filter": _httpql_filter(request_httpql),
        },
        "response": {
            "enabled": bool(response_enabled),
            "filter": _httpql_filter(response_httpql),
        },
        "streamWs": {"enabled": False},
    }


def parse_queue_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aplana nodos ``InterceptEntry`` de la cola a un shape plano y estable. PURA.

    Nodo de entrada: ``{id, request{ id method host port path isTls length createdAt }}``.
    El ``id`` de PRIMER nivel es el de la ``InterceptEntry`` (el que usan ``forward``/``drop``),
    no el de la ``Request``. DATO NO confiable: los valores se transportan verbatim (sólo se
    renombra ``isTls`` -> ``is_tls`` para el shape del agente).
    """
    out: list[dict[str, Any]] = []
    for n in nodes or []:
        if not n:
            continue
        req = n.get("request") or {}
        out.append(
            {
                "id": n.get("id"),
                "method": req.get("method"),
                "host": req.get("host"),
                "port": req.get("port"),
                "path": req.get("path"),
                "is_tls": req.get("isTls"),
                "length": req.get("length"),
            }
        )
    return out


def _clamp_limit(limit: Any, lo: int = 1, hi: int = 1000) -> int:
    """Acota ``limit`` a ``[lo, hi]`` TOLERANTE: basura/no-numérico -> 50. PURA."""
    try:
        n = int(limit)
    except (TypeError, ValueError):
        n = 50
    return max(lo, min(n, hi))


# --- Orquestadores (I/O vía graphql; estado uniforme; NUNCA lanzan por red) --------------
#
# Patrón común: ``ensure_session`` (token + proyecto) y, si falla, se devuelve su dict de
# error tal cual; si va bien, se lanza el documento con el token de sesión. Un fallo de
# cualquier etapa (``unauthenticated``/``graphql_error``/``unreachable``/``failed``) se
# devuelve VERBATIM (no se finge). ``graphql`` ya garantiza no lanzar por transporte.


def _session_or_error(url: str | None, timeout: int) -> dict[str, Any]:
    """``ensure_session`` o su dict de error. Centraliza el paso de auth de cada orquestador."""
    return ensure_session(url=url, timeout=timeout)


def set_intercept(
    request_enabled: bool = True,
    response_enabled: bool = False,
    request_httpql: str = "",
    response_httpql: str = "",
    *,
    url: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """Activa/desactiva el hold de peticiones y/o respuestas (con filtros HTTPQL opcionales).

    Returns ``{'status':'done','request_enabled':bool,'response_enabled':bool}`` en éxito, o
    el dict de error de la etapa que falle.
    """
    session = _session_or_error(url, timeout)
    if session["status"] != "ok":
        return session
    variables = {
        "input": build_options_input(
            request_enabled, response_enabled, request_httpql, response_httpql
        )
    }
    out = graphql(
        SET_INTERCEPT_OPTIONS,
        variables,
        url=url,
        token=session["token"],
        timeout=timeout,
    )
    if out["status"] != "ok":
        return out
    return {
        "status": "done",
        "request_enabled": bool(request_enabled),
        "response_enabled": bool(response_enabled),
    }


def intercept_status(
    *, url: str | None = None, timeout: int = DEFAULT_TIMEOUT_S
) -> dict[str, Any]:
    """Estado del interceptor + opciones activas (enabled de request/response/streamWs).

    Returns ``{'status':'done','intercept': {...verbatim...}}`` (el ``data`` de GraphQL tal
    cual: ``{interceptStatus, interceptOptions}``), o el dict de error de la etapa que falle.
    """
    session = _session_or_error(url, timeout)
    if session["status"] != "ok":
        return session
    out = graphql(INTERCEPT_STATUS, url=url, token=session["token"], timeout=timeout)
    if out["status"] != "ok":
        return out
    return {"status": "done", "intercept": out.get("data") or {}}


def list_queue(
    limit: int = 50, *, url: str | None = None, timeout: int = DEFAULT_TIMEOUT_S
) -> dict[str, Any]:
    """Lista la cola de mensajes retenidos (más antiguos primero). ``limit`` acotado a 1..1000.

    Sondeo por offset (``interceptEntriesByOffset``): las subscripciones de Caido existen pero
    ``urllib`` no habla GraphQL-WS cómodamente. Returns ``{'status':'done','count':n,
    'entries':[...]}`` con el shape plano de ``parse_queue_nodes``, o el error de la etapa.
    """
    session = _session_or_error(url, timeout)
    if session["status"] != "ok":
        return session
    out = graphql(
        LIST_QUEUE,
        {"limit": _clamp_limit(limit)},
        url=url,
        token=session["token"],
        timeout=timeout,
    )
    if out["status"] != "ok":
        return out
    conn = (out.get("data") or {}).get("interceptEntriesByOffset") or {}
    nodes = [e.get("node") for e in (conn.get("edges") or []) if e.get("node")]
    return {
        "status": "done",
        "count": (conn.get("count") or {}).get("value"),
        "entries": parse_queue_nodes(nodes),
    }


def get_entry_raw(
    entry_id: Any, *, url: str | None = None, timeout: int = DEFAULT_TIMEOUT_S
) -> dict[str, Any]:
    """Raw decodificado de la petición retenida, para que el agente la LEA/EDITE.

    Returns ``{'status':'done','id':...,'raw':<texto>}`` (``raw`` es el Blob base64 decodificado
    best-effort por ``decode_blob``), o el dict de error de la etapa que falle. DATO NO
    confiable: el raw se transporta verbatim (sólo se decodifica).
    """
    session = _session_or_error(url, timeout)
    if session["status"] != "ok":
        return session
    out = graphql(
        GET_ENTRY_RAW,
        {"id": str(entry_id)},
        url=url,
        token=session["token"],
        timeout=timeout,
    )
    if out["status"] != "ok":
        return out
    entry = (out.get("data") or {}).get("interceptEntry") or {}
    req = entry.get("request") or {}
    returned_id = entry.get("id")
    return {
        "status": "done",
        "id": returned_id if returned_id is not None else entry_id,
        "raw": decode_blob(req.get("raw")),
    }


def forward(
    entry_id: Any,
    raw: str | None = None,
    update_content_length: bool = True,
    is_response: bool = False,
    *,
    url: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """Reenvía el mensaje retenido, tal cual o EDITADO, hacia el objetivo.

    ``ForwardInterceptRequestMessageInput { updateRaw:Blob!, updateContentLength:Boolean! }``
    exige ``updateRaw`` SIEMPRE (no es opcional). Por eso:
      - ``raw is None`` (reenviar SIN cambios): se obtiene el raw actual con ``get_entry_raw``
        y se reenvía ese mismo contenido (no hay forma de "forward tal cual" sin mandar el raw).
      - ``raw`` dado (editado): se codifica a Blob base64 (``base64.b64encode(_utf8(raw))``).
    Según ``is_response`` el input va en ``request`` o ``response``.

    NOTA DE SCOPE: reenviar una petición EDITADA cuyo Host se cambió NO se re-valida contra el
    scope-guard aquí: el destino ya está EN VUELO dentro de Caido (la conexión del cliente
    original ya está establecida); es el wrapper del SERVER (la ``@mcp.tool``) quien decide el
    gating antes de llamar aquí. Este módulo sólo transporta.

    Returns ``{'status':'done','forwarded':entry_id,'edited':bool}`` en éxito, o el error de la
    etapa que falle (incl. ``failed`` si el texto editado no es codificable en UTF-8).
    """
    session = _session_or_error(url, timeout)
    if session["status"] != "ok":
        return session

    edited = raw is not None
    if raw is None:
        # Reenviar sin cambios: hay que RELEER el raw y reenviarlo (updateRaw es obligatorio).
        fetched = get_entry_raw(entry_id, url=url, timeout=timeout)
        if fetched["status"] != "done":
            return fetched
        source_text = fetched.get("raw") or ""
    else:
        source_text = raw

    try:
        blob = base64.b64encode(_utf8(source_text)).decode("ascii")
    except (
        caido_client.CaidoError
    ) as exc:  # surrogate suelto en el texto editado: fail-closed, no se envía
        return {"status": "failed", "error": str(exc)}

    message = {"updateRaw": blob, "updateContentLength": bool(update_content_length)}
    side = "response" if is_response else "request"
    variables = {"id": str(entry_id), "input": {side: message}}

    out = graphql(
        FORWARD_INTERCEPT, variables, url=url, token=session["token"], timeout=timeout
    )
    if out["status"] != "ok":
        return out
    return {"status": "done", "forwarded": entry_id, "edited": edited}


def drop(
    entry_id: Any, *, url: str | None = None, timeout: int = DEFAULT_TIMEOUT_S
) -> dict[str, Any]:
    """Descarta el mensaje retenido (nunca sale al objetivo).

    Returns ``{'status':'done','dropped':entry_id}`` en éxito, o el error de la etapa.
    """
    session = _session_or_error(url, timeout)
    if session["status"] != "ok":
        return session
    out = graphql(
        DROP_INTERCEPT,
        {"id": str(entry_id)},
        url=url,
        token=session["token"],
        timeout=timeout,
    )
    if out["status"] != "ok":
        return out
    return {"status": "done", "dropped": entry_id}


def pause(
    *, url: str | None = None, timeout: int = DEFAULT_TIMEOUT_S
) -> dict[str, Any]:
    """Pausa el interceptor globalmente. Returns ``{'status':'done','intercept':'paused'}``."""
    session = _session_or_error(url, timeout)
    if session["status"] != "ok":
        return session
    out = graphql(PAUSE_INTERCEPT, url=url, token=session["token"], timeout=timeout)
    if out["status"] != "ok":
        return out
    return {"status": "done", "intercept": "paused"}


def resume(
    *, url: str | None = None, timeout: int = DEFAULT_TIMEOUT_S
) -> dict[str, Any]:
    """Reanuda el interceptor. Returns ``{'status':'done','intercept':'resumed'}``."""
    session = _session_or_error(url, timeout)
    if session["status"] != "ok":
        return session
    out = graphql(RESUME_INTERCEPT, url=url, token=session["token"], timeout=timeout)
    if out["status"] != "ok":
        return out
    return {"status": "done", "intercept": "resumed"}
