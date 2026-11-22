"""Caido interception (hold / list / forward / edit / drop) — PURE STDLIB.

It is the testable LOGIC of the interception tools that ``kali_mcp_server`` exposes as
``@mcp.tool``. Like ``caido_client`` (its base), it lives in a separate module with ONLY the
standard library (no ``mcp`` or ``requests``) so it can be covered by unit tests in the venv
de dev, sin el SDK.

What it solves: Caido's proxy can HOLD requests/responses before they
go out, so the OODA loop can read, EDIT and forward or drop them.
It is the classic intercept mode of a web proxy, modeled on Caido's GraphQL schema.

It REUSES ALL of ``caido_client``'s transport and session (auth is not reimplemented): the
same ``graphql`` (generic passthrough, never raises on network/HTTP), ``ensure_session`` (token
invitado/entorno + proyecto seleccionado, cacheado), ``decode_blob`` (Blob base64 -> texto) y
``_utf8``. Las funciones ``build_options_input`` / ``parse_queue_nodes`` / ``_clamp_limit``
are PURE and are the core covered by tests; the orchestrators (``set_intercept``,
``intercept_status``, ``list_queue``, ``get_entry_raw``, ``forward``, ``drop``, ``pause``,
``resume``) do I/O via ``graphql`` and return a uniform status dict.

Dato NO confiable: todo lo que devuelve Caido (``data``/``errors``) se transporta verbatim;
here only the form is NORMALIZED (by ``caido_client.graphql``), the content is never interpreted
If a schema version breaks these documents, ``graphql`` returns
``graphql_error`` with the server's error VERBATIM (success is not faked).

Version-dependent: Caido warns that the schema changes every release. The documents
GraphQL below are written against Caido 0.59.0 (see ``caido_schema_ref.md``, section
INTERCEPT). Where a subselection is uncertain, only ``id``/``__typename`` are requested to
quedarse robusto frente a renombrados de campos.
"""

from __future__ import annotations

import base64
from typing import Any

import caido_client  # noqa: F401  (se usa como referencia del flujo; nombres re-exportados abajo)

# They are re-exported in THIS module (not called as ``caido_client.x``) so tools and
# los tests puedan parchear ``caido_intercept.graphql`` / ``caido_intercept.ensure_session``
# without touching the base client. NOTHING about session/transport is reimplemented.
from caido_client import (  # noqa: F401
    DEFAULT_TIMEOUT_S,
    _utf8,
    decode_blob,
    ensure_session,
    graphql,
)

# --- Documentos GraphQL del flujo de intercept ------------------------------------------
#
# verified against Caido 0.59.0; version-dependent. If a release breaks them, the error
# from the server travels VERBATIM (success is not faked). Where the payload subselection is
# uncertain, only ``__typename``/``id`` are requested so renamed fields do not break it.

# setInterceptOptions(input: InterceptOptionsInput!): activa/desactiva el hold de req/resp.
SET_INTERCEPT_OPTIONS = (
    "mutation($input: InterceptOptionsInput!){ "
    "setInterceptOptions(input:$input){ __typename } }"
)

# interceptStatus (scalar/enum, no subselection) + interceptOptions in a single document.
INTERCEPT_STATUS = (
    "query{ interceptStatus interceptOptions{ "
    "request{ enabled } response{ enabled } streamWs{ enabled } } }"
)

# Queue of held messages, by offset, oldest first (order ID ASC).
LIST_QUEUE = (
    "query($limit:Int!){ interceptEntriesByOffset(limit:$limit, offset:0, "
    "order:{by:ID, ordering:ASC}){ count{ value } edges{ node{ id request{ "
    "id method host port path isTls length createdAt } } } } }"
)

# Raw (base64 Blob) of the held request, so the agent can read/edit it before forwarding.
GET_ENTRY_RAW = "query($id:ID!){ interceptEntry(id:$id){ id request{ id raw } } }"

# Forwards the held message (possibly edited). updateRaw is Blob! (base64).
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
    """QueryInput filter from an HTTPQL expression: ``{HTTPQL:{code}}`` or ``None``.

    QueryInput { HTTPQL: HTTPQLInput{ code } }. Empty -> ``None`` (the ``filter`` field is
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
    scope:InterceptScopeOptionsInput }``. ``scope`` is OMITTED here (optional): without it, hold
    no se restringe a un scope concreto. ``streamWs`` se deja desactivado (no se retienen
    WebSockets: ``urllib`` does not speak GraphQL-WS easily). Each side's ``filter`` is a
    QueryInput with HTTPQL; empty -> ``None``.
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
    not the ``Request``'s. UNTRUSTED data: values are transported verbatim (only
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
    """Clamps ``limit`` to ``[lo, hi]`` TOLERANTLY: garbage/non-numeric -> 50. PURE."""
    try:
        n = int(limit)
    except (TypeError, ValueError):
        n = 50
    return max(lo, min(n, hi))


# --- Orchestrators (I/O via graphql; uniform status; NEVER raise on network) --------------
#
# Common pattern: ``ensure_session`` (token + project) and, if it fails, its error dict is
# returned as-is; if it succeeds, the document is sent with the session token. A failure of
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

    Returns ``{'status':'done','request_enabled':bool,'response_enabled':bool}`` on success, or
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
    """Lists the queue of held messages (oldest first). ``limit`` bounded to 1..1000.

    Sondeo por offset (``interceptEntriesByOffset``): las subscripciones de Caido existen pero
    ``urllib`` does not speak GraphQL-WS easily. Returns ``{'status':'done','count':n,
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
    """Decoded raw of the held request, so the agent can READ/EDIT it.

    Returns ``{'status':'done','id':...,'raw':<texto>}`` (``raw`` es el Blob base64 decodificado
    best-effort por ``decode_blob``), o el dict de error de la etapa que falle. DATO NO
    trusted: the raw is transported verbatim (only decoded).
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
    """Forwards the held message, as-is or EDITED, toward the target.

    ``ForwardInterceptRequestMessageInput { updateRaw:Blob!, updateContentLength:Boolean! }``
    exige ``updateRaw`` SIEMPRE (no es opcional). Por eso:
      - ``raw is None`` (reenviar SIN cambios): se obtiene el raw actual con ``get_entry_raw``
        and that same content is forwarded (there is no way to "forward as-is" without sending the raw).
      - ``raw`` dado (editado): se codifica a Blob base64 (``base64.b64encode(_utf8(raw))``).
    Depending on ``is_response``, the input goes in ``request`` or ``response``.

    SCOPE NOTE: forwarding an EDITED request whose Host was changed is NOT re-validated against the
    scope-guard here: the target is already IN FLIGHT inside Caido (the client's
    original connection is already established); it is the SERVER wrapper (the ``@mcp.tool``) that decides the
    gating before calling here. This module only transports.

    Returns ``{'status':'done','forwarded':entry_id,'edited':bool}`` on success, or the error of the
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
    ) as exc:  # lone surrogate in the edited text: fail-closed, not sent
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

    Returns ``{'status':'done','dropped':entry_id}`` on success, or the error of the stage.
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
