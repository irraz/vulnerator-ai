"""Caido Automate (Intruder/ffuf-style fuzzing) in PURE STDLIB — the tool's logic.

Es la pieza testeable de la tool ``caido_automate`` que ``kali_mcp_server`` expone como
``@mcp.tool``. Like ``caido_client`` (Replay/history), it lives in a separate module with ONLY
the standard library (no ``mcp`` or ``requests``) and REUSES ``caido_client``'s transport
(``graphql``), so no HTTP is done here: all network I/O goes through that passthrough,
already verified. Nothing about token/project/session is reimplemented: ``ensure_session`` resolves the
auth (token de entorno o invitado headless) y un proyecto seleccionado.

What it solves: give the OODA loop Caido fuzzing — mark ONE injection point in a
raw request and run through a list of payloads, collecting status/length/time per payload.
El flujo REAL del esquema (verificado en vivo contra Caido 0.59.0 + OWASP Juice Shop) es:
``createAutomateSession`` (seeds the base request) -> ``updateAutomateSession`` (sets the
request + fuzz settings: payloads, placeholder, concurrency) -> ``startAutomateTask``
(launches; the AUTORITATIVE ``entry id`` comes from here) -> ``automateEntry`` is POLLED until the
result count stops growing or reaches the expected number of combinations.

Dato NO confiable: todo lo que devuelve Caido (payloads inyectados, status, longitudes, errores)
is transported verbatim; ``parse_entry_requests`` only decodes base64 Blobs and flattens the shape,
nunca interpreta el contenido. "No se finge": si cualquier etapa GraphQL falla, se devuelve su
dict de error tal cual (``graphql_error``/``unauthenticated``/``unreachable``/``failed``) y nunca
success is not faked. The ``build_*``/``parse_*`` functions are PURE (no network) and are the core
cubierto por tests; ``run_automate`` es el orquestador con I/O.

SCOPE GATING: this module ONLY sends. The MCP server wrapper (``kali_mcp_server``) is
quien valida el destino contra el scope-guard ANTES de invocar ``run_automate`` (igual que con
``caido_request``); the target is not re-validated here.

NOTA de esquema: Caido avisa de que su API GraphQL CAMBIA en cada release. Los documentos de
below are verified live against Caido 0.59.0 (see the real flow above); they are
VERSION-DEPENDENT. If another version breaks them, ``graphql`` returns the server's error
verbatim (no faking) and the generic ``caido_graphql`` tool still reaches the new schema.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import caido_client

# Reused from caido_client. Linked as module globals (not called at
# ``caido_client.graphql`` por ruta cualificada) para que ``run_automate`` use SIEMPRE estos
# nombres y los tests puedan monkeypatchear ``caido_automate.graphql`` /
# ``caido_automate.ensure_session`` sin tocar el cliente base.
from caido_client import (  # noqa: E402
    DEFAULT_TIMEOUT_S,
    build_raw_request,
    decode_blob,
    ensure_session,
    graphql,
    split_target_url,
    _utf8,
)

# --- Environment configuration (mirrors caido_client's REPLAY_POLL_*) --------------------
#
# The fuzzing result is ASYNCHRONOUS: startAutomateTask launches and rows appear little by
# poco en automateEntry. Tope y cadencia del sondeo, con los mismos helpers tolerantes.
AUTOMATE_POLL_TRIES = caido_client._env_int("CAIDO_AUTOMATE_POLL_TRIES", 60)
AUTOMATE_POLL_INTERVAL_S = caido_client._env_float("CAIDO_AUTOMATE_POLL_INTERVAL", 1.0)

# Default marker for the injection point (same as Caido/Burp's §).
DEFAULT_MARKER = "§"  # §

# Payload combination strategies (schema enum AutomatePayloadStrategy).
VALID_STRATEGIES = ("ALL", "SEQUENTIAL", "PARALLEL", "MATRIX")


# --- GraphQL documents of the Automate flow (live-verified; version-dependent) --
#
# VERIFICADOS contra Caido 0.59.0 (fuzz real sobre OWASP Juice Shop: apple->200, banana->200,
# bad payload->400). The introspection doc had 3 inaccuracies corrected here live:
#   - CreateAutomateSessionPayload has NO ``error`` field (only ``session``); ``entries``
#     needs ``{ id }`` subfields and returns empty [] on create (the entry is created at start).
#   - StartAutomateTaskPayload NO tiene campo ``error``; el ``entry id`` AUTORITATIVO sale de
#     ``automateTask.entry.id`` (NO de session.entries).
#   - UpdateAutomateSessionPayload DOES have ``error``.
#   - ``AutomateEntryRequest.payloads`` es ``[AutomateEntryRequestPayload]`` con
#     ``{ raw: Blob, position: Int }`` (raw = base64 del payload inyectado), no ``[String!]``.
CREATE_AUTOMATE_SESSION = (
    "mutation($i:CreateAutomateSessionInput!){ createAutomateSession(input:$i){ "
    "session{ id entries{ id } } } }"
)
UPDATE_AUTOMATE_SESSION = (
    "mutation($id:ID!,$i:UpdateAutomateSessionInput!){ "
    "updateAutomateSession(id:$id, input:$i){ session{ id } error{ __typename } } }"
)
START_AUTOMATE_TASK = (
    "mutation($id:ID!){ startAutomateTask(automateSessionId:$id){ "
    "automateTask{ id entry{ id } } } }"
)
# ``$n`` is DECLARED explicitly (the requestsByOffset limit). ``request{ id }`` is added
# to the minimal verified query to populate ``request_id`` (Request.id is a verified field).
AUTOMATE_ENTRY_QUERY = (
    "query($id:ID!,$n:Int!){ automateEntry(id:$id){ "
    "requestsByOffset(limit:$n, offset:0){ count{ value } edges{ node{ "
    "sequenceId payloads{ raw position } error "
    "request{ id response{ statusCode length roundtripTime } } } } } } }"
)


# --- Builders PUROS (testables, sin red) ------------------------------------------------


def build_placeholder_request(
    method: str,
    path: str,
    host: str,
    headers: dict[str, str] | None = None,
    body: str = "",
    marker: str = DEFAULT_MARKER,
) -> dict[str, Any]:
    """Builds the raw request and locates the fuzz injection point. PURE.

    El llamador pone EXACTAMENTE UN ``marker`` (en el path, el valor de una cabecera o el
    body) where it wants to inject the payload. The raw request is assembled with
    ``caido_client.build_raw_request``, se calcula el OFFSET EN BYTES del marcador sobre el raw
    codificado en UTF-8, se ELIMINA el marcador y se devuelve un placeholder de ancho cero
    (``start == end == offset``), i.e., the point where Caido will insert each payload.

    Fail-closed (el llamador maneja el ``CaidoError``):
      - empty or MISSING marker (0 occurrences) -> ``CaidoError``.
      - if it appears more than once, the FIRST one is used (no error for that; only for zero).

    Offsets en BYTES, no en caracteres: un cuerpo multibyte (p. ej. UTF-8 con acentos) hace
    the byte offset differs from the character index, and Caido works in bytes.

    Returns ``{"raw": <raw limpio sin el marcador>, "start": <int>, "end": <int>}``.
    """
    marker_bytes = _utf8(marker or "")
    if not marker_bytes:
        raise caido_client.CaidoError(
            "empty injection marker: set a marker (e.g. §)."
        )
    raw = build_raw_request(method, path, host, headers=headers or {}, body=body or "")
    raw_bytes = _utf8(raw)
    offset = raw_bytes.find(marker_bytes)
    if offset < 0:
        raise caido_client.CaidoError(
            "injection marker not found in the request: place exactly one "
            "(%r) en el path, una cabecera o el cuerpo." % marker
        )
    # Only the FIRST occurrence is removed (contract: a single marker); its byte offset
    # no cambia al quitarla (todo lo anterior queda intacto). Quitar una secuencia UTF-8
    # completion of valid UTF-8 text leaves valid UTF-8, so decoding is safe.
    clean_bytes = raw_bytes[:offset] + raw_bytes[offset + len(marker_bytes) :]
    clean_raw = clean_bytes.decode("utf-8")
    return {"raw": clean_raw, "start": offset, "end": offset}


def build_automate_settings(
    payloads: list[str],
    start: int,
    end: int,
    strategy: str = "SEQUENTIAL",
    workers: int = 10,
    delay: int = 0,
) -> dict[str, Any]:
    """Arma el ``AutomateSettingsInput`` del fuzz (lista simple de payloads). PURA.

    A single payload source (``simpleList``) injected into ONE placeholder. Redirects
    desactivadas (``NEVER``) y sin reintentos, para que cada fila sea el resultado DIRECTO de
    its payload (no faking). Fail-closed validation: ``payloads`` non-empty, ``workers >= 1`` and
    ``strategy`` dentro del enum; si no, ``CaidoError`` (la tool no llega a llamar a Caido).

    Returns el dict listo para ``UpdateAutomateSessionInput.settings``.
    """
    if not isinstance(payloads, (list, tuple)) or len(payloads) == 0:
        raise caido_client.CaidoError(
            "empty payload list: fuzzing needs at least one."
        )
    strat = (strategy or "").strip().upper()
    if strat not in VALID_STRATEGIES:
        raise caido_client.CaidoError(
            "invalid strategy %r: use one of %s."
            % (strategy, "/".join(VALID_STRATEGIES))
        )
    try:
        w = int(workers)
        d = int(delay)
        s = int(start)
        e = int(end)
    except (TypeError, ValueError) as exc:
        raise caido_client.CaidoError(
            f"workers/delay/start/end not numeric: {exc}"
        ) from exc
    if w < 1:
        raise caido_client.CaidoError(f"workers must be >= 1 (got {w}).")
    if d < 0:
        raise caido_client.CaidoError(f"delay cannot be negative (got {d}).")
    return {
        "payloads": [
            {
                "options": {"simpleList": {"list": [str(p) for p in payloads]}},
                "preprocessors": [],
            }
        ],
        "placeholders": [{"start": s, "end": e}],
        "redirect": {"strategy": "NEVER", "max": 0},
        "strategy": strat,
        "concurrency": {"workers": w, "delay": d},
        "retryOnFailure": {"maximumRetries": 0, "backoff": 0},
        "closeConnection": True,
        "updateContentLength": True,
        "extractors": [],
    }


def parse_entry_requests(nodes: list[dict] | None) -> list[dict[str, Any]]:
    """Aplana nodos ``AutomateEntryRequest`` a filas uniformes. PURA. Dato NO confiable.

    Cada ``payloads`` es ``[AutomateEntryRequestPayload{ raw:Blob, position:Int }]``: ``raw``
    es el base64 del payload INYECTADO, que se decodifica con ``caido_client.decode_blob`` a
    text. The ``response`` can be ``null`` (error row: failed connection, etc.): its
    campos quedan en ``None`` y el ``error`` se transporta verbatim. No se interpreta nada; los
    valores (status, longitud, tiempo) se pasan tal cual los da Caido.

    Returns ``[{"payloads": [...], "status_code": .., "length": .., "roundtrip_ms": ..,
    "error": .., "request_id": ..}]``.
    """
    results: list[dict[str, Any]] = []
    for node in nodes or []:
        node = node or {}
        payloads: list[Any] = []
        for p in node.get("payloads") or []:
            if isinstance(p, dict):
                payloads.append(decode_blob(p.get("raw")))
            else:  # forma inesperada: se transporta verbatim (no se revienta)
                payloads.append(p)
        req = node.get("request") or {}
        resp = req.get("response")  # puede ser None (fila de error)
        if resp is None:
            status_code = length = roundtrip_ms = None
        else:
            status_code = resp.get("statusCode")
            length = resp.get("length")
            roundtrip_ms = resp.get("roundtripTime")
        results.append(
            {
                "payloads": payloads,
                "status_code": status_code,
                "length": length,
                "roundtrip_ms": roundtrip_ms,
                "error": node.get("error"),
                "request_id": req.get("id"),
            }
        )
    return results


# --- Orchestrator (I/O via caido_client.graphql; returns uniform status, never raises) ----


def run_automate(
    url_target: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str = "",
    *,
    marker: str = DEFAULT_MARKER,
    payloads: list[str],
    strategy: str = "SEQUENTIAL",
    workers: int = 10,
    delay: int = 0,
    max_results: int = 500,
    url: str | None = None,
    timeout: int = DEFAULT_TIMEOUT_S,
) -> dict[str, Any]:
    """Ejecuta un fuzz de Automate contra ``url_target`` y DEVUELVE las filas por payload.

    REAL flow (live-verified): validate input -> ``ensure_session`` -> creates the
    Automate session with the base request -> UPDATES it with the request + fuzz settings -> launches the
    task (hence the authoritative ``entry id``) -> POLLS ``automateEntry`` until the count
    deja de crecer en 2 lecturas o alcanza el nº de combinaciones esperado (``len(payloads)``
    para ``SEQUENTIAL``) o se agota el sondeo.

    The server wrapper already validated the target scope BEFORE calling here (this module
    only sends). "No faking": if a GraphQL stage fails, its error dict is returned as-is.

    Returns on success ``{"status":"done","session_id":..,"entry_id":..,"count":n,
    "results":[...]}``; o el dict de error de la etapa que falle (``failed``/``unauthenticated``/
    ``unreachable``/``graphql_error``).
    """
    # 1-3. PURE builders: any invalid input is fail-closed BEFORE touching the network.
    try:
        target = split_target_url(url_target)
        placeholder = build_placeholder_request(
            method,
            target["path"],
            target["host"],
            headers=headers or {},
            body=body or "",
            marker=marker,
        )
        settings = build_automate_settings(
            payloads,
            placeholder["start"],
            placeholder["end"],
            strategy=strategy,
            workers=workers,
            delay=delay,
        )
    except (caido_client.CaidoError, UnicodeError) as exc:
        return {"status": "failed", "error": str(exc)}

    blob = base64.b64encode(_utf8(placeholder["raw"])).decode("ascii")
    conn = {
        "host": target["host"],
        "port": target["port"],
        "isTLS": target["is_tls"],  # REAL schema name: isTLS (capital letters)
    }

    # 4. Session (guest/environment token + project). If unresolved, its error is returned.
    session = ensure_session(url=url, timeout=timeout)
    if session["status"] != "ok":
        return session
    token = session["token"]

    # 5. createAutomateSession: seeds the base request. CreateAutomateSessionPayload has no
    #    error field; it is enough to check that a session came back.
    created = graphql(
        CREATE_AUTOMATE_SESSION,
        {"i": {"requestSource": {"raw": {"connectionInfo": conn, "raw": blob}}}},
        url=url,
        token=token,
        timeout=timeout,
    )
    if created["status"] != "ok":
        return created
    cs = (created.get("data") or {}).get("createAutomateSession") or {}
    if not cs.get("session"):
        return {
            "status": "failed",
            "error": "createAutomateSession returned no session.",
        }
    session_id = cs["session"]["id"]

    # 6. updateAutomateSession: sets request + fuzz settings (payloads, placeholder, etc.).
    updated = graphql(
        UPDATE_AUTOMATE_SESSION,
        {
            "id": session_id,
            "i": {"connection": conn, "raw": blob, "settings": settings},
        },
        url=url,
        token=token,
        timeout=timeout,
    )
    if updated["status"] != "ok":
        return updated

    # 7. startAutomateTask: LAUNCHES the fuzz. The AUTHORITATIVE entry id to poll comes from here
    #    (automateTask.entry.id), not from session.entries (empty on create).
    started = graphql(
        START_AUTOMATE_TASK, {"id": session_id}, url=url, token=token, timeout=timeout
    )
    if started["status"] != "ok":
        return started
    task = (started.get("data") or {}).get("startAutomateTask") or {}
    entry_id = ((task.get("automateTask") or {}).get("entry") or {}).get("id")
    if not entry_id:
        return {
            "status": "failed",
            "error": "startAutomateTask returned no task entry id.",
        }

    # 8. Sondea automateEntry hasta que la cuenta alcance las combinaciones esperadas
    #    (len(payloads) en SEQUENTIAL) o deje de crecer en 2 lecturas, o se agote el sondeo.
    strat = (strategy or "").strip().upper()
    expected = len(payloads) if strat == "SEQUENTIAL" else None
    prev_count = None
    final_count: Any = None
    result_nodes: list[dict] = []
    for _ in range(AUTOMATE_POLL_TRIES):
        time.sleep(AUTOMATE_POLL_INTERVAL_S)
        polled = graphql(
            AUTOMATE_ENTRY_QUERY,
            {"id": entry_id, "n": int(max_results)},
            url=url,
            token=token,
            timeout=timeout,
        )
        if polled["status"] != "ok":
            return polled
        entry = (polled.get("data") or {}).get("automateEntry") or {}
        by_offset = entry.get("requestsByOffset") or {}
        count = (by_offset.get("count") or {}).get("value")
        result_nodes = [
            e.get("node") for e in (by_offset.get("edges") or []) if e.get("node")
        ]
        final_count = count
        reached = expected is not None and isinstance(count, int) and count >= expected
        # "Deja de crecer": dos lecturas consecutivas con la misma cuenta (>0). El >0 evita
        # stop at startup, when no row has appeared yet.
        stalled = (
            prev_count is not None
            and isinstance(count, int)
            and count == prev_count
            and count > 0
        )
        if reached or stalled:
            break
        prev_count = count

    return {
        "status": "done",
        "session_id": session_id,
        "entry_id": entry_id,
        "count": final_count,
        "results": parse_entry_requests(result_nodes),
    }
