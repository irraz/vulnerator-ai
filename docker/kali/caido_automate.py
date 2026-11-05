"""Automate de Caido (fuzzing tipo Intruder/ffuf) en STDLIB PURA — la lógica de la tool.

Es la pieza testeable de la tool ``caido_automate`` que ``kali_mcp_server`` expone como
``@mcp.tool``. Igual que ``caido_client`` (Replay/historial), vive en un módulo aparte con SOLO
la librería estándar (sin ``mcp`` ni ``requests``) y REUTILIZA el transporte de ``caido_client``
(``graphql``), así que aquí NO se hace HTTP propio: todo el I/O de red pasa por ese passthrough
ya verificado. No se reimplementa nada de token/proyecto/sesión: ``ensure_session`` resuelve la
auth (token de entorno o invitado headless) y un proyecto seleccionado.

Qué resuelve: darle al bucle OODA el fuzzing de Caido — marcar UN punto de inyección en una
petición cruda y recorrer una lista de payloads, recogiendo status/longitud/tiempo por payload.
El flujo REAL del esquema (verificado en vivo contra Caido 0.59.0 + OWASP Juice Shop) es:
``createAutomateSession`` (siembra la petición base) -> ``updateAutomateSession`` (fija la
petición + los ajustes de fuzz: payloads, placeholder, concurrencia) -> ``startAutomateTask``
(lanza; de aquí sale el ``entry id`` AUTORITATIVO) -> se SONDEA ``automateEntry`` hasta que la
cuenta de resultados deja de crecer o alcanza el número de combinaciones esperado.

Dato NO confiable: todo lo que devuelve Caido (payloads inyectados, status, longitudes, errores)
se transporta verbatim; ``parse_entry_requests`` sólo decodifica Blobs base64 y aplana la forma,
nunca interpreta el contenido. "No se finge": si cualquier etapa GraphQL falla, se devuelve su
dict de error tal cual (``graphql_error``/``unauthenticated``/``unreachable``/``failed``) y nunca
se simula éxito. Las funciones ``build_*``/``parse_*`` son PURAS (sin red) y son el núcleo
cubierto por tests; ``run_automate`` es el orquestador con I/O.

GATING DE SCOPE: este módulo SÓLO envía. El wrapper del servidor MCP (``kali_mcp_server``) es
quien valida el destino contra el scope-guard ANTES de invocar ``run_automate`` (igual que con
``caido_request``); aquí no se re-valida el objetivo.

NOTA de esquema: Caido avisa de que su API GraphQL CAMBIA en cada release. Los documentos de
abajo están verificados en vivo contra Caido 0.59.0 (ver el flujo real arriba); son
DEPENDIENTES DE VERSIÓN. Si otra versión los rompe, ``graphql`` devuelve el error del servidor
verbatim (no se finge) y la tool genérica ``caido_graphql`` sigue alcanzando el esquema nuevo.
"""

from __future__ import annotations

import base64
import time
from typing import Any

import caido_client

# Reutilizados de caido_client. Se enlazan como globales del módulo (no se llama a
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

# --- Configuración por entorno (espeja REPLAY_POLL_* de caido_client) --------------------
#
# El resultado del fuzzing es ASÍNCRONO: startAutomateTask lanza y las filas aparecen poco a
# poco en automateEntry. Tope y cadencia del sondeo, con los mismos helpers tolerantes.
AUTOMATE_POLL_TRIES = caido_client._env_int("CAIDO_AUTOMATE_POLL_TRIES", 60)
AUTOMATE_POLL_INTERVAL_S = caido_client._env_float("CAIDO_AUTOMATE_POLL_INTERVAL", 1.0)

# Marcador por defecto del punto de inyección (igual que el § de Caido/Burp).
DEFAULT_MARKER = "§"  # §

# Estrategias de combinación de payloads (enum AutomatePayloadStrategy del esquema).
VALID_STRATEGIES = ("ALL", "SEQUENTIAL", "PARALLEL", "MATRIX")


# --- Documentos GraphQL del flujo Automate (verificados en vivo; dependientes de versión) --
#
# VERIFICADOS contra Caido 0.59.0 (fuzz real sobre OWASP Juice Shop: apple->200, banana->200,
# payload malo->400). La doc de introspección tenía 3 imprecisiones corregidas aquí en vivo:
#   - CreateAutomateSessionPayload NO tiene campo ``error`` (sólo ``session``); ``entries``
#     necesita subcampos ``{ id }`` y vuelve vacío [] en el create (el entry se crea al start).
#   - StartAutomateTaskPayload NO tiene campo ``error``; el ``entry id`` AUTORITATIVO sale de
#     ``automateTask.entry.id`` (NO de session.entries).
#   - UpdateAutomateSessionPayload SÍ tiene ``error``.
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
# ``$n`` se DECLARA explícitamente (el límite de requestsByOffset). ``request{ id }`` se añade
# sobre la query mínima verificada para poblar ``request_id`` (Request.id es campo verificado).
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
    """Construye la petición cruda y localiza el punto de inyección del fuzz. PURA.

    El llamador pone EXACTAMENTE UN ``marker`` (en el path, el valor de una cabecera o el
    cuerpo) donde quiere inyectar el payload. Se arma la petición cruda con
    ``caido_client.build_raw_request``, se calcula el OFFSET EN BYTES del marcador sobre el raw
    codificado en UTF-8, se ELIMINA el marcador y se devuelve un placeholder de ancho cero
    (``start == end == offset``), es decir, el punto donde Caido insertará cada payload.

    Fail-closed (el llamador maneja el ``CaidoError``):
      - marcador vacío o AUSENTE (0 apariciones) -> ``CaidoError``.
      - si aparece más de una vez, se usa la PRIMERA (no se lanza por eso; sólo por cero).

    Offsets en BYTES, no en caracteres: un cuerpo multibyte (p. ej. UTF-8 con acentos) hace
    que el offset en bytes difiera del índice en caracteres, y Caido trabaja en bytes.

    Returns ``{"raw": <raw limpio sin el marcador>, "start": <int>, "end": <int>}``.
    """
    marker_bytes = _utf8(marker or "")
    if not marker_bytes:
        raise caido_client.CaidoError(
            "marcador de inyección vacío: pon un marcador (p. ej. §)."
        )
    raw = build_raw_request(method, path, host, headers=headers or {}, body=body or "")
    raw_bytes = _utf8(raw)
    offset = raw_bytes.find(marker_bytes)
    if offset < 0:
        raise caido_client.CaidoError(
            "marcador de inyección no encontrado en la petición: coloca exactamente uno "
            "(%r) en el path, una cabecera o el cuerpo." % marker
        )
    # Se elimina SÓLO la primera aparición (contrato: un único marcador); su offset en bytes
    # no cambia al quitarla (todo lo anterior queda intacto). Quitar una secuencia UTF-8
    # completa de un texto UTF-8 válido deja UTF-8 válido, así que el decode es seguro.
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

    Un único origen de payloads (``simpleList``) inyectado en UN placeholder. Redirecciones
    desactivadas (``NEVER``) y sin reintentos, para que cada fila sea el resultado DIRECTO de
    su payload (no se finge). Valida fail-closed: ``payloads`` no vacío, ``workers >= 1`` y
    ``strategy`` dentro del enum; si no, ``CaidoError`` (la tool no llega a llamar a Caido).

    Returns el dict listo para ``UpdateAutomateSessionInput.settings``.
    """
    if not isinstance(payloads, (list, tuple)) or len(payloads) == 0:
        raise caido_client.CaidoError(
            "lista de payloads vacía: el fuzz necesita al menos uno."
        )
    strat = (strategy or "").strip().upper()
    if strat not in VALID_STRATEGIES:
        raise caido_client.CaidoError(
            "strategy inválida %r: usa una de %s."
            % (strategy, "/".join(VALID_STRATEGIES))
        )
    try:
        w = int(workers)
        d = int(delay)
        s = int(start)
        e = int(end)
    except (TypeError, ValueError) as exc:
        raise caido_client.CaidoError(
            f"workers/delay/start/end no numéricos: {exc}"
        ) from exc
    if w < 1:
        raise caido_client.CaidoError(f"workers debe ser >= 1 (llegó {w}).")
    if d < 0:
        raise caido_client.CaidoError(f"delay no puede ser negativo (llegó {d}).")
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
    texto. La ``response`` puede ser ``null`` (fila de error: conexión fallida, etc.): sus
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


# --- Orquestador (I/O vía caido_client.graphql; devuelve estado uniforme, nunca lanza) ----


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

    Flujo REAL (verificado en vivo): valida entrada -> ``ensure_session`` -> crea la sesión de
    Automate con la petición base -> la ACTUALIZA con la petición + ajustes de fuzz -> lanza la
    tarea (de ahí el ``entry id`` autoritativo) -> SONDEA ``automateEntry`` hasta que la cuenta
    deja de crecer en 2 lecturas o alcanza el nº de combinaciones esperado (``len(payloads)``
    para ``SEQUENTIAL``) o se agota el sondeo.

    El wrapper del servidor ya validó el scope del destino ANTES de llamar aquí (este módulo
    sólo envía). "No se finge": si una etapa GraphQL falla, se devuelve su dict de error tal cual.

    Returns en éxito ``{"status":"done","session_id":..,"entry_id":..,"count":n,
    "results":[...]}``; o el dict de error de la etapa que falle (``failed``/``unauthenticated``/
    ``unreachable``/``graphql_error``).
    """
    # 1-3. Builders PUROS: cualquier entrada inválida es fail-closed ANTES de tocar la red.
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
        "isTLS": target["is_tls"],  # nombre REAL del esquema: isTLS (mayúsculas)
    }

    # 4. Sesión (token invitado/entorno + proyecto). Si no resuelve, se devuelve su error.
    session = ensure_session(url=url, timeout=timeout)
    if session["status"] != "ok":
        return session
    token = session["token"]

    # 5. createAutomateSession: siembra la petición base. CreateAutomateSessionPayload no tiene
    #    campo error; basta con comprobar que vino la sesión.
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
            "error": "createAutomateSession no devolvió sesión.",
        }
    session_id = cs["session"]["id"]

    # 6. updateAutomateSession: fija petición + ajustes de fuzz (payloads, placeholder, etc.).
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

    # 7. startAutomateTask: LANZA el fuzz. El entry id AUTORITATIVO para sondear sale de aquí
    #    (automateTask.entry.id), no de session.entries (vacío en el create).
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
            "error": "startAutomateTask no devolvió el entry id de la tarea.",
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
        # cortar en el arranque, cuando aún no ha aparecido ninguna fila.
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
