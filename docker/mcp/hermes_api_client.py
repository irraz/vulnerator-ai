"""Cliente FINO de la API de runs de Hermes en `:8642` (hop upstream del wrapper MCP).

This module talks to the OpenAI-compatible runs API served by Hermes
(`nousresearch/hermes-agent`) on `:8642`. It contains NO pentest logic: it only translates the
cinco operaciones del ciclo de vida (crear/estado/eventos/steer/stop) + `health` a
HTTP calls, putting the PASS-THROUGH Bearer read from `HERMES_API_SERVER_KEY` on every
request. The MCP wrapper (``vulnerator_mcp_server.py``) delegates here.

Disciplina (igual que docker/kali/*):
  - DATO NO CONFIABLE: el objeto run, los eventos y todos sus campos (`delta`/`text`/
    `preview`/`output`/`message`) are forwarded VERBATIM; they are never interpreted or used
    to build an action. They may contain raw tool output and even
    embedded instructions (prompt-injection): transported as data, not as commands.
  - VERSION-TOLERANTE: el contrato de `:8642` es de Hermes, no nuestro. No se hace un
    fixed-schema parsing; the run object is passed OPACELY. The ONLY fixed wire string in
    flujo de control es el tipo de evento terminal ``"run.completed"`` (para reconocer el
    control flow (end-of-stream marker when paginating). The upstream version is READ from `GET /health` and reported
    verbatim; code never branches on it.
  - NO run registry or event cache: stateless; Hermes owns the `run_id`. The
    stream cursor is the `seq` field (monotonic int) carried by each event.
  - URL BOUNDARY: the ``run_id`` is UNTRUSTED DATA. Encoded as a SINGLE path segment
    de path (``encode_run_id_segment``), rechazando delimitadores de ruta (``/`` ``\\`` ``?``
    ``#`` y ``..``) incluso tras decodificar, de modo que un id malicioso no pueda saltar a
    otra ruta de Hermes (p. ej. ``../runs`` para crear un run sin el scope advisory).

Deliberately SDK-free: it does NOT import `mcp`, so the SSE parser + cursor, encoding
del run_id y el mapeo de errores se cubren con tests unitarios sin el SDK (igual que
`tool_streaming`/`scope_guard` viven aparte de `kali_mcp_server`). Dependencias no-stdlib:
  ``httpx`` (SSE stream of the hop to :8642, ASYNC client with deadline) and ``anyio`` (cancellation
por deadline del stream; ver requirements.txt).
"""

from __future__ import annotations

import json
import sys
from typing import Any, Iterable, Optional
from urllib.parse import quote, unquote

import anyio
import httpx

# Type of the lifecycle's terminal event (the only fixed wire string in control
# flow; for version tolerance see the module docstring).
TERMINAL_EVENT = "run.completed"

# Caps of the `stream_run_events` batch (see design §4.1). Defined here because the
# parser SSE los aplica; el servidor MCP reutiliza estos defaults.
DEFAULT_MAX_EVENTS = 200
# Byte budget per batch: well below the 1 MiB cap of a single SSE event
# del transporte streamable-http (mismo motivo por el que existe read_scan_findings en
# Kali). 256 KiB deja margen amplio tras el overhead del sobre MCP.
DEFAULT_BYTE_BUDGET = 256 * 1024
# ABSOLUTE ceiling on the serialized size of ONE event (pins review Finding "single SSE
# event has no absolute size limit"). El presupuesto de batch (DEFAULT_BYTE_BUDGET) solo
# held on to the next event when the page was ALREADY non-empty; a SINGLE event on an
# empty page was admitted for anti-starvation with no upper cap, so an
# untrusted `tool.completed.preview`/`text` could exceed the ~1 MiB message limit
# del transporte streamable-http. Este techo acota ese caso: un evento cuyo JSON supere
# MAX_SINGLE_EVENT_BYTES NO se emite (ni verbatim ni como placeholder dentro de `events`).
#
# FAIL-LOUD CONTRACT (pins the blocking Findings of review 4 — "oversized event
# placeholder breaks opaque verbatim pass-through" y "oversized terminal run.completed can
# return done:false"): un placeholder DENTRO de `events` violaba dos invariantes a la vez:
#   (a) descartaba el payload no confiable (`preview`/`text`/`delta`/`output` y cualquier
#       campo futuro) AVANZANDO el cursor, dejando el `seq` original irrecuperable — rompe el
#       pass-through opaco/verbatim/version-tolerante; y
#   (b) si el evento sobredimensionado era `run.completed`, el placeholder conservaba ese
#       `event` while the page closed with STOP_CAP (`done=false`), returning a
#       terminal marker with non-terminal semantics.
# En su lugar, el batcher NO emite nada dentro de `events` para un evento sobredimensionado,
# It does NOT advance the cursor (the `seq` stays recoverable) and signals STOP_OVERSIZE with the metadata
# of the event (seq/type/size/limit). The server translates those into a BARE error envelope
# outside `events` —fail-loud and terminal for pagination, like a pre-event
# run_not_found— without faking a Hermes event or consuming the cursor. Events that DO
# fit under the ceiling are delivered COMPLETE first (if the page already had events, it closes
# first and the oversized one is reprocessed on the next empty page).
# 512 KiB deja margen holgado bajo 1 MiB tras el overhead del sobre MCP.
MAX_SINGLE_EVENT_BYTES = 512 * 1024
# Presupuesto wall-clock por batch: una llamada a la tool nunca cuelga al cliente esperando
# un stream silencioso.
DEFAULT_WAIT_SECONDS = 25.0

# Razones de parada del batcher SSE (design §4.1). Distinguen un corte por TOPE (cap/
# deadline -> there is more data pending, the batch is NOT terminal) of a real DRAIN of the
# stream (upstream closed the connection), the ONLY condition that enables
# terminality confirmation via `get_run` on the server.
STOP_CAP = "cap"            # max_events o presupuesto de bytes agotado
STOP_DEADLINE = "deadline"  # presupuesto wall-clock agotado (stream silencioso)
STOP_TERMINAL = "terminal"  # se vio el evento run.completed
STOP_DRAINED = "drained"    # the line iterator was exhausted (upstream closed the stream)
# The next event exceeds the absolute per-event ceiling (MAX_SINGLE_EVENT_BYTES): the page
# se cierra SIN emitirlo y SIN avanzar el cursor (fail-loud, ver docstring de
# MAX_SINGLE_EVENT_BYTES). Los metadatos del evento quedan en SseBatcher.oversized para que el
# server translates them into a bare error envelope. This is a "for this page" stop, NOT
# terminal del run: la terminalidad real (si el oversized era run.completed) se recupera con
# get_run.
STOP_OVERSIZE = "oversize"


def _error_envelope(message: str, code: str, type_: str = "upstream_error") -> dict[str, Any]:
    """Builds a uniform OpenAI-style error envelope (same shape as Hermes').

    `message` is UNTRUSTED DATA if it comes from upstream; here it is only wrapped, not
    interpreted. The wrapper forwards it verbatim to the MCP client.
    """
    return {"error": {"message": message, "type": type_, "param": None, "code": code}}


class RunIdError(ValueError):
    """El ``run_id`` no es un segmento de path seguro (contiene delimitadores de ruta)."""


# Delimiters that, after decoding, would let a run_id jump to another path/host of
# Hermes or inject a query/fragment. Explicitly rejected (defense in depth
# sobre el quote por-segmento), incluido ``..`` (segmento de recorrido).
_FORBIDDEN_IN_RUN_ID = ("/", "\\", "?", "#")


def encode_run_id_segment(run_id: str) -> str:
    """Encodes ``run_id`` as a SINGLE safe path segment (pins review Finding `run_id`).

    El ``run_id`` es DATO NO CONFIABLE: interpolarlo crudo en la URL deja que
    ``steer_run(run_id="../runs?x", ...)`` normalice a ``POST /v1/runs`` (creando un run sin
    el scope advisory) o que alcance otra ruta de Hermes. Para evitarlo:

      1. Se DECODIFICA el valor (``unquote``) y se comprueba que NI el crudo NI el decodificado
         contain a path delimiter (``/`` ``\\`` ``?`` ``#``) nor ``..`` nor NUL. Thus
         the percent-encoded variant is also rejected (``%2F`` -> ``/`` after decoding).
      2. ``quote`` with ``safe=""`` so the result is a single segment (any
         special character is percent-encoded and does NOT change the path).

    It does not validate the ``run_`` format (Hermes owns the id space; version tolerance):
    solo garantiza que el valor no es sintaxis de URL que cambie de ruta. Lanza
    ``RunIdError`` si el id no es un segmento seguro.
    """
    if not isinstance(run_id, str) or not run_id:
        raise RunIdError("empty or non-string run_id")
    # Both raw and decoded forms are checked: a client might send the separator already
    # literal o su forma percent-encoded.
    decoded = unquote(run_id)
    for candidate in (run_id, decoded):
        if "\x00" in candidate:
            raise RunIdError("run_id contiene NUL")
        if ".." in candidate:
            raise RunIdError("run_id contiene '..' (recorrido de ruta)")
        for bad in _FORBIDDEN_IN_RUN_ID:
            if bad in candidate:
                raise RunIdError("run_id contiene delimitador de ruta prohibido: %r" % bad)
    # safe="": everything else is percent-encoded; the result is a single path segment.
    return quote(run_id, safe="")


class SseBatcher:
    """PURE, INCREMENTAL SSE batcher (no socket): accumulates ONE page of events.

    Wire lines are fed ONE BY ONE via :meth:`feed`; each ``feed`` returns a
    stop reason (``STOP_CAP``/``STOP_TERMINAL``) as soon as the page must close, or
    ``None`` if it can keep accepting lines. It is the highest-value unit-test piece:
    it is given raw lines (including the `` : open`` comment, multiline ``data:`` and a
    evento malformado) y expone ``events``/``next_cursor`` ya filtrados por cursor. NO abre
    network: ``iter_events`` passes the lines it reads from the network and can STOP as soon as the
    batcher signals a cap (without buffering the whole stream in memory).

    The server uses the stop reason to decide ``done`` (design §4.1): ONLY
    ``STOP_TERMINAL`` or ``STOP_DRAINED`` (iterator exhausted) end pagination;
    ``STOP_CAP``/``STOP_DEADLINE`` mean "more data, keep paging" -> ``done=false``.

    Wire protocol observed (hermes-agent 0.22.0, research §10.4):
      - El campo SSE ``event:`` NO se usa; el tipo vive dentro del JSON (campo ``event``).
      - Cada mensaje es ``id: <n>`` + ``data: <json>``; el stream abre con ``: open``.
      - Cada evento JSON trae ``event`` (tipo), ``run_id``, ``timestamp`` (float), ``seq``
        (monotonic int). ``seq`` IS THE CURSOR.

    Reglas:
      - Comments (``:`` at line start, e.g. ``: open``) and the ``id:`` line are ignored (the
        JSON's ``seq`` is authoritative). A blank line is the event boundary.
      - The current event's ``data:`` lines are accumulated (SSE allows multiline ``data:``).
      - En la frontera de evento se hace ``json.loads``. Si falla el parseo o falta/!int el
        ``seq`` -> that event is SKIPPED (best-effort, like read_findings skips
        corruptas); nunca se rompe el stream por un payload malformado/oversized.
      - ``seq <= after_seq`` -> skipped (already delivered): dedup across pages.

    Byte budget (pins review Finding "byte budget overshoots"): the event's size
    is measured BEFORE adding it. If adding it to an ALREADY NON-EMPTY page would cross ``byte_budget``,
    the page is closed WITHOUT it (``STOP_CAP``) and it is kept for the next one (nothing is lost:
    its ``seq`` does not advance). A SINGLE event larger than ``byte_budget`` on an empty page IS
    included (deliberate anti-starvation) and closes the page after it, so a batch
    devuelva como mucho UN evento por encima del presupuesto, nunca dos. 256 KiB deja margen
    stays under the transport's 1 MiB even for that single event + MCP envelope overhead.

    Techo ABSOLUTO por evento (fija review Finding "single SSE event has no absolute size
    limit" and review 4's blocking findings): the earlier anti-starvation did not bound the size
    of THAT single event, so an untrusted event (e.g. ``tool.completed.preview``/
    ``text``) could exceed the transport's ~1 MiB limit. If an event's JSON exceeds
    ``max_single_event_bytes`` se aplica el contrato FAIL-LOUD (ver docstring de
    ``MAX_SINGLE_EVENT_BYTES``): it is NOT emitted (neither verbatim —truncating an opaque event would violate the
    pass-through— nor as a placeholder inside ``events``, which would discard the payload and
    advance the cursor), ``next_cursor`` is NOT advanced (the ``seq`` stays recoverable) and
    ``STOP_OVERSIZE`` is signalled, storing the event's metadata in :attr:`oversized`
    (``event``/``run_id``/``timestamp``/``seq`` + size/limit, WITHOUT the payload). The server
    translates that into a BARE error envelope outside ``events``. If the page ALREADY has events
    normales, se cierra ANTES con ``STOP_CAP`` (se entregan completos) y el sobredimensionado
    it is reprocessed on the next empty page.
    """

    def __init__(
        self,
        *,
        after_seq: int = 0,
        max_events: Optional[int] = None,
        byte_budget: int = DEFAULT_BYTE_BUDGET,
        max_single_event_bytes: int = MAX_SINGLE_EVENT_BYTES,
    ) -> None:
        self._after_seq = after_seq
        self._max = max_events if (max_events is not None and max_events > 0) else None
        self._byte_budget = byte_budget
        self._max_single = max_single_event_bytes
        self.events: list[dict[str, Any]] = []
        self.next_cursor = after_seq
        # Metadata of the event that triggered STOP_OVERSIZE (None unless an event exceeds the
        # absolute ceiling and the page is empty). It does NOT contain the untrusted payload: only
        # ``event``/``run_id``/``timestamp``/``seq`` + ``serialized_bytes``/``limit_bytes``.
        self.oversized: Optional[dict[str, Any]] = None
        self._bytes_seen = 0
        self._data_parts: list[str] = []

    def _parse(self) -> Optional[dict[str, Any]]:
        """Procesa el evento acumulado en el buffer. Devuelve el dict a emitir o None."""
        if not self._data_parts:
            return None
        raw = "\n".join(self._data_parts)
        self._data_parts = []
        try:
            event = json.loads(raw)
        except (ValueError, TypeError):
            return None  # best-effort: evento malformado se omite
        if not isinstance(event, dict):
            return None
        seq = event.get("seq")
        if not isinstance(seq, int) or isinstance(seq, bool):
            return None  # sin cursor usable -> se omite
        if seq <= self._after_seq:
            return None  # already delivered (dedup across pages)
        return event

    @staticmethod
    def _oversized_metadata(event: dict[str, Any], size: int, limit: int) -> dict[str, Any]:
        """Metadatos (SIN payload) del evento que supera el techo absoluto por evento.

        It does NOT forward untrusted content (``preview``/``text``/``delta``/``output`` nor
        campos futuros): solo los metadatos de wire (``event``/``run_id``/``timestamp``/
        ``seq``) and the size/limit. The server puts them in a BARE error envelope outside
        ``events``. El ``seq`` NO avanza el cursor del batch: el evento queda recuperable (el
        the operator can inspect it or manually advance the cursor past it).
        """
        meta: dict[str, Any] = {
            "serialized_bytes": size,
            "limit_bytes": limit,
        }
        for key in ("event", "run_id", "timestamp", "seq"):
            if key in event:
                meta[key] = event[key]
        return meta

    def _emit(self, event: dict[str, Any]) -> Optional[str]:
        """Tries to add ``event`` to the page. Returns a stop reason or None.

        Measures size BEFORE adding (pins the overshoot): if a non-empty page would cross the
        budget, it does NOT add it and returns ``STOP_CAP`` (the event is kept for the next
        batch). A single oversized event on an empty page IS added (anti-starvation),
        and then the page is closed after it.

        Techo ABSOLUTO — contrato FAIL-LOUD (fija review Finding "single SSE event has no
        absolute size limit" and review 4's blocking findings): if the event's JSON exceeds
        ``max_single_event_bytes`` it is NOT emitted —neither verbatim (truncating an opaque event would violate
        the pass-through) nor as a placeholder inside ``events`` (which would discard the payload and
        advance the cursor)—. If the page ALREADY has normal events, it closes FIRST with
        ``STOP_CAP`` (they are delivered complete and the oversized one is reprocessed on the next page
        empty). With an empty page: nothing is added to ``events``, ``next_cursor`` is NOT advanced
        (el ``seq`` queda recuperable), se guardan los metadatos en :attr:`oversized` y se
        devuelve ``STOP_OVERSIZE``. El servidor lo traduce a un sobre de error desnudo fuera de
        ``events``. Thus a single untrusted event never exceeds the transport limit and a
        terminalidad real (si el oversized era ``run.completed``) se recupera con ``get_run``,
        terminal marker with non-terminal semantics is never returned.
        """
        size = len(json.dumps(event))
        if size > self._max_single:
            # El evento supera el techo absoluto: nunca se emite dentro de `events`. Si la
            # page ALREADY has events, it closes FIRST to deliver them complete (the oversized
            # one is reprocessed on the next empty page).
            if self.events:
                return STOP_CAP
            # Empty page: fail-loud. Metadata is stored WITHOUT payload and WITHOUT advancing the
            # cursor (el seq queda recuperable); el servidor devuelve un sobre de error desnudo.
            self.oversized = self._oversized_metadata(event, size, self._max_single)
            return STOP_OVERSIZE
        if self.events and self._bytes_seen + size > self._byte_budget:
            return STOP_CAP  # cerrar ANTES de cruzar el tope; el evento no se incluye
        self.events.append(event)
        self._bytes_seen += size
        seq = event["seq"]
        if seq > self.next_cursor:
            self.next_cursor = seq
        if event.get("event") == TERMINAL_EVENT:
            return STOP_TERMINAL
        if self._max is not None and len(self.events) >= self._max:
            return STOP_CAP
        if self._bytes_seen >= self._byte_budget:
            # A single event already above the budget (or exactly at the limit): it was included
            # for anti-starvation, but the page is closed here so a second one is not accumulated.
            return STOP_CAP
        return None

    def feed(self, raw_line: str) -> Optional[str]:
        """Feeds ONE wire line. Returns a stop reason or None (keeps accepting)."""
        line = raw_line.rstrip("\n").rstrip("\r")
        if line == "":
            event = self._parse()
            if event is not None:
                return self._emit(event)
            return None
        if line.startswith(":"):
            return None  # comentario (p. ej. ": open")
        if line.startswith("id:"):
            return None  # id de wire: ignorado, se usa el seq del JSON
        if line.startswith("data:"):
            payload = line[5:]
            if payload.startswith(" "):
                payload = payload[1:]
            self._data_parts.append(payload)
            return None
        # Any other line (e.g. "event:") is ignored: the type lives in the JSON.
        return None

    def flush(self) -> Optional[str]:
        """Processes the last event WITHOUT a blank boundary (stream drained by upstream)."""
        event = self._parse()
        if event is not None:
            return self._emit(event)
        return None


def batch_sse_events(
    lines: Iterable[str],
    *,
    after_seq: int = 0,
    max_events: Optional[int] = None,
    byte_budget: int = DEFAULT_BYTE_BUDGET,
    max_single_event_bytes: int = MAX_SINGLE_EVENT_BYTES,
) -> tuple[list[dict[str, Any]], int, str, Optional[dict[str, Any]]]:
    """Batches an ITERABLE of lines into ONE page (pure helper for tests + error path).

    Wraps :class:`SseBatcher`: feeds lines until the batcher signals a stop
    (``STOP_CAP``/``STOP_TERMINAL``/``STOP_OVERSIZE``) o se agota el iterable
    (``STOP_DRAINED``). Devuelve ``(events, next_cursor, stop_reason, oversized)`` donde
    ``oversized`` es ``None`` salvo que ``stop_reason`` sea ``STOP_OVERSIZE`` (entonces lleva
    los metadatos SIN payload del evento sobredimensionado). El corte por DEADLINE (stream
    silent stream) is handled by `iter_events` with async cancellation, not this sync helper.
    """
    batcher = SseBatcher(
        after_seq=after_seq,
        max_events=max_events,
        byte_budget=byte_budget,
        max_single_event_bytes=max_single_event_bytes,
    )
    for raw_line in lines:
        reason = batcher.feed(raw_line)
        if reason is not None:
            return batcher.events, batcher.next_cursor, reason, batcher.oversized
    reason = batcher.flush()
    if reason is not None:
        return batcher.events, batcher.next_cursor, reason, batcher.oversized
    return batcher.events, batcher.next_cursor, STOP_DRAINED, batcher.oversized


class HermesApiClient:
    """Cliente FINO de la API de runs de Hermes en `:8642`.

    Built with the base URL and the pass-through Bearer. Each method sets
    ``Authorization: Bearer <api_key>`` (+ ``Content-Type: application/json`` en cuerpos).
    Los retornos son el payload UPSTREAM reenviado opaco, o un sobre de error estructurado
    ``{"error": {...}}`` (see mapping in each method). Version-tolerant: no schema parsing
    fijo; la terminalidad se deriva de los booleanos del objeto run, nunca del string
    ``status``.
    """

    def __init__(self, base_url: str, api_key: str, *, timeout: float = 30.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    # ------------------------------------------------------------------ helpers

    def _headers(self, *, json_body: bool = False) -> dict[str, str]:
        headers = {"Authorization": "Bearer %s" % self._api_key}
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    def _run_path(self, run_id: str, suffix: str = "") -> dict[str, Any] | str:
        """Construye ``/v1/runs/<seg>[/suffix]`` con el run_id como UN segmento seguro.

        Devuelve el path (str) o, si el run_id no es un segmento seguro, un sobre de error
        ``invalid_request`` (fail-closed, SIN llamada upstream). El llamador comprueba el tipo.
        """
        try:
            seg = encode_run_id_segment(run_id)
        except RunIdError as exc:
            self._warn("run_id rechazado como segmento de path: %s" % exc)
            return _error_envelope(
                "'run_id' is not a valid identifier", code="invalid_request",
                type_="invalid_request_error",
            )
        return "/v1/runs/%s%s" % (seg, suffix)

    def _handle_response(self, resp: httpx.Response) -> dict[str, Any]:
        """Mapea una respuesta HTTP a dict (payload opaco o sobre de error).

        - 2xx con JSON -> se devuelve el JSON tal cual (opaco).
        - non-2xx con sobre de error JSON (``{"error": {...}}``) -> se devuelve verbatim.
        - non-2xx sin sobre parseable -> sobre sintetizado ``upstream_error`` con un
          snippet corto del cuerpo (recortado; no se interpola payload grande).
        - 2xx sin JSON parseable -> sobre ``upstream_error`` (forma inesperada).
        """
        try:
            body = resp.json()
        except (ValueError, json.JSONDecodeError):
            body = None

        if resp.is_success:
            if isinstance(body, dict):
                return body
            snippet = (resp.text or "")[:200]
            self._warn("respuesta 2xx no-JSON de %s: %s" % (resp.url, snippet))
            return _error_envelope(
                "upstream returned a non-JSON 2xx body: %s" % snippet,
                code="upstream_error",
            )

        # non-2xx
        if isinstance(body, dict) and isinstance(body.get("error"), dict):
            code = body["error"].get("code", "upstream_error")
            self._warn("error upstream %s (%s) en %s" % (resp.status_code, code, resp.url))
            return body  # sobre OpenAI-style verbatim (run_not_found/run_not_accepting_steer/...)

        snippet = (resp.text or "")[:200]
        self._warn("non-2xx %s sin sobre en %s: %s" % (resp.status_code, resp.url, snippet))
        return _error_envelope(
            "upstream HTTP %s: %s" % (resp.status_code, snippet),
            code="upstream_error",
        )

    def _unreachable(self, exc: Exception) -> dict[str, Any]:
        """Sobre estructurado cuando no se puede alcanzar `:8642` (DNS/refused/TLS)."""
        self._warn("Hermes inalcanzable en %s: %s" % (self._base_url, exc))
        return _error_envelope(
            "cannot reach Hermes at %s: %s" % (self._base_url, exc),
            code="upstream_unreachable",
            type_="upstream_unreachable",
        )

    @staticmethod
    def _warn(message: str) -> None:
        """Logs a single line to stderr; never interpolates large untrusted payloads."""
        sys.stderr.write("[vulnerator-mcp] %s\n" % message)

    def _request(self, method: str, path: str, *, json_body: Any = None,
                 extra_headers: Optional[dict[str, str]] = None) -> dict[str, Any]:
        url = "%s%s" % (self._base_url, path)
        headers = self._headers(json_body=json_body is not None)
        if extra_headers:
            headers.update(extra_headers)
        try:
            resp = httpx.request(
                method, url, headers=headers, json=json_body, timeout=self._timeout
            )
        except httpx.HTTPError as exc:
            return self._unreachable(exc)
        return self._handle_response(resp)

    # ------------------------------------------------------------------ API

    def health(self) -> dict[str, Any]:
        """GET /health -> {status, platform, version} (research §10.1).

        ``version`` is reported to the client VERBATIM and NEVER used to branch in code
        (version tolerance). This is the only place an upstream version is exposed.
        """
        return self._request("GET", "/health")

    def create_run(
        self,
        input: str,
        *,
        session_id: Optional[str] = None,
        instructions: Optional[str] = None,
        previous_response_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> dict[str, Any]:
        """POST /v1/runs -> {run_id, status, replayed} (research §10.3).

        Sends ``Idempotency-Key`` as a HEADER (not in the body) only when a non-
        empty one is passed. Empty/None optionals are OMITTED from the JSON body.
        ``conversation_history`` is deliberately OMITTED by the wrapper (design §3): the
        continuidad se expresa con ``previous_response_id``/``session_id``.
        """
        body: dict[str, Any] = {"input": input}
        if session_id:
            body["session_id"] = session_id
        if instructions:
            body["instructions"] = instructions
        if previous_response_id:
            body["previous_response_id"] = previous_response_id
        extra = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        return self._request("POST", "/v1/runs", json_body=body, extra_headers=extra)

    def get_run(self, run_id: str) -> dict[str, Any]:
        """GET /v1/runs/{run_id} -> objeto hermes.run completo (opaco; §10.5).

        La terminalidad se lee de los booleanos ``completed``/``interrupted`` del objeto,
        NUNCA del string ``status``. El ``run_id`` se codifica como un segmento seguro.
        """
        path = self._run_path(run_id)
        if isinstance(path, dict):
            return path
        return self._request("GET", path)

    def steer_run(self, run_id: str, input: str) -> dict[str, Any]:
        """POST /v1/runs/{run_id}/steer. 409 run_not_accepting_steer is forwarded verbatim (§10.6)."""
        path = self._run_path(run_id, "/steer")
        if isinstance(path, dict):
            return path
        return self._request("POST", path, json_body={"input": input})

    def stop_run(self, run_id: str) -> dict[str, Any]:
        """POST /v1/runs/{run_id}/stop -> objeto run completo (terminal NO garantizado 'cancelled'; §10.5)."""
        path = self._run_path(run_id, "/stop")
        if isinstance(path, dict):
            return path
        return self._request("POST", path)

    async def iter_events(
        self,
        run_id: str,
        *,
        after_seq: int = 0,
        max_events: Optional[int] = None,
        wait_seconds: Optional[float] = None,
    ) -> tuple[list[dict[str, Any]], int, Optional[dict[str, Any]], str]:
        """GET /v1/runs/{run_id}/events (SSE). Returns ONE batched page (ASYNC).

        Es ASYNC y con deadline propio (fija review Finding "quiet SSE wait"): abre
        ``httpx.AsyncClient.stream`` and reads lines asynchronously under an
        ``anyio.move_on_after(wait_seconds)``. Thus a SILENT stream (before or after
        ``: open``) se corta en el presupuesto wall-clock (frontera de batch NORMAL,
        ``done=false``), SIN esperar al read-timeout de httpx y SIN bloquear el event loop de
        streamable-HTTP. The deadline also wraps RESPONSE ACQUISITION
        (``client.stream(...)`` espera status+cabeceras) y el drenaje del cuerpo de error de
        un non-2xx (fija review Finding "SSE pre-header wait escapes the deadline"): un
        an upstream that accepts the connection but withholds headers/body is bounded by
        ``wait_seconds``, no solo por el connect timeout.

        A deadline cut is DIFFERENT from a connection/HTTP failure:
          - deadline/cap -> ``stop_reason`` ``STOP_DEADLINE``/``STOP_CAP`` y ``error=None``
            (el cliente sigue paginando).
          - non-2xx or connection exception -> ``error`` is the ``{"error": {...}}`` envelope
            COMPLETO (fija review Finding "streaming errors lose the envelope"): se preserva
            the SAME shape as request/response, not a synthetic ``_error``.

        Returns:
            ``(events, next_cursor, error, stop_reason)``. Si ``error`` no es None, es el
            sobre de error completo y ``stop_reason`` es ``"error"``.
        """
        path = self._run_path(run_id, "/events")
        if isinstance(path, dict):
            return [], after_seq, path, "error"  # invalid run_id: invalid_request envelope

        url = "%s%s" % (self._base_url, path)
        headers = self._headers()

        if wait_seconds is not None and wait_seconds > 0:
            effective_wait = wait_seconds
        else:
            effective_wait = DEFAULT_WAIT_SECONDS

        # max_single_event_bytes is read from the module at CALL time (not the default bound at
        # __init__ definition): so the ceiling is configurable/testable.
        batcher = SseBatcher(
            after_seq=after_seq,
            max_events=max_events,
            max_single_event_bytes=MAX_SINGLE_EVENT_BYTES,
        )
        cap_reason: Optional[str] = None  # STOP_CAP/STOP_TERMINAL if a cap closed the page
        hit_deadline = False
        http_error: Optional[dict[str, Any]] = None  # sobre {"error":...} de un non-2xx
        # Status de un non-2xx YA observado (cabeceras recibidas) ANTES de drenar su cuerpo. Se
        # guarda aparte para que, si el DRENAJE del cuerpo de error se pasa del deadline (fija
        # review NB "stalled error body downgrades to a deadline page"), se pueda recuperar la
        # error classification instead of degrading to an empty deadline page.
        pending_error_status: Optional[int] = None

        try:
            # Read-timeout de httpx = None: el corte REAL por tiempo lo hace
            # anyio.move_on_after (deadline wall-clock del batch), no el read-timeout, para no
            # confusing a SLOW/silent stream with a connection failure. The connect timeout
            # is short (fail-fast if :8642 is absent).
            stream_timeout = httpx.Timeout(
                connect=min(self._timeout, 10.0),
                read=None, write=self._timeout, pool=self._timeout,
            )
            # The wall-clock deadline wraps the ENTIRE stream lifecycle: acquisition
            # de la respuesta (status+cabeceras), el drenaje del cuerpo de error en un non-2xx
            # and line reading of the 2xx body (pins review Finding "pre-header wait
            # escapes the deadline"). Si expira ANTES de tener respuesta/cabeceras,
            # cancelled_caught -> hit_deadline (frontera NORMAL, no error): el read-timeout
            # is disabled, so without this scope an upstream withholding headers
            # would hang indefinitely.
            with anyio.move_on_after(effective_wait) as scope:
                async with httpx.AsyncClient(timeout=stream_timeout) as client:
                    async with client.stream("GET", url, headers=headers) as resp:
                        if not resp.is_success:
                            # Se registra el status ANTES de drenar: si el drenaje se pasa del
                            # deadline, the error classification is recovered after the scope (NB
                            # "stalled error body downgrades to a deadline page").
                            pending_error_status = resp.status_code
                            # Drena el cuerpo de error DENTRO del mismo deadline (un cuerpo que
                            # that does not close cannot keep the call open beyond it).
                            await resp.aread()
                            http_error = self._handle_response(resp)
                        else:
                            # Async line reading. Stops as soon as the batcher signals
                            # un tope, SIN bufferizar el resto del stream.
                            async for line in resp.aiter_lines():
                                cap_reason = batcher.feed(line)
                                if cap_reason is not None:
                                    break
            if scope.cancelled_caught:
                hit_deadline = True
        except httpx.HTTPError as exc:
            # Connection/HTTP failure: COMPLETE {"error": {...}} envelope (same shape as the
            # rest of the client), never a synthetic {"_error": ...} dict. Events
            # parciales ya acumulados en el batcher se devuelven igualmente (no se pierden).
            error = self._unreachable(exc)
            return batcher.events, batcher.next_cursor, error, "error"

        if http_error is not None:
            # non-2xx con cabeceras ya recibidas dentro del deadline: sobre de error completo.
            return [], after_seq, http_error, "error"
        if pending_error_status is not None:
            # A non-2xx was observed (headers received) but DRAINING its body went
            # past the deadline (http_error was unassigned and cancelled_caught would win). Before this
            # it degraded to an empty deadline page (done=false), inviting a client
            # loop-until-done a reintentar el mismo non-2xx (NB "stalled error body downgrades
            # to a deadline page"). Error classification is preserved by returning the envelope
            # BARE from the already-known status (no body, because the body hung),
            # terminal for pagination like any other non-2xx.
            self._warn(
                "upstream HTTP error body %s passed the deadline on %s; reporting the "
                "status sin cuerpo" % (pending_error_status, url)
            )
            error = _error_envelope(
                "upstream HTTP %s (error body stalled past the %.3gs stream deadline; body "
                "withheld)" % (pending_error_status, effective_wait),
                code="upstream_error",
            )
            return [], after_seq, error, "error"
        if cap_reason == STOP_OVERSIZE:
            # An OVERSIZED event (on an empty page) closed the batch: contract
            # FAIL-LOUD. NO se devuelve el evento (ni placeholder), NO se avanza el cursor
            # (next_cursor sigue en after_seq -> recuperable) y se emite un sobre de error
            # BARE with metadata WITHOUT payload. The server forwards it bare (terminal
            # for pagination), like a run_not_found pre-event. Real terminality
            # (si el oversized era run.completed) se recupera con get_run_status.
            meta = batcher.oversized or {}
            seq = meta.get("seq")
            etype = meta.get("event")
            error = _error_envelope(
                "a single SSE event (seq=%s, type=%s) serialized to %s bytes, exceeding the "
                "per-event ceiling of %s bytes; it was NOT forwarded (payload withheld to stay "
                "under the transport message limit) and the cursor was NOT advanced. Fetch the "
                "run with get_run_status to recover terminal state, or advance 'cursor' past "
                "seq=%s to skip it." % (
                    seq, etype, meta.get("serialized_bytes"), meta.get("limit_bytes"), seq,
                ),
                code="oversized_event",
                type_="oversized_event",
            )
            # Se adjuntan los metadatos (SIN payload) para que el cliente los inspeccione.
            error["error"]["oversized_event"] = meta
            return [], after_seq, error, "error"
        if cap_reason is not None:
            # A cap (max_events/byte_budget) or the terminal event closed the page.
            return batcher.events, batcher.next_cursor, None, cap_reason
        if hit_deadline:
            # The wall-clock deadline cut a still-open stream: NORMAL batch boundary.
            # It is NOT STOP_DRAINED (there may be more events after the silence), so the
            # servidor NO debe confirmar terminalidad a partir de este batch.
            return batcher.events, batcher.next_cursor, None, STOP_DEADLINE
        # The aiter was exhausted: upstream closed the stream. Process the last event without a boundary.
        drain_reason = batcher.flush()
        stop_reason = drain_reason if drain_reason is not None else STOP_DRAINED
        return batcher.events, batcher.next_cursor, None, stop_reason
