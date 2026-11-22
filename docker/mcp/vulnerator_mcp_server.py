"""Servidor `vulnerator-mcp` — front door MCP sobre la API de runs de Hermes (`:8642`).

Este proceso es el SERVIDOR MCP que CONSUMEN los clientes externos (Claude Code / Kiro en
locally via stdio; remote/containerized consumers such as BugTraceAI via streamable-HTTP).
ENVUELVE —no reemplaza— la API HTTP de runs de Hermes: expone SOLO el ciclo de vida de un
run (disparar/observar/dirigir/parar) como tools MCP, para que el cliente externo sea un
trigger/observer and NEVER the brain. It does NOT expose `/v1/chat/completions` or any
`kali_run` crudo.

What this wrapper does NOT do (important): NO scope enforcement, NO added security, NO
consent validation, NO auditing. It only adds REACHABILITY. ``scope`` is a REQUIRED argument
pero ADVISORY que se dobla dentro del prompt (claridad del operador, no un guard). La capa
Kali DOES have a DETERMINISTIC OPT-IN scope-guard (v1.3.0, via ``scope.json``) that the
operador puede activar para defensa en profundidad sobre acciones de shell cruda; eso vive
en otra capa y NO es un gate de la API de runs de `:8642`.

UNTRUSTED DATA: the run object, events and all their fields are forwarded VERBATIM; never
se interpretan como instrucciones (`agent-ooda/context/AGENTS.md`). VERSION-TOLERANTE: la
terminalidad se deriva de los booleanos ``completed``/``interrupted`` del objeto run (y del
evento SSE ``run.completed``), NUNCA del string ``status`` ni de la ``version``, que se
forwarded opaquely.

Transportes (uno/una imagen, dos modos, design §6):
  - stdio (default de proceso): ruta local recomendada de superficie-cero (sin listener, sin
    token, sin puerto). El cliente arranca el proceso (``docker run -i``).
  - streamable-http: para consumidores in-docker/remotos. FAIL-CLOSED en el token de entrada
    (``VULNERATOR_MCP_INBOUND_TOKEN``): it does NOT start without it. Bound internally to the docker network; no
    host publication by default (see the vulnerator-mcp service in docker-compose.yml).
"""

from __future__ import annotations

import functools
import hmac
import os
import sys
from typing import Any, Optional

# anyio.to_thread.run_sync: offload of the client's SYNCHRONOUS (blocking) HTTP calls
# :8642 a un hilo worker, para que NO bloqueen el event loop de streamable-http (fija review
# Finding "synchronous HTTP inside the async tool blocks the event loop"). El SDK `mcp` 1.x
# runs the body of a SYNCHRONOUS tool INLINE in the event loop (does not delegate to a thread:
# see func_metadata.call_fn_with_arg_validation), so a blocking tool with a timeout
# of 30 s would freeze all MCP traffic and /healthz. That is why ALL tools are `async` and
# delegan la llamada bloqueante con `anyio.to_thread.run_sync`.
import anyio

# Cliente FINO de :8642 (SDK-free): health/create_run/get_run/steer/stop + stream SSE con
# cursor by `seq`. Forwards opaque payloads and maps errors to structured envelopes.
from hermes_api_client import (
    DEFAULT_MAX_EVENTS,
    DEFAULT_WAIT_SECONDS,
    STOP_DRAINED,
    STOP_TERMINAL,
    HermesApiClient,
)

# PURE logic (SDK-free): scope-folding, input validation and the `done` decision.
# Vive aparte para testearse sin importar FastMCP (igual que scope_guard/tool_streaming en Kali).
from mcp_tool_logic import (
    clamp_cursor,
    decide_stream_done,
    fold_scope_into_input,
    normalize_optional_positive,
    validate_run_id,
    validate_start_pentest,
    validate_steer,
)

# SDK `mcp`: se fija mcp>=1.28,<2 (API 1.x de FastMCP), misma era de protocolo que el
# live Kali container (mcp==1.30.0). Imported here; that is why this module is NOT imported in
# the pure-logic unit tests (which import mcp_tool_logic/hermes_api_client).
from mcp.server.fastmcp import Context, FastMCP

# --- Environment configuration (overridable; safe defaults) ---------------
HOST = os.environ.get("VULNERATOR_MCP_HOST", "0.0.0.0")
PORT = int(os.environ.get("VULNERATOR_MCP_PORT", "8700"))
# URL del hop upstream a Hermes. En compose se alcanza por DNS de servicio (ooda-agent).
HERMES_API_BASE_URL = os.environ.get("HERMES_API_BASE_URL", "http://ooda-agent:8642")
# Upstream PASS-THROUGH Bearer (a second secret is NOT minted for the hop to :8642).
HERMES_API_SERVER_KEY = os.environ.get("HERMES_API_SERVER_KEY", "")
# Transporte: stdio (default de proceso) | streamable-http (lo fija el servicio opt-in).
TRANSPORT = os.environ.get("VULNERATOR_MCP_TRANSPORT", "stdio")
# Token de ENTRADA (hop 2: clientes -> vulnerator-mcp). OBLIGATORIO en streamable-http
# (fail-closed). Distinto de HERMES_API_SERVER_KEY: protege otra frontera (§8.3).
INBOUND_TOKEN = os.environ.get("VULNERATOR_MCP_INBOUND_TOKEN", "")

# DEDICATED health route (exact): the MCP endpoint is mounted at "/", so the carve-out of
# auth de entrada es SOLO para esta ruta exacta, nunca un prefijo (§8.2).
HEALTH_PATH = "/healthz"

# The MCP endpoint is mounted at the root so the service URL needs no path (same
# que kali-mcp).
mcp = FastMCP(
    "vulnerator-mcp",
    host=HOST,
    port=PORT,
    streamable_http_path="/",
)

# A single module-level client (stateless; Hermes owns the run_id).
_client = HermesApiClient(HERMES_API_BASE_URL, HERMES_API_SERVER_KEY)


async def _offload(fn: Any, *args: Any, **kwargs: Any) -> Any:
    """Runs a SYNCHRONOUS (blocking) call to the :8642 client in a worker thread.

    Fija review Finding "synchronous HTTP inside the async tool blocks the event loop": el
    cliente usa ``httpx.request`` bloqueante (timeout 30 s). Como el SDK `mcp` 1.x corre el
    body of a synchronous tool INLINE in the event loop, a slow call to :8642 would freeze
    all streamable-http traffic (other tools, /healthz). Delegating it to a thread with
    ``anyio.to_thread.run_sync`` el event loop sigue libre y solo se demora SU llamador. En
    stdio (un proceso por cliente) el efecto es inocuo pero la ruta es la misma.
    """
    return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))


# ---------------------------------------------------------------- tools


@mcp.tool()
async def start_pentest(
    input: str,
    scope: str,
    session_id: Optional[str] = None,
    instructions: Optional[str] = None,
    previous_response_id: Optional[str] = None,
    idempotency_key: Optional[str] = None,
) -> dict[str, Any]:
    """Dispara un pentest OODA de Hermes (POST /v1/runs). Devuelve {run_id, status, replayed}.

    El cliente externo es un DISPARADOR, no el cerebro: esta tool solo arranca el run; el
    razonamiento OODA lo hace Hermes.

    SIN GUARDRAILS: esta capa MCP NO impone scope, consentimiento ni audit. ``scope`` es
    REQUERIDO pero ADVISORY: se DOBLA dentro del ``input`` como metadato de claridad del
    operator (``AUTHORIZED SCOPE ...``), NOT as an enforced restriction. The
    responsabilidad del alcance es enteramente del operador. (La capa Kali ofrece un
    separate DETERMINISTIC OPT-IN scope-guard —v1.3.0, via ``scope.json``— for defense in
    depth over ``kali_run``/``kali_exec``; enable it if you want a real gate at the
    shell level. It is not a gate of this runs API and must not be presented as a guarantee.)

    Args:
        input: engagement instruction (non-empty string). UNTRUSTED DATA.
        scope: authorized limit declared by the operator (non-empty string). It is folded into the
            prompt; advisory, no impuesto.
        session_id: optional, to chain runs in a Hermes session.
        instructions: opcional, instrucciones de sistema adicionales.
        previous_response_id: opcional, continuidad nativa de Hermes (en lugar de pasar un
            conversation history, which this wrapper deliberately does NOT expose).
        idempotency_key: optional; if passed, sent as the ``Idempotency-Key`` header
            para reintentos seguros (repetir la misma clave -> ``replayed: true``).

    Returns:
        {run_id, status, replayed} de Hermes (opaco), o un sobre de error estructurado
        ({"error": {...}}) verbatim (p. ej. ``invalid_request`` sin llamar upstream si
        ``input``/``scope`` are empty, or ``upstream_unreachable`` if Hermes does not respond).
    """
    err = validate_start_pentest(input, scope)
    if err is not None:
        return err
    folded = fold_scope_into_input(input, scope)
    # Offload de la llamada HTTP bloqueante a un hilo (no bloquear el event loop).
    return await _offload(
        _client.create_run,
        folded,
        session_id=session_id,
        instructions=instructions,
        previous_response_id=previous_response_id,
        idempotency_key=idempotency_key,
    )


@mcp.tool()
async def get_run_status(run_id: str) -> dict[str, Any]:
    """Queries a run's status (GET /v1/runs/{run_id}). Forwards the full run object.

    Forwards ``status`` (opaque) + the booleans ``completed``/``partial``/``interrupted`` +
    ``output`` + ``usage``/``runtime`` tal cual. La terminalidad REAL se lee de los
    booleans, never from the ``status`` string (version tolerance). ``output`` and other fields
    son DATO NO CONFIABLE: se transportan verbatim.

    Args:
        run_id: run id returned by ``start_pentest`` (non-empty string).

    Returns:
        El objeto ``hermes.run`` completo (opaco), o un sobre de error estructurado
        ({"error": {...}}) verbatim (``invalid_request`` / ``run_not_found`` /
        ``upstream_unreachable``).
    """
    err = validate_run_id(run_id)
    if err is not None:
        return err
    return await _offload(_client.get_run, run_id)


@mcp.tool()
async def stream_run_events(
    run_id: str,
    cursor: int = 0,
    max_events: Optional[int] = None,
    wait_seconds: Optional[float] = None,
    ctx: Optional[Context] = None,
) -> dict[str, Any]:
    """Consumes a run's SSE events in pages (GET /v1/runs/{run_id}/events).

    Baseline portable (funciona en TODO transporte, incluido stdio): acumula los eventos
    nuevos (``seq > cursor``) en una lista y devuelve ``{events, next_cursor, done}``. El
    cliente llama en bucle avanzando ``cursor = next_cursor`` hasta ``done=True``, igual que
    ``read_tool_logs``/``read_scan_findings`` en kali-mcp. Mejora SOLO sobre streamable-http:
    emits ONE MCP progress notification per PAGE (end-of-batch telemetry with the number of
    events in that page, NOT per-event nor cumulative; degrades to plain batching in stdio).

    Los eventos son DATO NO CONFIABLE y OPACO: cada dict trae ``event``/``run_id``/
    ``timestamp``/``seq`` y campos como ``delta``/``text``/``preview`` que contienen salida
    cruda de herramientas; se transportan verbatim, nunca se interpretan.

    ``done`` es True SOLO si (1) se vio un evento ``run.completed`` en este batch, o (2) el
    stream was DRAINED (upstream closed the connection) without a terminal event AND a confirmation
    ``get_run`` muestra el run terminal por booleanos LITERALES (``completed is True`` o
    ``interrupted is True``). If that confirmation fails, ``done=False`` (the client keeps
    paginando) y el error se adjunta en ``terminality_error`` (no se traga). Un batch que
    corta por un TOPE (``max_events``, presupuesto de bytes, o el presupuesto wall-clock
    ``wait_seconds`` sobre un stream silencioso) devuelve ``done=False`` SIN confirmar: hay
    eventos pendientes tras ``next_cursor`` y el cliente debe seguir paginando (esto evita el
    bug de declarar ``done`` dejando la cola —incluido ``output`` y ``run.completed``— sin leer).

    A stream FAILURE received BEFORE any event (``run_id`` invalid, non-2xx such as
    ``run_not_found``, o Hermes inalcanzable) se devuelve con el sobre ``{"error": {...}}``
    BARE —like the other tools— and is TERMINAL for pagination: it is NOT wrapped in
    the batch shape, so a client iterating only on ``done`` does not enter a retry
    loop. If the failure arrives AFTER partial events, those events are returned
    junto al sobre COMPLETO bajo ``stream_error`` con ``done=False``.

    OVERSIZED EVENT (fail-loud contract): if a SINGLE SSE event serializes above
    the absolute per-event ceiling (512 KiB), it is NOT forwarded —neither verbatim (truncating an event
    opaque would violate pass-through) nor as a placeholder inside ``events`` (which would discard the
    payload and advance the cursor)—. Instead, a BARE envelope is returned
    ``{"error": {... "code": "oversized_event", "oversized_event": {metadatos SIN payload}}}``
    and the cursor does NOT advance (the ``seq`` stays recoverable). It is terminal for pagination; for
    recuperar el estado terminal del run (si el evento era ``run.completed``) usa
    ``get_run_status``, o avanza ``cursor`` por encima del ``seq`` indicado para saltarlo. Los
    normal events preceding the oversized one in a page are delivered COMPLETE
    first (the oversized one is reprocessed on the next empty page). If the confirmation of
    terminalidad (``get_run`` tras un drenado) falla, su sobre COMPLETO va bajo
    ``terminality_error`` (misma forma). ``wait_seconds`` NO es un error: corta el batch de
    asynchronously (deadline cancellation) without waiting for the network timeout or blocking the
    event loop de streamable-http.

    Args:
        run_id: run id (non-empty string).
        cursor: last ``seq`` already consumed; 0 to read from the beginning. Negative -> 0.
        max_events: optional cap of events per page (internal default 200).
        wait_seconds: optional wall-clock budget per page (internal default 25.0 s).
        ctx: inyectado por FastMCP; usado para progreso en streamable-http (guardado).

    Returns:
        {"events": [...opaco...], "next_cursor": int, "done": bool
         [, "terminality_error": {"error": {...}}]}, o
        {"events": [...], "next_cursor": int, "done": false, "stream_error": {"error": {...}}}
        si el fallo llega tras eventos parciales, o el sobre de error DESNUDO
        ({"error": {...}}) verbatim on failed validation or a pre-event failure (e.g.
        invalid ``run_id`` or ``run_not_found``) — terminal for pagination.
    """
    err = validate_run_id(run_id)
    if err is not None:
        return err

    start_cursor = clamp_cursor(cursor)
    eff_max = normalize_optional_positive(max_events)
    if eff_max is None:
        eff_max = DEFAULT_MAX_EVENTS
    eff_wait = normalize_optional_positive(wait_seconds)
    if eff_wait is None:
        eff_wait = DEFAULT_WAIT_SECONDS

    events, next_cursor, error, stop_reason = await _client.iter_events(
        run_id,
        after_seq=start_cursor,
        max_events=int(eff_max),
        wait_seconds=float(eff_wait),
    )

    if error is not None:
        code = error.get("error", {}).get("code") if isinstance(error, dict) else None
        # Fail-closed BEFORE touching the network (invalid run_id) or ANY non-2xx/unreachable
        # received BEFORE any event: the BARE {"error": {...}} envelope is returned,
        # like the other tools (get_run_status/steer_run/...). Thus a run_not_found in
        # el endpoint de eventos NO se envuelve en la forma de batch {events,next_cursor,done}
        # (fija review Finding "unknown-run stream error invites a paging spin": un cliente
        # que itere solo sobre `done` ya no reintenta en bucle; el sobre es terminal).
        if not events:
            return error
        # If partial events had already arrived before the failure, they are preserved along with the envelope
        # COMPLETO bajo stream_error (misma forma que el resto de errores). done=False.
        return {
            "events": events,
            "next_cursor": next_cursor,
            "done": False,
            "stream_error": error,
        }

    # Progress (streamable-http only). END-OF-BATCH TELEMETRY, not per-event: emit ONE
    # notification with the number of events in THIS page (not cumulative, no `total`) just
    # before returning the result. The client perceives that a page brought N events; for
    # per-event progress it would have to paginate. Wrapped in try/except to degrade to plain batching
    # in stdio or with clients lacking progress support (it is cosmetic, never breaks the batch).
    if ctx is not None and events:
        try:
            await ctx.report_progress(progress=float(len(events)))
        except Exception:  # noqa: BLE001 - progress is cosmetic; never breaks the batch
            pass

    saw_terminal = stop_reason == STOP_TERMINAL
    stream_drained = stop_reason == STOP_DRAINED

    # Case 2 (only on a REAL DRAIN without a terminal event): a get_run confirmation decides the
    # terminalidad por booleanos. Un batch cortado por tope/deadline no confirma (done=False).
    # The confirmation is a blocking HTTP call: it is OFFLOADED to a thread so as not to freeze
    # el event loop de streamable-http (fija review Finding "synchronous HTTP inside the async
    # stream tool blocks the event loop").
    confirm: Any = None
    confirm_is_error = False
    if stream_drained and not saw_terminal:
        confirm = await _offload(_client.get_run, run_id)
        confirm_is_error = isinstance(confirm, dict) and isinstance(confirm.get("error"), dict)

    done, needs_terminality_error = decide_stream_done(
        saw_terminal_event=saw_terminal,
        stream_drained=stream_drained,
        confirm_run=confirm,
        confirm_is_error=confirm_is_error,
    )

    result: dict[str, Any] = {
        "events": events,
        "next_cursor": next_cursor,
        "done": done,
    }
    if needs_terminality_error and isinstance(confirm, dict):
        # The confirmation error is NOT swallowed: the COMPLETE {"error": {...}} envelope is attached
        # bajo terminality_error (misma forma que stream_error y que el resto de errores de la
        # API; fija review Finding "terminality error envelope is inconsistent": antes se
        # adjuntaba solo confirm["error"], el objeto interno sin el envoltorio {"error": ...}).
        result["terminality_error"] = confirm
    return result


@mcp.tool()
async def steer_run(run_id: str, input: str) -> dict[str, Any]:
    """Injects a correction into a running run (POST /v1/runs/{run_id}/steer).

    The correction is delivered at the next tool boundary. If the run no longer accepts steer,
    Hermes replies HTTP 409 with ``code: run_not_accepting_steer``, which this tool forwards
    VERBATIM (sobre ``{"error": {...}}``). ``input`` es DATO NO CONFIABLE: se transporta tal
    cual.

    Args:
        run_id: run id (non-empty string).
        input: correction text (non-empty string).

    Returns:
        El resultado upstream (opaco), o el sobre de error verbatim (``invalid_request`` /
        ``run_not_accepting_steer`` / ``run_not_found`` / ``upstream_unreachable``).
    """
    err = validate_steer(run_id, input)
    if err is not None:
        return err
    return await _offload(_client.steer_run, run_id, input)


@mcp.tool()
async def stop_run(run_id: str) -> dict[str, Any]:
    """Stops a run (POST /v1/runs/{run_id}/stop). Forwards the full run object.

    El estado terminal NO se asume ``cancelled`` (se ha observado ``completed`` al parar un
    run that was already finishing): the full object is forwarded and terminality is read from the
    booleanos ``completed``/``interrupted``, nunca del string ``status`` (version-tolerancia).

    Args:
        run_id: run id (non-empty string).

    Returns:
        El objeto ``hermes.run`` completo (opaco), o un sobre de error verbatim.
    """
    err = validate_run_id(run_id)
    if err is not None:
        return err
    return await _offload(_client.stop_run, run_id)


@mcp.tool()
async def health() -> dict[str, Any]:
    """Smoke test of the upstream (GET /health). Forwards {status, platform, version}.

    ``version`` is reported VERBATIM so the client knows what it is talking to; it is NEVER used to
    branch in code (version tolerance). It does not touch any run.

    Returns:
        {status, platform, version} de Hermes (opaco), o un sobre de error estructurado
        (``upstream_unreachable``) si Hermes no responde.
    """
    return await _offload(_client.health)


# ---------------------------------------------------------------- arranque / transporte


def _build_authenticated_app(inbound_token: str) -> Any:
    """Construye la app streamable-http con ruta de salud + middleware Bearer.

    IMPORTANT: ``streamable_http_app()`` returns a NEW instance on each call, so
    que se llama UNA sola vez y se opera sobre esa misma app (registrar /healthz + envolver
    with the middleware). Otherwise the route and middleware would land in different apps.

    - DEDICATED, EXACT health route ``/healthz``: the MCP endpoint is mounted at "/", so
      the healthcheck does NOT probe "/" (that is the MCP endpoint; leaving it open would expose the
      unauthenticated MCP surface). It is the ONLY middleware carve-out (exact match).
    - Bearer middleware: every request must carry
      ``Authorization: Bearer <VULNERATOR_MCP_INBOUND_TOKEN>``; cualquier otra cosa -> 401. La
      comparison is constant-time (``hmac.compare_digest``, as
      ``artifact_http._token_ok``). El carve-out es la ruta EXACTA ``/healthz`` (nunca un
      prefijo: "/" es el endpoint MCP y debe quedar autenticado).
    """
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    app = mcp.streamable_http_app()

    async def _healthz(_request: Any) -> JSONResponse:
        return JSONResponse({"status": "ok", "service": "vulnerator-mcp"})

    app.router.routes.append(Route(HEALTH_PATH, _healthz, methods=["GET"]))

    async def _auth(request: Any, call_next: Any) -> Any:
        # Carve-out EXACTO: solo /healthz pasa sin token (igualdad, nunca startswith).
        if request.url.path == HEALTH_PATH:
            return await call_next(request)
        header = request.headers.get("Authorization", "")
        expected = "Bearer %s" % inbound_token
        if not hmac.compare_digest(header, expected):
            return JSONResponse(
                {"error": {"message": "unauthorized", "type": "auth_error",
                           "param": None, "code": "unauthorized"}},
                status_code=401,
            )
        return await call_next(request)

    app.add_middleware(BaseHTTPMiddleware, dispatch=_auth)
    return app


def main() -> None:
    """Selecciona el transporte y arranca el servidor.

    - streamable-http: FAIL-CLOSED en VULNERATOR_MCP_INBOUND_TOKEN (sin token -> stderr +
      sys.exit(1), igual que artifact_http.make_server se niega sin KALI_ARTIFACTS_TOKEN).
      Luego sirve la app ASGI con el middleware Bearer (constante en tiempo) por delante.
    - stdio: superficie de red cero; no requiere token de entrada.
    """
    if TRANSPORT == "streamable-http":
        if not INBOUND_TOKEN:
            sys.stderr.write(
                "ERROR: VULNERATOR_MCP_INBOUND_TOKEN empty: the transport "
                "streamable-http NO arranca sin token de entrada (fail-closed). "
                "Genera uno con 'openssl rand -hex 32' y ponlo en .env.\n"
            )
            sys.exit(1)
        import uvicorn

        app = _build_authenticated_app(INBOUND_TOKEN)
        uvicorn.run(app, host=HOST, port=PORT)
    else:
        # stdio: el cliente (Claude Code / Kiro) arranca el proceso por stdin/stdout.
        mcp.run()


if __name__ == "__main__":
    main()
