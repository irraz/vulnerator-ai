"""vulnerator-web — la GUI web de Vulnerator-AI (capa fina Starlette sobre módulos puros).

Sirve una consola de operador (``static/``) y su API:

  GET /healthz                               vida del proceso (SIN auth, match exacto)
  GET /api/status                            Hermes/ingesta/Caido + puertos de las UIs de Hermes
  GET /api/sessions                          sesiones (incluye subagentes) con contadores
  GET /api/sessions/{sid}                    una sesión
  GET /api/sessions/{sid}/events             eventos (``after``/``tail``/``kinds``/``limit``)
  GET /api/sessions/{sid}/trace              spans + agregados por tool (vista tipo Langfuse)
  GET /api/sessions/{sid}/pocs               PoCs de la sesión (cadena OODA + reproducción)
  GET /api/sessions/{sid}/pocs/{call}.cast   grabación asciinema v2 del PoC
  GET /api/sessions/{sid}/pocs/{call}.md     ficha Markdown del PoC
  GET /api/pocs                              índice de hallazgos de todas las sesiones
  GET /api/events/{seq}                      un evento con su texto COMPLETO
  GET /api/web                               tráfico web capturado por Caido
  GET /api/stream                            SSE en vivo (reanudable con Last-Event-ID)

OBSERVADOR por diseño: lee la API de sesiones de Hermes y el historial de Caido y los muestra; no
dirige ni para runs. La ÚNICA acción que puede iniciar, bajo demanda del operador, es generar el
informe formal (botón "Generar informe" -> POST /api/report); se desactiva con
VULNERATOR_WEB_ALLOW_TRIGGER=0 (consola en modo solo-observación). La lógica vive en módulos
stdlib-puros (``event_model``, ``trace_store``, ``poc_replay``, ``ooda_parse``) cubiertos por
tests; aquí solo hay HTTP, auth y cableado.

Seguridad:
  - Basic auth obligatoria (comparación en tiempo constante); FAIL-CLOSED: el proceso no
    arranca sin ``VULNERATOR_WEB_PASSWORD`` ni sin ``HERMES_API_SERVER_KEY``.
  - CSP estricta (sin scripts/estilos inline), ``nosniff``, ``no-referrer``, sin framing.
  - Todo lo que viene de Hermes/Caido es DATO NO CONFIABLE: se devuelve como JSON y el
    frontend lo pinta como texto, nunca como HTML.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import hmac
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Optional

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import (FileResponse, JSONResponse, PlainTextResponse, RedirectResponse,
                                 Response, StreamingResponse)
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

import event_model as em
import ingest
import poc_replay
import report
from trace_store import TraceStore

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"

_SID_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,160}$")
_CALL_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,200}$")
# Texto máximo por evento en listados y stream (el completo: /api/events/{seq}).
LIST_TEXT_MAX = 8 * 1024
STREAM_HEARTBEAT_S = 15.0


def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


class Settings:
    def __init__(self) -> None:
        self.hermes_url = _env("HERMES_API_BASE_URL", "http://ooda-agent:8642")
        self.hermes_key = _env("HERMES_API_SERVER_KEY")
        self.user = _env("VULNERATOR_WEB_USER", "admin")
        self.password = os.environ.get("VULNERATOR_WEB_PASSWORD", "")
        self.db_path = _env("VULNERATOR_WEB_DB", "/data/vulnerator-web.db")
        self.poc_dir = _env("VULNERATOR_WEB_POC_DIR", "/data/pocs")
        self.poll = float(_env("VULNERATOR_WEB_POLL_SECONDS", "1.5") or 1.5)
        self.caido_feed = _env("VULNERATOR_WEB_CAIDO_FEED", "1").lower() not in ("0", "false", "no", "off")
        self.dashboard_port = _env("HERMES_DASHBOARD_PUBLIC_PORT", "9119")
        self.webapp_port = _env("HERMES_WEBAPP_PUBLIC_PORT", "9120")
        self.dashboard_internal = _env("HERMES_DASHBOARD_INTERNAL_URL", "http://ooda-agent:9119/")
        self.webapp_internal = _env("HERMES_WEBAPP_INTERNAL_URL", "http://ooda-agent:9120/")
        # Pantallas en vivo (para presentaciones): UI de Caido y, más adelante, el navegador.
        self.caido_ui_port = _env("CAIDO_UI_PUBLIC_PORT")
        self.caido_ui_internal = _env("CAIDO_UI_INTERNAL_URL", "http://caido:8080/")
        self.browser_view_port = _env("BROWSER_VIEW_PUBLIC_PORT")
        self.browser_view_internal = _env("BROWSER_VIEW_INTERNAL_URL", "http://browser-view:6080/")
        self.caido_director_port = _env("CAIDO_DIRECTOR_PUBLIC_PORT")
        self.caido_director_internal = _env("CAIDO_DIRECTOR_INTERNAL_URL", "http://caido-director:6080/")
        # Proxy de la UI de Caido (auto-login de invitado) servido por ESTE proceso en otro puerto.
        self.caido_proxy_port = _env("CAIDO_PROXY_PORT", "7001")
        self.dashboard_url = _env("HERMES_DASHBOARD_PUBLIC_URL")
        self.webapp_url = _env("HERMES_WEBAPP_PUBLIC_URL")
        self.host = _env("VULNERATOR_WEB_HOST", "0.0.0.0")
        self.port = int(_env("VULNERATOR_WEB_PORT", "9100") or 9100)
        # Tareas de fondo (sondeo de Hermes/Caido). Los tests las apagan y alimentan el store.
        self.background = True
        # Acceso sin credenciales (oficial): VULNERATOR_WEB_AUTH=0 desactiva el Basic auth.
        self.auth_enabled = _env("VULNERATOR_WEB_AUTH", "1").lower() not in ("0", "false", "no", "off")
        # Disparador de informe (POST /api/report): es la ÚNICA acción que la consola puede iniciar
        # sobre Hermes. ON por defecto; VULNERATOR_WEB_ALLOW_TRIGGER=0 lo desactiva y deja la consola
        # en modo SOLO-OBSERVACIÓN (el botón "Generar informe" se oculta y la ruta responde 403).
        self.allow_trigger = _env("VULNERATOR_WEB_ALLOW_TRIGGER", "1").lower() not in ("0", "false", "no", "off")
        # Informe: lee los artefactos del engagement (severities.json / pentest-report.md) del
        # volumen compartido kali-artifacts montado aquí en modo lectura.
        self.artifacts_dir = _env("VULNERATOR_WEB_ARTIFACTS_DIR", "/artifacts")
        # Engagement/cliente/operador del informe. VACIOS por defecto: nada de datos reales en el
        # codigo. El handler deriva el engagement del engagement_id de los hallazgos; cliente y
        # operador solo salen en el informe si los defines (en tu .env, git-ignored).
        self.engagement = _env("VULNERATOR_WEB_ENGAGEMENT", "")
        self.client = _env("VULNERATOR_WEB_CLIENT", "")
        self.operator = _env("VULNERATOR_WEB_OPERATOR", "")

    def validate(self) -> list[str]:
        problems = []
        if self.auth_enabled and not self.password:
            problems.append("VULNERATOR_WEB_PASSWORD vacío: la GUI no arranca sin credencial (fail-closed). "
                            "Usa VULNERATOR_WEB_AUTH=0 para desactivar el login explícitamente.")
        if not self.hermes_key:
            problems.append("HERMES_API_SERVER_KEY vacío: sin él no se puede leer la API de Hermes.")
        return problems


# --------------------------------------------------------------------------- sesión
SESSION_COOKIE = "vweb_session"
SESSION_TTL_S = 12 * 3600
# Rutas sin auth: vida del proceso, login/logout y estáticos (no son secretos).
_OPEN_EXACT = ("/healthz", "/login", "/logout")
_OPEN_PREFIX = ("/static/",)


def session_key(user: str, password: str, hermes_key: str) -> bytes:
    """Clave HMAC de las cookies/enlaces: derivada de la credencial (cambiarla invalida todo)."""
    return hashlib.sha256(("vweb-session\0%s\0%s\0%s" % (user, password, hermes_key)).encode()).digest()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(key: bytes, kind: str, payload: str) -> str:
    mac = hmac.new(key, ("%s|%s" % (kind, payload)).encode(), hashlib.sha256).digest()
    return "%s.%s" % (_b64(payload.encode()), _b64(mac))


def verify(key: bytes, kind: str, token: str) -> Optional[str]:
    """Devuelve el payload si la firma es válida (tiempo constante); None si no."""
    try:
        body, mac = token.split(".", 1)
        payload = _unb64(body).decode()
        expected = hmac.new(key, ("%s|%s" % (kind, payload)).encode(), hashlib.sha256).digest()
        return payload if hmac.compare_digest(_unb64(mac), expected) else None
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return None


def make_session_cookie(key: bytes, user: str, now: Optional[float] = None) -> str:
    exp = int((now or time.time()) + SESSION_TTL_S)
    return sign(key, "session", "%s|%d" % (user, exp))


def check_session_cookie(key: bytes, token: str, now: Optional[float] = None) -> bool:
    payload = verify(key, "session", token or "")
    if not payload:
        return False
    _user, _, exp = payload.rpartition("|")
    try:
        return int(exp) > (now or time.time())
    except ValueError:
        return False


def safe_next(target: Optional[str]) -> str:
    """Solo rutas locales (``/...``): evita redirecciones abiertas a otro host."""
    t = (target or "/").strip()
    if not t.startswith("/") or t.startswith("//") or t.startswith("/\\") or "\\" in t:
        return "/"
    return t


# --------------------------------------------------------------------------- middleware
_SECURITY_HEADERS = [
    (b"content-security-policy",
     b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
     b"connect-src 'self'; font-src 'self'; frame-src http: https:; object-src 'none'; "
     b"base-uri 'none'; form-action 'self'; frame-ancestors 'none'"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"cache-control", b"no-store"),
]


class SecurityMiddleware:
    """Basic auth (salvo ``/healthz`` exacto) + cabeceras de seguridad en toda respuesta."""

    def __init__(self, app, user: str, password: str, key: bytes = b"", enabled: bool = True) -> None:
        self.app = app
        self._user = user.encode("utf-8")
        self._password = password.encode("utf-8")
        self._key = key
        self._enabled = enabled

    def _cookie_ok(self, scope) -> bool:
        if not self._key:
            return False
        for key, value in scope.get("headers") or []:
            if key == b"cookie":
                for part in value.decode("latin-1").split(";"):
                    name, _, val = part.strip().partition("=")
                    if name == SESSION_COOKIE and check_session_cookie(self._key, val):
                        return True
        return False

    def _authorized(self, scope) -> bool:
        for key, value in scope.get("headers") or []:
            if key == b"authorization":
                scheme, _, token = value.partition(b" ")
                if scheme.lower() != b"basic":
                    return False
                try:
                    raw = base64.b64decode(token.strip(), validate=True)
                except (binascii.Error, ValueError):
                    return False
                user, sep, password = raw.partition(b":")
                if not sep:
                    return False
                ok_user = hmac.compare_digest(user, self._user)
                ok_pass = hmac.compare_digest(password, self._password)
                return ok_user and ok_pass
        return False

    @staticmethod
    def _wants_html(scope) -> bool:
        if scope.get("method") != "GET":
            return False
        for key, value in scope.get("headers") or []:
            if key == b"accept":
                return b"text/html" in value
        return False

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                present = {k.lower() for k, _ in headers}
                headers.extend((k, v) for k, v in _SECURITY_HEADERS if k not in present)
                message["headers"] = headers
            await send(message)

        path = scope.get("path") or ""
        open_route = (not self._enabled) or path in _OPEN_EXACT or path.startswith(_OPEN_PREFIX)
        if not open_route and not (self._cookie_ok(scope) or self._authorized(scope)):
            if self._wants_html(scope):
                from urllib.parse import quote
                resp = RedirectResponse("/login?next=" + quote(path or "/", safe="/"), status_code=303)
                return await resp(scope, receive, send_with_headers)
            resp = PlainTextResponse(
                "Autenticación requerida", status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="Vulnerator-AI", charset="UTF-8"'},
            )
            return await resp(scope, receive, send_with_headers)
        return await self.app(scope, receive, send_with_headers)


# --------------------------------------------------------------------------- helpers
def _int(value: Optional[str], default: int, lo: int = 0, hi: int = 10**12) -> int:
    try:
        n = int(value) if value not in (None, "") else default
    except (TypeError, ValueError):
        n = default
    return max(lo, min(hi, n))


def _sid(request: Request) -> Optional[str]:
    sid = request.path_params.get("sid", "")
    return sid if _SID_RE.match(sid or "") else None


def _bad(msg: str, code: int = 400) -> JSONResponse:
    return JSONResponse({"error": msg}, status_code=code)


def _state(request: Request):
    return request.app.state


def _pocs_for(app_state, sid: str) -> list[dict[str, Any]]:
    """PoCs de una sesión con caché por versión (último seq de la sesión)."""
    sess = app_state.store.session(sid)
    if sess is None:
        return []
    events = app_state.store.session_events(sid)
    last = events[-1]["seq"] if events else 0
    cached = app_state.poc_cache.get(sid)
    if cached and cached[0] == last:
        pocs = cached[1]
    else:
        pocs = poc_replay.build_pocs(events)
        app_state.poc_cache[sid] = (last, pocs)
    # Severidad: ÚNICA fuente de verdad (report.severity_for), resuelta aquí para TODO consumidor
    # (consola, informe, contadores, filtro). Se aplica en cada llamada para reflejar el
    # severities.json ACTUAL de la IA sin invalidar la caché de build_pocs. El engagement se deriva
    # en sitio desde los propios PoC (NO con _engagement(), que llamaría de vuelta a _pocs_for).
    eng = ""
    for p in pocs:
        eid = (p.get("finding") or {}).get("engagement_id")
        if eid:
            eng = eid
            break
    ai = _load_severities(app_state.settings, eng or app_state.settings.engagement)
    for p in pocs:
        title = (p.get("finding") or {}).get("title", "")
        p["sev"], p["sev_by"], p["score"], p["rationale"] = report.severity_for(title, ai)
    return pocs


_PROBE_TTL_S = 20.0


async def probe_ui(app_state, key: str, url: str) -> dict[str, Any]:
    """¿Responde la UI de Hermes en la red interna? (caché ``_PROBE_TTL_S``; nunca lanza).

    Cualquier respuesta HTTP < 500 (incluida la redirección/401 del sign-in) cuenta como "en
    línea"; un fallo de conexión o un 5xx, como "no disponible" con el motivo. No se sigue la
    redirección ni se manda credencial: solo se comprueba que el listener está vivo.
    """
    cache = app_state.probe_cache
    hit = cache.get(key)
    if hit and time.time() - hit["checked_at"] < _PROBE_TTL_S:
        return hit
    import httpx
    result: dict[str, Any] = {"up": False, "detail": None, "checked_at": time.time()}
    if not url:
        result["detail"] = "sin URL interna configurada"
    else:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(3.0), follow_redirects=False) as c:
                resp = await c.get(url)
            result["up"] = resp.status_code < 500
            result["detail"] = "HTTP %s" % resp.status_code
        except Exception as exc:  # red: se informa, no se finge
            result["detail"] = em.one_line(str(exc) or exc.__class__.__name__, 160)
    cache[key] = result
    return result


# --------------------------------------------------------------------------- handlers
async def healthz(request: Request) -> Response:
    return JSONResponse({"status": "ok"})


def _set_session(resp: Response, settings: "Settings") -> Response:
    key = session_key(settings.user, settings.password, settings.hermes_key)
    resp.set_cookie(SESSION_COOKIE, make_session_cookie(key, settings.user), max_age=SESSION_TTL_S,
                    httponly=True, samesite="strict", path="/")
    return resp


async def login_page(request: Request) -> Response:
    if request.method == "GET":
        return FileResponse(STATIC / "login.html", media_type="text/html; charset=utf-8")
    from urllib.parse import parse_qs, quote
    body = (await request.body())[:4096].decode("utf-8", "replace")
    form = {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}
    s: Settings = _state(request).settings
    target = safe_next(form.get("next"))
    ok_user = hmac.compare_digest(form.get("user", "").encode(), s.user.encode())
    ok_pass = hmac.compare_digest(form.get("password", "").encode(), s.password.encode())
    if not (ok_user and ok_pass):
        await asyncio.sleep(0.4)  # frena la fuerza bruta online sin bloquear el loop
        return RedirectResponse("/login?error=1&next=" + quote(target, safe="/"), status_code=303)
    return _set_session(RedirectResponse(target, status_code=303), s)


async def logout(request: Request) -> Response:
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp


async def index(request: Request) -> Response:
    return FileResponse(STATIC / "index.html", media_type="text/html; charset=utf-8")


async def api_status(request: Request) -> Response:
    st = _state(request)
    s: Settings = st.settings
    dash, webapp, caido_ui, browser_view, caido_dir = await asyncio.gather(
        probe_ui(st, "dashboard", s.dashboard_internal), probe_ui(st, "webapp", s.webapp_internal),
        probe_ui(st, "caido_ui", s.caido_ui_internal if s.caido_ui_port else ""),
        probe_ui(st, "browser_view", s.browser_view_internal if s.browser_view_port else ""),
        probe_ui(st, "caido_director", s.caido_director_internal if s.caido_director_port else ""))
    return JSONResponse({
        "now": time.time(),
        "allow_trigger": s.allow_trigger,
        "ingest": st.ingestor.status,
        "caido": st.caido.status if st.caido else {"enabled": False},
        "max_seq": st.store.max_seq(),
        "hermes": {
            "dashboard": {"port": s.dashboard_port, "url": s.dashboard_url or None,
                          "up": dash["up"], "detail": dash["detail"]},
            "webapp": {"port": s.webapp_port, "url": s.webapp_url or None,
                       "up": webapp["up"], "detail": webapp["detail"]},
        },
        "screens": {
            "caido": {"port": s.caido_ui_port or None, "up": caido_ui["up"],
                      "detail": caido_ui["detail"]},
            "browser": {"port": s.browser_view_port or None, "up": browser_view["up"],
                        "detail": browser_view["detail"]},
            "caido_director": {"port": s.caido_director_port or None, "up": caido_dir["up"],
                               "detail": caido_dir["detail"]},
        },
    })


async def api_sessions(request: Request) -> Response:
    limit = _int(request.query_params.get("limit"), 100, 1, 1000)
    return JSONResponse({"data": _state(request).store.list_sessions(limit)})


async def api_session(request: Request) -> Response:
    sid = _sid(request)
    if not sid:
        return _bad("session id inválido")
    sess = _state(request).store.session(sid)
    if sess is None:
        return _bad("sesión no encontrada", 404)
    return JSONResponse(sess)


async def api_session_events(request: Request) -> Response:
    sid = _sid(request)
    if not sid:
        return _bad("session id inválido")
    q = request.query_params
    kinds = [k for k in (q.get("kinds") or "").split(",") if k]
    store: TraceStore = _state(request).store
    if q.get("tail"):
        evs = store.tail_events(sid, _int(q.get("tail"), 400, 1, 5000), text_limit=LIST_TEXT_MAX)
        if kinds:
            evs = [e for e in evs if e["kind"] in kinds]
    else:
        evs = store.events(_int(q.get("after"), 0), session_id=sid, kinds=kinds,
                           limit=_int(q.get("limit"), 500, 1, 5000), text_limit=LIST_TEXT_MAX)
    return JSONResponse({"data": evs, "max_seq": store.max_seq()})


async def api_trace(request: Request) -> Response:
    sid = _sid(request)
    if not sid:
        return _bad("session id inválido")
    store: TraceStore = _state(request).store
    if store.session(sid) is None:
        return _bad("sesión no encontrada", 404)
    return JSONResponse({"summary": store.trace_summary(sid), "spans": store.spans(sid),
                         "session": store.session(sid), "now": time.time()})


async def api_session_pocs(request: Request) -> Response:
    sid = _sid(request)
    if not sid:
        return _bad("session id inválido")
    return JSONResponse({"data": _pocs_for(_state(request), sid)})


async def api_poc_file(request: Request) -> Response:
    sid = _sid(request)
    call = request.path_params.get("call", "")
    ext = request.path_params.get("ext", "")
    if not sid or not _CALL_RE.match(call or "") or ext not in ("cast", "md"):
        return _bad("parámetros inválidos")
    for poc in _pocs_for(_state(request), sid):
        if poc.get("call_id") == call:
            name = ingest.poc_basename(poc) + "." + ext
            if ext == "cast":
                body, media = poc_replay.to_asciicast(poc), "application/x-asciicast"
            else:
                body, media = poc_replay.to_markdown(poc), "text/markdown; charset=utf-8"
            return Response(body, media_type=media, headers={
                "Content-Disposition": 'attachment; filename="%s"' % name})
    return _bad("PoC no encontrado", 404)


async def api_pocs(request: Request) -> Response:
    st = _state(request)
    out = []
    for sess in st.store.list_sessions(200):
        if not sess.get("findings"):
            continue
        for poc in _pocs_for(st, sess["id"]):
            f = poc["finding"]
            out.append({
                "id": poc["id"], "session_id": poc["session_id"], "call_id": poc["call_id"],
                "session_title": sess.get("title") or sess.get("preview"),
                "ts": poc["ts"], "title": f["title"], "state": f["state"],
                "target": f.get("target"), "technique_id": f.get("technique_id"),
                "store_status": poc["store_status"], "confirmed": poc["confirmed"],
                "phase": poc.get("phase"), "step": poc.get("step"),
                # Severidad ya resuelta en el backend (ver _pocs_for): el front solo la pinta.
                "sev": poc.get("sev"), "sev_by": poc.get("sev_by"),
                "score": poc.get("score"), "rationale": poc.get("rationale"),
            })
    out.sort(key=lambda p: p.get("ts") or 0, reverse=True)
    return JSONResponse({"data": out})


# --------------------------------------------------------------------------- informe
# Instruccion de la generacion del informe: la IA evalua severidad por riesgo real y la graba,
# y luego redacta el informe. chmod 644 para que ESTE proceso (uid no-root) pueda leer los
# artefactos del volumen compartido.
REPORT_INPUT = (
    "mode: pentest. Trabaja EXCLUSIVAMENTE sobre los hallazgos ya registrados en el store de esta sesion. "
    "NO realices nuevo escaneo, enumeracion ni pruebas sobre los hosts.\n\n"
    "PASO 1 — SEVERIDAD POR CRITERIO PROPIO: evalua la severidad REAL de cada hallazgo segun riesgo "
    "operativo, no solo el CVSS del titulo. Ejemplos: una base de datos de PRODUCCION expuesta en red, "
    "APP_DEBUG=true en produccion, phpinfo() expuesto, paneles/metricas sin autenticar o software EOL sin "
    "parches son de severidad alta o media aunque el titulo no lleve CVSS. Escribe con kali_run el fichero "
    "/artifacts/{eng}/severities.json con un objeto JSON valido (comillas dobles) que mapea el TITULO EXACTO "
    "de cada hallazgo (verbatim, tal cual esta registrado) a "
    '{"severity":"critical|high|medium|low|info","cvss":<numero 0.0-10.0>,"rationale":"<justificacion breve>"}. '
    "El CVSS es OBLIGATORIO (nunca null): asigna la nota que corresponda y que sea COHERENTE con la "
    "severidad — critical 9.0-10.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9, info 0.0. "
    "Incluye TODOS los hallazgos.\n\n"
    "PASO 2 — INFORME: genera el informe formal (skill pentest-report, base report_gen.py) usando esas "
    "severidades. Para cada hallazgo: severidad, vector, version afectada, version parcheada y recomendacion. "
    "Entrega Markdown y su version HTML (pentest-report.html).\n\n"
    "PASO 3: ejecuta con kali_run 'chmod 644 /artifacts/{eng}/severities.json /artifacts/{eng}/pentest-report.md "
    "/artifacts/{eng}/pentest-report.html' para que la consola pueda servir los artefactos."
)


def _report_sid(state, q) -> Optional[str]:
    sid = q.get("session")
    if sid:
        return sid
    best = None
    for s in state.store.list_sessions(200):
        if (s.get("findings") or 0) <= 0:
            continue
        if s.get("source") == "api_server":
            return s["id"]
        best = best or s["id"]
    return best


def _read_artifact_text(settings, name: str, eng: str) -> str:
    if not eng:
        return ""
    try:
        return (Path(settings.artifacts_dir) / eng / name).read_text(
            encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _load_severities(settings, eng: str) -> dict:
    txt = _read_artifact_text(settings, "severities.json", eng)
    if not txt:
        return {}
    try:
        d = json.loads(txt)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _engagement(state, settings, sid) -> str:
    """Engagement del informe: el engagement_id de los hallazgos de la sesion; si no, el de env."""
    if sid:
        for p in _pocs_for(state, sid):
            eid = (p.get("finding") or {}).get("engagement_id")
            if eid:
                return eid
    return settings.engagement


async def api_severities(request: Request) -> Response:
    st = _state(request)
    sid = _report_sid(st, request.query_params)
    return JSONResponse(_load_severities(st.settings, _engagement(st, st.settings, sid)))


async def api_report(request: Request) -> Response:
    ext = request.path_params.get("ext", "")
    if ext not in ("md", "txt", "html"):
        return _bad("formato no soportado", 404)
    st = _state(request)
    settings = st.settings
    sid = _report_sid(st, request.query_params)
    pocs = _pocs_for(st, sid) if sid else []
    eng = _engagement(st, settings, sid)
    ai_sev = _load_severities(settings, eng)
    findings = report.normalize(pocs, ai_sev)
    narrative = _read_artifact_text(settings, "pentest-report.md", eng)
    dl = request.query_params.get("dl") == "1"
    kw = dict(engagement=eng or "engagement", narrative=narrative,
              client=settings.client, operator=settings.operator)

    def cd(fn):
        return {"Content-Disposition": 'attachment; filename="%s"' % fn} if dl else {}

    if ext == "md":
        return Response(report.render_md(findings, **kw),
                        media_type="text/markdown; charset=utf-8", headers=cd("pentest-report.md"))
    if ext == "txt":
        return Response(report.render_txt(findings, **kw),
                        media_type="text/plain; charset=utf-8", headers=cd("pentest-report.txt"))
    return Response(report.render_html(findings, **kw),
                    media_type="text/html; charset=utf-8", headers=cd("pentest-report.html"))


async def api_report_trigger(request: Request) -> Response:
    st = _state(request)
    settings = st.settings
    if not settings.allow_trigger:
        return _bad("Disparador de informe desactivado (VULNERATOR_WEB_ALLOW_TRIGGER=0): "
                    "consola en modo solo-observación.", 403)
    if not settings.hermes_key:
        return _bad("sin HERMES_API_SERVER_KEY: no se puede lanzar el informe", 503)
    try:
        body = await request.json()
    except Exception:
        body = {}
    sid = (body or {}).get("session_id") or _report_sid(st, request.query_params)
    eng = _engagement(st, settings, sid) or "engagement"
    payload = {"input": REPORT_INPUT.replace("{eng}", eng)}
    if sid:
        payload["session_id"] = sid
    import httpx
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0), follow_redirects=False) as c:
            r = await c.post(settings.hermes_url.rstrip("/") + "/v1/runs",
                             headers={"Authorization": "Bearer " + settings.hermes_key},
                             json=payload)
        return Response(r.text, status_code=r.status_code, media_type="application/json")
    except Exception as e:  # noqa: BLE001
        return _bad("no se pudo lanzar el informe: %s" % e, 502)


async def api_event(request: Request) -> Response:
    seq = _int(request.path_params.get("seq"), -1, -1)
    ev = _state(request).store.event(seq) if seq >= 0 else None
    if ev is None:
        return _bad("evento no encontrado", 404)
    if ev.get("kind") == em.KIND_TOOL_RESULT:
        ev["output"] = em.tool_output_text(ev.get("text") or "")
    return JSONResponse(ev)


async def api_web(request: Request) -> Response:
    q = request.query_params
    store: TraceStore = _state(request).store
    if q.get("tail"):
        evs = store.tail_events(limit=_int(q.get("tail"), 200, 1, 2000), kinds=[em.KIND_WEB])
    else:
        evs = store.events(_int(q.get("after"), 0), kinds=[em.KIND_WEB],
                           limit=_int(q.get("limit"), 500, 1, 5000))
    return JSONResponse({"data": evs})


async def api_stream(request: Request) -> Response:
    st = _state(request)
    store: TraceStore = st.store
    notifier: ingest.Notifier = st.notifier
    after = _int(request.headers.get("last-event-id") or request.query_params.get("after"),
                 store.max_seq())
    sid = request.query_params.get("session") or None
    if sid and not _SID_RE.match(sid):
        return _bad("session id inválido")

    async def gen():
        cursor = after
        version = notifier.version
        yield "retry: 2000\n\n"
        while True:
            if await request.is_disconnected():
                return
            batch = store.events(cursor, session_id=sid, limit=500, text_limit=LIST_TEXT_MAX)
            for ev in batch:
                cursor = ev["seq"]
                data = json.dumps(ev, ensure_ascii=False, default=str)
                yield "id: %d\nevent: ev\ndata: %s\n\n" % (cursor, data)
            if len(batch) >= 500:
                continue
            new_version = await notifier.wait(version, STREAM_HEARTBEAT_S)
            if new_version == version:
                yield ": ping\n\n"
            version = new_version

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# --------------------------------------------------------------------------- app
@contextlib.asynccontextmanager
async def lifespan(app: Starlette):
    s: Settings = app.state.settings
    if s.db_path != ":memory:":
        Path(s.db_path).parent.mkdir(parents=True, exist_ok=True)
    app.state.store = TraceStore(s.db_path)
    app.state.notifier = ingest.Notifier()
    app.state.poc_cache = {}
    app.state.probe_cache = {}
    hermes = ingest.HermesSessions(s.hermes_url, s.hermes_key)
    app.state.ingestor = ingest.SessionIngestor(
        app.state.store, app.state.notifier, hermes, interval=s.poll, poc_dir=s.poc_dir)
    tasks = []
    if s.background:
        tasks.append(asyncio.create_task(app.state.ingestor.run(), name="session-ingest"))
    app.state.caido = None
    if s.caido_feed and s.background:
        try:
            import caido_client  # mismo módulo stdlib que usa kali-mcp (copiado en la imagen)
        except ImportError:
            caido_client = None
            ingest._log("caido_client no disponible: feed de tráfico web desactivado")
        if caido_client is not None:
            app.state.caido = ingest.CaidoFeed(
                app.state.store, app.state.notifier,
                lambda httpql, limit: caido_client.search_history(httpql=httpql, limit=limit, timeout=15),
            )
            tasks.append(asyncio.create_task(app.state.caido.run(), name="caido-feed"))
    # Segundo servidor en el mismo proceso: la UI de Caido pre-autenticada como invitado,
    # servida desde nuestro origen para poder inyectar el token (ver caido_proxy.py). Gobernado
    # por el MISMO interruptor que el feed (CAIDO_FEED): =0 apaga TODO lo de Caido (feed + proxy).
    if s.caido_proxy_port and s.caido_feed and s.background:
        try:
            import uvicorn
            from caido_proxy import create_caido_proxy_app
            capp = create_caido_proxy_app(s.caido_ui_internal)
            cconf = uvicorn.Config(capp, host="0.0.0.0", port=int(s.caido_proxy_port),
                                   log_level="warning", access_log=False)
            tasks.append(asyncio.create_task(uvicorn.Server(cconf).serve(), name="caido-proxy"))
        except Exception as exc:  # el proxy es opcional: su fallo no tumba la consola
            ingest._log("proxy de Caido no disponible: %s" % exc)
    try:
        yield
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await hermes.close()
        app.state.store.close()


def create_app(settings: Optional[Settings] = None) -> Starlette:
    settings = settings or Settings()
    routes = [
        Route("/healthz", healthz),
        Route("/", index),
        Route("/login", login_page, methods=["GET", "POST"]),
        Route("/logout", logout),
        Route("/api/status", api_status),
        Route("/api/sessions", api_sessions),
        Route("/api/sessions/{sid}", api_session),
        Route("/api/sessions/{sid}/events", api_session_events),
        Route("/api/sessions/{sid}/trace", api_trace),
        Route("/api/sessions/{sid}/pocs", api_session_pocs),
        Route("/api/sessions/{sid}/pocs/{call}.{ext}", api_poc_file),
        Route("/api/pocs", api_pocs),
        Route("/api/events/{seq:int}", api_event),
        Route("/api/web", api_web),
        Route("/api/stream", api_stream),
        Route("/api/severities", api_severities),
        Route("/api/report", api_report_trigger, methods=["POST"]),
        Route("/api/report.{ext}", api_report),
        Mount("/static", app=StaticFiles(directory=str(STATIC)), name="static"),
    ]
    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.settings = settings
    app.add_middleware(SecurityMiddleware, user=settings.user, password=settings.password,
                       key=session_key(settings.user, settings.password, settings.hermes_key),
                       enabled=settings.auth_enabled)
    return app


def main() -> None:
    settings = Settings()
    problems = settings.validate()
    if problems:
        for p in problems:
            sys.stderr.write("[vulnerator-web] ERROR: %s\n" % p)
        sys.exit(2)
    import uvicorn
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port,
                log_level="warning", proxy_headers=False, access_log=False)


if __name__ == "__main__":
    main()
