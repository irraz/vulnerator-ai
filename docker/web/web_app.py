"""vulnerator-web — the Vulnerator-AI web GUI (thin Starlette layer over pure modules).

Serves an operator console (``static/``) and its API:

  GET /healthz                               process liveness (NO auth, exact match)
  GET /api/status                            Hermes/ingest/Caido + ports of the Hermes UIs
  GET /api/sessions                          sessions (includes subagents) with counters
  GET /api/sessions/{sid}                    a single session
  GET /api/sessions/{sid}/events             events (``after``/``tail``/``kinds``/``limit``)
  GET /api/sessions/{sid}/trace              spans + per-tool aggregates (Langfuse-style view)
  GET /api/sessions/{sid}/pocs               PoCs of the session (OODA chain + replay)
  GET /api/sessions/{sid}/pocs/{call}.cast   asciinema v2 recording of the PoC
  GET /api/sessions/{sid}/pocs/{call}.md     Markdown sheet of the PoC
  GET /api/pocs                              index of findings across all sessions
  GET /api/events/{seq}                      a single event with its FULL text
  GET /api/web                               web traffic captured by Caido
  GET /api/stream                            live SSE (resumable with Last-Event-ID)

OBSERVER by design: it reads the Hermes sessions API and the Caido history and displays them; it
does not drive or stop runs. The ONLY action it can start, on operator demand, is generating the
formal report ("Generate report" button -> POST /api/report); it is disabled with
VULNERATOR_WEB_ALLOW_TRIGGER=0 (console in observe-only mode). The logic lives in pure-stdlib
modules (``event_model``, ``trace_store``, ``poc_replay``, ``ooda_parse``) covered by
tests; here there is only HTTP, auth and wiring.

Security:
  - Mandatory Basic auth (constant-time comparison); FAIL-CLOSED: the process does not
    start without ``VULNERATOR_WEB_PASSWORD`` nor without ``HERMES_API_SERVER_KEY``.
  - Strict CSP (no inline scripts/styles), ``nosniff``, ``no-referrer``, no framing.
  - Everything coming from Hermes/Caido is UNTRUSTED DATA: it is returned as JSON and the
    frontend renders it as text, never as HTML.
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
# Max text per event in listings and stream (the full one: /api/events/{seq}).
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
        # Live screens (for presentations): Caido UI and, later on, the browser.
        self.caido_ui_port = _env("CAIDO_UI_PUBLIC_PORT")
        self.caido_ui_internal = _env("CAIDO_UI_INTERNAL_URL", "http://caido:8080/")
        self.browser_view_port = _env("BROWSER_VIEW_PUBLIC_PORT")
        self.browser_view_internal = _env("BROWSER_VIEW_INTERNAL_URL", "http://browser-view:6080/")
        self.caido_director_port = _env("CAIDO_DIRECTOR_PUBLIC_PORT")
        self.caido_director_internal = _env("CAIDO_DIRECTOR_INTERNAL_URL", "http://caido-director:6080/")
        # Caido UI proxy (guest auto-login) served by THIS process on another port.
        self.caido_proxy_port = _env("CAIDO_PROXY_PORT", "7001")
        self.dashboard_url = _env("HERMES_DASHBOARD_PUBLIC_URL")
        self.webapp_url = _env("HERMES_WEBAPP_PUBLIC_URL")
        self.host = _env("VULNERATOR_WEB_HOST", "0.0.0.0")
        self.port = int(_env("VULNERATOR_WEB_PORT", "9100") or 9100)
        # Background tasks (polling Hermes/Caido). Tests turn them off and feed the store.
        self.background = True
        # Credential-free access (official): VULNERATOR_WEB_AUTH=0 disables Basic auth.
        self.auth_enabled = _env("VULNERATOR_WEB_AUTH", "1").lower() not in ("0", "false", "no", "off")
        # Report trigger (POST /api/report): it is the ONLY action the console can start
        # against Hermes. ON by default; VULNERATOR_WEB_ALLOW_TRIGGER=0 disables it and leaves the
        # console in OBSERVE-ONLY mode (the "Generate report" button is hidden and the route returns 403).
        self.allow_trigger = _env("VULNERATOR_WEB_ALLOW_TRIGGER", "1").lower() not in ("0", "false", "no", "off")
        # Report: reads the engagement artifacts (severities.json / pentest-report.md) from the
        # shared kali-artifacts volume mounted here in read-only mode.
        self.artifacts_dir = _env("VULNERATOR_WEB_ARTIFACTS_DIR", "/artifacts")
        # Engagement/client/operator of the report. EMPTY by default: no real data in the
        # code. The handler derives the engagement from the engagement_id of the findings; client and
        # operator only appear in the report if you define them (in your .env, git-ignored).
        self.engagement = _env("VULNERATOR_WEB_ENGAGEMENT", "")
        self.client = _env("VULNERATOR_WEB_CLIENT", "")
        self.operator = _env("VULNERATOR_WEB_OPERATOR", "")

    def validate(self) -> list[str]:
        problems = []
        if self.auth_enabled and not self.password:
            problems.append("VULNERATOR_WEB_PASSWORD empty: the GUI does not start without a credential (fail-closed). "
                            "Use VULNERATOR_WEB_AUTH=0 to disable login explicitly.")
        if not self.hermes_key:
            problems.append("HERMES_API_SERVER_KEY empty: without it the Hermes API cannot be read.")
        return problems


# --------------------------------------------------------------------------- session
SESSION_COOKIE = "vweb_session"
SESSION_TTL_S = 12 * 3600
# Routes without auth: process liveness, login/logout and static files (not secrets).
_OPEN_EXACT = ("/healthz", "/login", "/logout")
_OPEN_PREFIX = ("/static/",)


def session_key(user: str, password: str, hermes_key: str) -> bytes:
    """HMAC key for cookies/links: derived from the credential (changing it invalidates everything)."""
    return hashlib.sha256(("vweb-session\0%s\0%s\0%s" % (user, password, hermes_key)).encode()).digest()


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def sign(key: bytes, kind: str, payload: str) -> str:
    mac = hmac.new(key, ("%s|%s" % (kind, payload)).encode(), hashlib.sha256).digest()
    return "%s.%s" % (_b64(payload.encode()), _b64(mac))


def verify(key: bytes, kind: str, token: str) -> Optional[str]:
    """Returns the payload if the signature is valid (constant time); None otherwise."""
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
    """Local routes only (``/...``): avoids open redirects to another host."""
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
    """Basic auth (except exact ``/healthz``) + security headers on every response."""

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
                "Authentication required", status_code=401,
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
    """PoCs of a session with per-version cache (last seq of the session)."""
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
    # Severity: SINGLE source of truth (report.severity_for), resolved here for EVERY consumer
    # (console, report, counters, filter). It is applied on each call to reflect the AI's CURRENT
    # severities.json without invalidating the build_pocs cache. The engagement is derived
    # in place from the PoCs themselves (NOT with _engagement(), which would call back into _pocs_for).
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
    """Does the Hermes UI respond on the internal network? (``_PROBE_TTL_S`` cache; never raises).

    Any HTTP response < 500 (including the sign-in redirect/401) counts as "online"; a connection
    failure or a 5xx counts as "unavailable" with the reason. The redirect is not followed and no
    credential is sent: it only checks that the listener is alive.
    """
    cache = app_state.probe_cache
    hit = cache.get(key)
    if hit and time.time() - hit["checked_at"] < _PROBE_TTL_S:
        return hit
    import httpx
    result: dict[str, Any] = {"up": False, "detail": None, "checked_at": time.time()}
    if not url:
        result["detail"] = "no internal URL configured"
    else:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(3.0), follow_redirects=False) as c:
                resp = await c.get(url)
            result["up"] = resp.status_code < 500
            result["detail"] = "HTTP %s" % resp.status_code
        except Exception as exc:  # network: report it, don't fake it
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
        await asyncio.sleep(0.4)  # slows online brute force without blocking the loop
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
        return _bad("invalid session id")
    sess = _state(request).store.session(sid)
    if sess is None:
        return _bad("session not found", 404)
    return JSONResponse(sess)


async def api_session_events(request: Request) -> Response:
    sid = _sid(request)
    if not sid:
        return _bad("invalid session id")
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
        return _bad("invalid session id")
    store: TraceStore = _state(request).store
    if store.session(sid) is None:
        return _bad("session not found", 404)
    return JSONResponse({"summary": store.trace_summary(sid), "spans": store.spans(sid),
                         "session": store.session(sid), "now": time.time()})


async def api_session_pocs(request: Request) -> Response:
    sid = _sid(request)
    if not sid:
        return _bad("invalid session id")
    return JSONResponse({"data": _pocs_for(_state(request), sid)})


async def api_poc_file(request: Request) -> Response:
    sid = _sid(request)
    call = request.path_params.get("call", "")
    ext = request.path_params.get("ext", "")
    if not sid or not _CALL_RE.match(call or "") or ext not in ("cast", "md"):
        return _bad("invalid parameters")
    for poc in _pocs_for(_state(request), sid):
        if poc.get("call_id") == call:
            name = ingest.poc_basename(poc) + "." + ext
            if ext == "cast":
                body, media = poc_replay.to_asciicast(poc), "application/x-asciicast"
            else:
                body, media = poc_replay.to_markdown(poc), "text/markdown; charset=utf-8"
            return Response(body, media_type=media, headers={
                "Content-Disposition": 'attachment; filename="%s"' % name})
    return _bad("PoC not found", 404)


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
                # Severity already resolved in the backend (see _pocs_for): the front just renders it.
                "sev": poc.get("sev"), "sev_by": poc.get("sev_by"),
                "score": poc.get("score"), "rationale": poc.get("rationale"),
            })
    out.sort(key=lambda p: p.get("ts") or 0, reverse=True)
    return JSONResponse({"data": out})


# --------------------------------------------------------------------------- report
# Report generation instruction: the AI evaluates severity by real risk and records it,
# and then writes the report. chmod 644 so THIS process (non-root uid) can read the
# artifacts from the shared volume.
REPORT_INPUT = (
    "mode: pentest. Work EXCLUSIVELY on the findings already recorded in the store of this session. "
    "Do NOT perform new scanning, enumeration or testing against the hosts.\n\n"
    "STEP 1 — SEVERITY BY YOUR OWN JUDGMENT: evaluate the REAL severity of each finding based on "
    "operational risk, not just the CVSS in the title. Examples: a PRODUCTION database exposed on the network, "
    "APP_DEBUG=true in production, exposed phpinfo(), unauthenticated panels/metrics or EOL software without "
    "patches are high or medium severity even if the title carries no CVSS. Use kali_run to write the file "
    "/artifacts/{eng}/severities.json with a valid JSON object (double quotes) that maps the EXACT TITLE "
    "of each finding (verbatim, exactly as recorded) to "
    '{"severity":"critical|high|medium|low|info","cvss":<number 0.0-10.0>,"rationale":"<brief justification>"}. '
    "The CVSS is MANDATORY (never null): assign the appropriate score and make it CONSISTENT with the "
    "severity — critical 9.0-10.0, high 7.0-8.9, medium 4.0-6.9, low 0.1-3.9, info 0.0. "
    "Include ALL findings.\n\n"
    "STEP 2 — REPORT: generate the formal report (skill pentest-report, based on report_gen.py) using those "
    "severities. For each finding: severity, vector, affected version, patched version and recommendation. "
    "Deliver Markdown and its HTML version (pentest-report.html).\n\n"
    "STEP 3: run with kali_run 'chmod 644 /artifacts/{eng}/severities.json /artifacts/{eng}/pentest-report.md "
    "/artifacts/{eng}/pentest-report.html' so the console can serve the artifacts."
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
    """Report engagement: the engagement_id of the session's findings; otherwise, the one from env."""
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
        return _bad("unsupported format", 404)
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
        return _bad("Report trigger disabled (VULNERATOR_WEB_ALLOW_TRIGGER=0): "
                    "console in observe-only mode.", 403)
    if not settings.hermes_key:
        return _bad("missing HERMES_API_SERVER_KEY: cannot launch the report", 503)
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
        return _bad("could not launch the report: %s" % e, 502)


async def api_event(request: Request) -> Response:
    seq = _int(request.path_params.get("seq"), -1, -1)
    ev = _state(request).store.event(seq) if seq >= 0 else None
    if ev is None:
        return _bad("event not found", 404)
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
        return _bad("invalid session id")

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
            import caido_client  # same stdlib module used by kali-mcp (copied into the image)
        except ImportError:
            caido_client = None
            ingest._log("caido_client not available: web traffic feed disabled")
        if caido_client is not None:
            app.state.caido = ingest.CaidoFeed(
                app.state.store, app.state.notifier,
                lambda httpql, limit: caido_client.search_history(httpql=httpql, limit=limit, timeout=15),
            )
            tasks.append(asyncio.create_task(app.state.caido.run(), name="caido-feed"))
    # Second server in the same process: the Caido UI pre-authenticated as guest,
    # served from our origin so we can inject the token (see caido_proxy.py). Governed
    # by the SAME switch as the feed (CAIDO_FEED): =0 turns OFF EVERYTHING Caido (feed + proxy).
    if s.caido_proxy_port and s.caido_feed and s.background:
        try:
            import uvicorn
            from caido_proxy import create_caido_proxy_app
            capp = create_caido_proxy_app(s.caido_ui_internal)
            cconf = uvicorn.Config(capp, host="0.0.0.0", port=int(s.caido_proxy_port),
                                   log_level="warning", access_log=False)
            tasks.append(asyncio.create_task(uvicorn.Server(cconf).serve(), name="caido-proxy"))
        except Exception as exc:  # the proxy is optional: its failure doesn't take down the console
            ingest._log("Caido proxy not available: %s" % exc)
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
