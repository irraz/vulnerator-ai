"""Proxy for the Caido UI with guest auto-login (STDLIB + httpx + starlette).

Goal: have the "Screens" tab open the REAL Caido interface already INSIDE as a guest,
without the login screen or the onboarding. Caido authenticates its SPA with the localStorage
key ``CAIDO_AUTHENTICATION`` (a guest token); since the iframe loads Caido on another origin, the
console cannot seed that localStorage (cross-origin). This proxy serves the Caido UI from
vulnerator-web's OWN origin and INJECTS a ``<script>`` at the start of the ``<head>`` that
seeds that token BEFORE the SPA starts. Result: the iframe opens straight into the
HTTP history with the engagement traffic.

Anyone who prefers their own Caido account configures it at install time (environment token); this
proxy only covers the default ZERO-TOUCH guest case.

- The token is obtained via ``loginAsGuest`` (same mechanism as kali-mcp, via ``caido_client``)
  and cached until shortly before it expires.
- Caido's assets are RELATIVE, so the proxy serves at the ROOT of its port and the routes
  resolve on their own. ``Accept-Encoding: identity`` is requested from upstream so the HTML
  can be injected without fighting gzip.
- UNTRUSTED DATA: Caido's content is transported verbatim (except for injecting the
  bootstrap into the HTML); it is not interpreted.
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import httpx  # noqa: E402
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

# Hop-by-hop headers + those that change when rewriting the body: not forwarded.
_DROP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "content-encoding", "content-length", "host",
}



# Onboarding flags that the Caido UI marks when completing/disabling the tutorial (captured
# from the UI's own updateViewerSettings). Setting them all to true = no carousel, no checklist.
_ONBOARDING_DONE = {
    "createdProject": True, "docs": True, "installedPlugin": True, "intercept": True,
    "interceptedRequest": True, "labs": True, "launchedPreconfiguredBrowser": True,
    "plugins": True, "projects": True, "scopes": True, "sentRequestToReplay": True,
    "visitedSettings": True, "welcome": True,
}
# COMPLETE default data (same shape the UI writes) in case the guest does not yet have a
# settings row: this way the write creates a valid, complete row, not a partial one.
_DEFAULT_DATA = {
    "css": "", "editorFontSize": 14, "fontFamily": "Arial", "fontSize": 14, "grids": {},
    "isCommunityStoreEnabled": False, "isSidebarCollapsed": False, "isSidebarHidden": False,
    "js": "", "layoutOrientation": "horizontal", "onboarding": dict(_ONBOARDING_DONE),
    "projects": {}, "shortcuts": [], "sidebarPosition": "left",
    "skipProjectUpgradeConfirmation": False, "tables": {}, "viewModes": {},
}
_VIEWER_SETTINGS_Q = (
    "query{ viewer{ __typename ... on GuestUser{ id settings{ data migrations } }"
    " ... on CloudUser{ id settings{ data migrations } } } }"
)
_VIEWER_SETTINGS_M = (
    "mutation($input: UpdateViewerSettingsInput!){ updateViewerSettings(input:$input)"
    "{ settings{ __typename } } }"
)
# INSTANCE settings (global). SetInstanceSettingsInput is @oneOf: a single field per call.
_INSTANCE_SET_M = (
    "mutation($input: SetInstanceSettingsInput!){ setInstanceSettings(input:$input)"
    "{ settings{ onboarding{ analytic } } } }"
)
_INSTANCE_Q = "query{ instanceSettings{ onboarding{ analytic } } }"


def _mark_instance_onboarded(caido_client, token: str, url: str) -> bool:
    """Marks the INSTANCE onboarding (the 'Privacy-Safe Usage Analytics' screen) as done.

    It is global (not per guest). Sets ``onboarding.analytic=true`` (step completed) and disables
    sending analytics (``analytics.enabled=false``, privacy by default). Idempotent.
    Returns True if it is confirmed.
    """
    try:
        caido_client.graphql(_INSTANCE_SET_M, {"input": {"onboarding": {"analytic": True}}},
                             url=url, token=token, timeout=10)
        caido_client.graphql(_INSTANCE_SET_M, {"input": {"analytics": {"enabled": False}}},
                             url=url, token=token, timeout=10)
        chk = caido_client.graphql(_INSTANCE_Q, url=url, token=token, timeout=10)
        return bool((((chk.get("data") or {}).get("instanceSettings") or {}).get("onboarding") or {}).get("analytic"))
    except Exception as exc:
        sys.stderr.write("[caido-proxy] instance onboarding failed: %s\n" % exc)
        return False


def _mark_onboarded(caido_client, token: str, url: str) -> bool:
    """Marks the onboarding as COMPLETE for the freshly created guest (code-level).

    Reads the viewer settings for the token, sets ``data.onboarding.*`` to true and rewrites them.
    This way the UI, authenticated with that token, does NOT show the "Learn the Essentials"
    carousel or the "Getting started" checklist — it goes straight into the workspace. Best-effort:
    if something fails, the token still works (only the onboarding would be seen).
    """
    try:
        cur = caido_client.graphql(_VIEWER_SETTINGS_Q, url=url, token=token, timeout=10)
        settings = {}
        if cur.get("status") == "ok":
            settings = ((cur.get("data") or {}).get("viewer") or {}).get("settings") or {}
        # Start from the existing row if there is one; otherwise from complete default data.
        data = dict(settings["data"]) if isinstance(settings.get("data"), dict) else dict(_DEFAULT_DATA)
        ob = dict(data.get("onboarding") or {})
        ob.update(_ONBOARDING_DONE)
        data["onboarding"] = ob
        # updateViewerSettings requires both data AND migrations (both JSON!). migrations may not
        # exist yet on a new guest -> [] by default.
        migrations = settings.get("migrations")
        if migrations is None:
            migrations = []
        out = caido_client.graphql(_VIEWER_SETTINGS_M, {"input": {"data": data, "migrations": migrations}},
                                   url=url, token=token, timeout=10)
        if out.get("status") != "ok":
            sys.stderr.write("[caido-proxy] updateViewerSettings failed: %s\n" % (out.get("errors") or out.get("error")))
            return False
        # Verify by reading again: only True if the onboarding ended up COMPLETE.
        chk = caido_client.graphql(_VIEWER_SETTINGS_Q, url=url, token=token, timeout=10)
        cob = ((((chk.get("data") or {}).get("viewer") or {}).get("settings") or {}).get("data") or {}).get("onboarding") or {}
        return bool(cob) and all(cob.values())
    except Exception as exc:  # best-effort
        sys.stderr.write("[caido-proxy] could not mark onboarding: %s\n" % exc)
        return False

class GuestToken:
    """Keeps ONE guest token and guarantees its onboarding is complete (code-level).

    Separates the login (creating the guest) from the onboarding (leaving it tutorial-free): mints ONE
    guest and, on each ``get``, RE-APPLIES the onboarding on THAT same guest until it
    sticks — without creating new guests (avoids churn). This way, on a freshly created
    Caido volume, as soon as its settings subsystem is ready, the onboarding is set and persists.
    """

    def __init__(self, caido_url: str) -> None:
        self._url = caido_url
        self._json: Optional[str] = None
        self._access: Optional[str] = None
        self._renew_at = 0.0
        self._onboarded = False
        self._lock = threading.Lock()

    def _mint(self) -> None:
        """Creates the guest and selects a project. Does NOT do onboarding (that is separate)."""
        import caido_client  # lazy (lives in the image)
        out = caido_client.graphql(caido_client._GUEST_LOGIN, url=self._url, timeout=15)
        if out.get("status") != "ok":
            sys.stderr.write("[caido-proxy] loginAsGuest failed: %s\n" % out.get("error"))
            return
        tok = ((out.get("data") or {}).get("loginAsGuest") or {}).get("token") or {}
        access = tok.get("accessToken")
        if not access:
            return
        try:
            caido_client._ensure_project(access, self._url, 10)
        except Exception as exc:
            sys.stderr.write("[caido-proxy] could not ensure project: %s\n" % exc)
        auth = {
            "__typename": "AuthenticationToken", "accessToken": access,
            "expiresAt": tok.get("expiresAt"), "refreshToken": None, "scopes": ["PROFILE_READ"],
        }
        self._access = access
        self._json = json.dumps(auth, separators=(",", ":"))
        self._onboarded = False
        # Renew at half-life (or 30 min if expiresAt cannot be parsed).
        self._renew_at = time.time() + 1800
        exp = tok.get("expiresAt")
        if isinstance(exp, str):
            try:
                dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
                self._renew_at = (dt.timestamp() + time.time()) / 2
            except ValueError:
                pass

    def get(self) -> Optional[str]:
        with self._lock:
            if self._json is None or self._access is None or time.time() >= self._renew_at:
                self._mint()
            return self._json

    def ensure_onboarded(self) -> bool:
        """(Re)applies the onboarding on the shared guest NOW. Idempotent.

        Called on every HTML page load: since Caido uses ONE shared guest and its SPA
        can rewrite settings, re-applying it right before serving guarantees that the browser
        ALWAYS loads with the onboarding complete (no carousel) no matter how many times it is opened.
        """
        import caido_client  # lazy
        with self._lock:
            if self._json is None or self._access is None or time.time() >= self._renew_at:
                self._mint()
            if not self._access:
                return False
            viewer_ok = _mark_onboarded(caido_client, self._access, self._url)
            instance_ok = _mark_instance_onboarded(caido_client, self._access, self._url)
            self._onboarded = viewer_ok and instance_ok
            return self._onboarded


# CLIENT-side safety net against the onboarding. The GraphQL marking (viewer+instance)
# is the main path, but the SPA may paint the "Learn the Essentials" modal (a blocking
# z-[99999] fixed inset-0 overlay) BEFORE those settings propagate: a race that, once
# seen, forces a reload. This guard kills it no matter what: it collapses the
# "Getting started" checklist and, with a MutationObserver (+ a backup sweep), as soon as
# a full-screen overlay whose text matches the onboarding appears, it clicks "Continue" and
# removes it from the DOM. It identifies the overlay by its TEXT, not by a generic z-index, so as
# not to touch legitimate Caido dialogs. Idempotent and passive if there is no onboarding.
_ONBOARDING_GUARD = r"""<script>(function(){
try{localStorage.setItem('layout.onboarding-checklist.is-expanded','false');}catch(e){}
var RX=/Learn the Essentials|Privacy-Safe Usage Analytics/i;
var GO=/continue|get started|got it|skip|close|accept|dismiss/i;
function kill(){try{
var ov=document.querySelectorAll('[class*="inset-0"]');
for(var i=0;i<ov.length;i++){var el=ov[i];
 if(el.isConnected&&RX.test(el.textContent||'')){
  var bs=el.querySelectorAll('button');
  for(var j=0;j<bs.length;j++){if(GO.test(bs[j].textContent||'')){try{bs[j].click();}catch(e){}break;}}
  try{el.remove();}catch(e){}
 }}
}catch(e){}}
function start(){try{new MutationObserver(kill).observe(document.documentElement,{childList:true,subtree:true});}catch(e){}kill();}
if(document.documentElement)start();else document.addEventListener('DOMContentLoaded',start);
var n=0,iv=setInterval(function(){kill();if(++n>60)clearInterval(iv);},400);
})();</script>"""


def _bootstrap_script(token_json: str) -> str:
    """``<script>`` that seeds the guest token and neutralizes the onboarding (code-level),
    before Caido's SPA starts."""
    # json.dumps of the string -> safe JS literal (correct quotes/escapes).
    return ("<script>try{localStorage.setItem('CAIDO_AUTHENTICATION',"
            + json.dumps(token_json) + ");}catch(e){}</script>" + _ONBOARDING_GUARD)


def inject(html: str, token_json: str) -> str:
    """Inserts the bootstrap right after ``<head>`` (before the deferred modules)."""
    script = _bootstrap_script(token_json)
    low = html.lower()
    i = low.find("<head>")
    if i != -1:
        pos = i + len("<head>")
        return html[:pos] + script + html[pos:]
    i = low.find("<html")
    if i != -1:
        pos = low.find(">", i) + 1
        return html[:pos] + script + html[pos:]
    return script + html


def create_caido_proxy_app(caido_base: str) -> Starlette:
    """ASGI app that proxies the Caido UI at ``caido_base`` injecting the guest token."""
    base = caido_base.rstrip("/")
    token = GuestToken(base)

    async def handler(request: Request) -> Response:
        client: httpx.AsyncClient = request.app.state.client
        url = base + request.url.path
        fwd = {k: v for k, v in request.headers.items() if k.lower() not in _DROP}
        fwd["accept-encoding"] = "identity"
        body = await request.body()
        try:
            up = await client.request(request.method, url, params=request.query_params,
                                      content=body, headers=fwd)
        except httpx.HTTPError as exc:
            return Response("caido upstream unreachable: %s" % exc, status_code=502,
                            media_type="text/plain")
        ct = up.headers.get("content-type", "")
        out_headers = [(k, v) for k, v in up.headers.items() if k.lower() not in _DROP]
        if "text/html" in ct:
            html = up.text
            # Re-apply the onboarding on the shared guest right before serving the UI.
            await asyncio.to_thread(token.ensure_onboarded)
            tok = token.get()
            if tok:
                html = inject(html, tok)
            return Response(html, status_code=up.status_code, headers=dict(out_headers),
                            media_type=ct)
        return Response(up.content, status_code=up.status_code, headers=dict(out_headers),
                        media_type=ct or None)

    async def _startup() -> None:
        app.state.client = httpx.AsyncClient(timeout=httpx.Timeout(30.0, connect=5.0),
                                             follow_redirects=False)
        # Warm up the guest token (login + project + onboarding) in the background, so that
        # the FIRST browser that opens already receives a ready token and does not see the
        # onboarding due to a propagation race.
        async def _warm() -> None:
            for _ in range(20):
                if await asyncio.to_thread(token.ensure_onboarded):
                    return
                await asyncio.sleep(3)
        asyncio.create_task(_warm())

    async def _shutdown() -> None:
        await app.state.client.aclose()

    ws_base = "ws" + base[base.find(":"):]  # http(s)://caido:8080 -> ws(s)://caido:8080

    async def ws_handler(ws: WebSocket) -> None:
        """Bridges a WebSocket between the browser <-> Caido (live GraphQL subscriptions)."""
        import websockets
        subs = ws.scope.get("subprotocols") or []
        target = ws_base + ws.url.path
        try:
            up = await websockets.connect(target, subprotocols=subs or None, open_timeout=10,
                                          max_size=None)
        except Exception as exc:  # upstream refuses: close the browser's socket
            sys.stderr.write("[caido-proxy] ws upstream failed (%s): %s\n" % (target, exc))
            await ws.close()
            return
        await ws.accept(subprotocol=up.subprotocol)

        async def c2u() -> None:
            try:
                while True:
                    msg = await ws.receive()
                    if msg["type"] == "websocket.disconnect":
                        break
                    if msg.get("text") is not None:
                        await up.send(msg["text"])
                    elif msg.get("bytes") is not None:
                        await up.send(msg["bytes"])
            except (WebSocketDisconnect, Exception):
                pass

        async def u2c() -> None:
            try:
                async for message in up:
                    if isinstance(message, (bytes, bytearray)):
                        await ws.send_bytes(message)
                    else:
                        await ws.send_text(message)
            except Exception:
                pass

        import asyncio as _a
        done, pending = await _a.wait({_a.create_task(c2u()), _a.create_task(u2c())},
                                      return_when=_a.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        with __import__("contextlib").suppress(Exception):
            await up.close()
        with __import__("contextlib").suppress(Exception):
            await ws.close()

    app = Starlette(
        routes=[
            WebSocketRoute("/{path:path}", ws_handler),
            Route("/{path:path}", handler,
                  methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]),
        ],
        on_startup=[_startup], on_shutdown=[_shutdown],
    )
    return app
