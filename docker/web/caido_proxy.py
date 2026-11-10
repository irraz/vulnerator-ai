"""Proxy de la UI de Caido con auto-login de invitado (STDLIB + httpx + starlette).

Objetivo: que la pestaña "Pantallas" abra la interfaz REAL de Caido ya DENTRO como invitado,
sin la pantalla de login ni el onboarding. Caido autentica su SPA con la clave de localStorage
``CAIDO_AUTHENTICATION`` (un token de invitado); como el iframe carga Caido en otro origen, la
consola no puede sembrar ese localStorage (cross-origin). Este proxy sirve la UI de Caido desde
el PROPIO origen de vulnerator-web e INYECTA un ``<script>`` al principio del ``<head>`` que
siembra ese token ANTES de que arranque la SPA. Resultado: el iframe abre directo en el
historial HTTP con el tráfico del engagement.

Quien prefiera su cuenta Caido la configura al instalar (token de entorno); este proxy solo
cubre el caso por defecto ZERO-TOUCH de invitado.

- El token se obtiene por ``loginAsGuest`` (mismo mecanismo que kali-mcp, vía ``caido_client``)
  y se cachea hasta poco antes de expirar.
- Los assets de Caido son RELATIVOS, así que el proxy sirve en la RAÍZ de su puerto y las rutas
  resuelven solas. Se pide ``Accept-Encoding: identity`` a upstream para poder inyectar en el
  HTML sin pelearse con gzip.
- DATO NO CONFIABLE: el contenido de Caido se transporta verbatim (salvo la inyección del
  bootstrap en el HTML); no se interpreta.
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

# Cabeceras hop-by-hop + las que cambian al reescribir el cuerpo: no se reenvían.
_DROP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "content-encoding", "content-length", "host",
}



# Flags de onboarding que la UI de Caido marca al completar/desactivar el tutorial (capturado
# del propio updateViewerSettings de la UI). Ponerlos todos a true = ni carrusel ni checklist.
_ONBOARDING_DONE = {
    "createdProject": True, "docs": True, "installedPlugin": True, "intercept": True,
    "interceptedRequest": True, "labs": True, "launchedPreconfiguredBrowser": True,
    "plugins": True, "projects": True, "scopes": True, "sentRequestToReplay": True,
    "visitedSettings": True, "welcome": True,
}
# data COMPLETO por defecto (misma forma que escribe la UI) por si el invitado aún no tiene
# fila de settings: así la escritura crea una fila válida y completa, no parcial.
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
# Ajustes de INSTANCIA (globales). SetInstanceSettingsInput es @oneOf: un solo campo por llamada.
_INSTANCE_SET_M = (
    "mutation($input: SetInstanceSettingsInput!){ setInstanceSettings(input:$input)"
    "{ settings{ onboarding{ analytic } } } }"
)
_INSTANCE_Q = "query{ instanceSettings{ onboarding{ analytic } } }"


def _mark_instance_onboarded(caido_client, token: str, url: str) -> bool:
    """Marca el onboarding de INSTANCIA (pantalla 'Privacy-Safe Usage Analytics') como hecho.

    Es global (no por invitado). Pone ``onboarding.analytic=true`` (paso completado) y desactiva
    el envío de analíticas (``analytics.enabled=false``, privacidad por defecto). Idempotente.
    Devuelve True si queda confirmado.
    """
    try:
        caido_client.graphql(_INSTANCE_SET_M, {"input": {"onboarding": {"analytic": True}}},
                             url=url, token=token, timeout=10)
        caido_client.graphql(_INSTANCE_SET_M, {"input": {"analytics": {"enabled": False}}},
                             url=url, token=token, timeout=10)
        chk = caido_client.graphql(_INSTANCE_Q, url=url, token=token, timeout=10)
        return bool((((chk.get("data") or {}).get("instanceSettings") or {}).get("onboarding") or {}).get("analytic"))
    except Exception as exc:
        sys.stderr.write("[caido-proxy] instance onboarding falló: %s\n" % exc)
        return False


def _mark_onboarded(caido_client, token: str, url: str) -> bool:
    """Marca el onboarding como COMPLETO para el invitado recién creado (code-level).

    Lee los viewer settings del token, fija ``data.onboarding.*`` a true y los reescribe. Así
    la UI, autenticada con ese token, NO muestra el carrusel "Learn the Essentials" ni el
    checklist "Getting started" — entra directa al workspace. Best-effort: si algo falla, el
    token sigue sirviendo (solo se vería el onboarding).
    """
    try:
        cur = caido_client.graphql(_VIEWER_SETTINGS_Q, url=url, token=token, timeout=10)
        settings = {}
        if cur.get("status") == "ok":
            settings = ((cur.get("data") or {}).get("viewer") or {}).get("settings") or {}
        # Parte de la fila existente si la hay; si no, de un data completo por defecto.
        data = dict(settings["data"]) if isinstance(settings.get("data"), dict) else dict(_DEFAULT_DATA)
        ob = dict(data.get("onboarding") or {})
        ob.update(_ONBOARDING_DONE)
        data["onboarding"] = ob
        # updateViewerSettings exige data Y migrations (ambos JSON!). migrations puede no existir
        # aún en un invitado nuevo -> [] por defecto.
        migrations = settings.get("migrations")
        if migrations is None:
            migrations = []
        out = caido_client.graphql(_VIEWER_SETTINGS_M, {"input": {"data": data, "migrations": migrations}},
                                   url=url, token=token, timeout=10)
        if out.get("status") != "ok":
            sys.stderr.write("[caido-proxy] updateViewerSettings falló: %s\n" % (out.get("errors") or out.get("error")))
            return False
        # Verifica leyendo de nuevo: solo True si el onboarding quedó COMPLETO.
        chk = caido_client.graphql(_VIEWER_SETTINGS_Q, url=url, token=token, timeout=10)
        cob = ((((chk.get("data") or {}).get("viewer") or {}).get("settings") or {}).get("data") or {}).get("onboarding") or {}
        return bool(cob) and all(cob.values())
    except Exception as exc:  # best-effort
        sys.stderr.write("[caido-proxy] no se pudo marcar onboarding: %s\n" % exc)
        return False

class GuestToken:
    """Mantiene UN token de invitado y garantiza su onboarding completo (code-level).

    Separa el login (crear el invitado) del onboarding (dejarlo sin tutoriales): mintea UN
    invitado y, en cada ``get``, RE-APLICA el onboarding sobre ESE mismo invitado hasta que
    cuaja — sin crear invitados nuevos (evita el churn). Así, en un volumen de Caido recién
    creado, en cuanto su subsistema de settings está listo, el onboarding se fija y persiste.
    """

    def __init__(self, caido_url: str) -> None:
        self._url = caido_url
        self._json: Optional[str] = None
        self._access: Optional[str] = None
        self._renew_at = 0.0
        self._onboarded = False
        self._lock = threading.Lock()

    def _mint(self) -> None:
        """Crea el invitado y selecciona proyecto. NO hace onboarding (eso es aparte)."""
        import caido_client  # perezoso (vive en la imagen)
        out = caido_client.graphql(caido_client._GUEST_LOGIN, url=self._url, timeout=15)
        if out.get("status") != "ok":
            sys.stderr.write("[caido-proxy] loginAsGuest falló: %s\n" % out.get("error"))
            return
        tok = ((out.get("data") or {}).get("loginAsGuest") or {}).get("token") or {}
        access = tok.get("accessToken")
        if not access:
            return
        try:
            caido_client._ensure_project(access, self._url, 10)
        except Exception as exc:
            sys.stderr.write("[caido-proxy] no se pudo asegurar proyecto: %s\n" % exc)
        auth = {
            "__typename": "AuthenticationToken", "accessToken": access,
            "expiresAt": tok.get("expiresAt"), "refreshToken": None, "scopes": ["PROFILE_READ"],
        }
        self._access = access
        self._json = json.dumps(auth, separators=(",", ":"))
        self._onboarded = False
        # Renueva a mitad de vida (o 30 min si no se parsea expiresAt).
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
        """(Re)aplica el onboarding sobre el invitado compartido AHORA. Idempotente.

        Se llama en cada carga de la página HTML: como Caido usa UN invitado compartido y su SPA
        puede reescribir settings, re-aplicarlo justo antes de servir garantiza que el navegador
        SIEMPRE cargue con el onboarding completo (sin carrusel) por muchas veces que se abra.
        """
        import caido_client  # perezoso
        with self._lock:
            if self._json is None or self._access is None or time.time() >= self._renew_at:
                self._mint()
            if not self._access:
                return False
            viewer_ok = _mark_onboarded(caido_client, self._access, self._url)
            instance_ok = _mark_instance_onboarded(caido_client, self._access, self._url)
            self._onboarded = viewer_ok and instance_ok
            return self._onboarded


# Red de seguridad de CLIENTE contra el onboarding. El marcado por GraphQL (viewer+instancia)
# es la vía principal, pero la SPA puede pintar el modal "Learn the Essentials" (overlay
# bloqueante z-[99999] fixed inset-0) ANTES de que esos settings propaguen: una carrera que, en
# cuanto se ve una vez, obliga a recargar. Este guard lo liquida pase lo que pase: colapsa el
# checklist "Getting started" y, con un MutationObserver (+ barrido de respaldo), en cuanto
# aparece un overlay a pantalla completa cuyo texto es el del onboarding, pulsa "Continue" y lo
# quita del DOM. Identifica el overlay por su TEXTO, no por un z-index genérico, para no tocar
# diálogos legítimos de Caido. Idempotente y pasivo si no hay onboarding.
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
    """``<script>`` que siembra el token de invitado y neutraliza el onboarding (code-level),
    antes de que arranque la SPA de Caido."""
    # json.dumps del string -> literal JS seguro (comillas/escapes correctos).
    return ("<script>try{localStorage.setItem('CAIDO_AUTHENTICATION',"
            + json.dumps(token_json) + ");}catch(e){}</script>" + _ONBOARDING_GUARD)


def inject(html: str, token_json: str) -> str:
    """Inserta el bootstrap justo después de ``<head>`` (antes de los módulos diferidos)."""
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
    """App ASGI que proxya la UI de Caido en ``caido_base`` inyectando el token de invitado."""
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
            # Re-aplica el onboarding sobre el invitado compartido justo antes de servir la UI.
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
        # Calienta el token de invitado (login + proyecto + onboarding) en segundo plano, para
        # que el PRIMER navegador que abra ya reciba un token listo y no vea el onboarding por
        # una carrera de propagación.
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
        """Puentea un WebSocket del navegador <-> Caido (suscripciones GraphQL en vivo)."""
        import websockets
        subs = ws.scope.get("subprotocols") or []
        target = ws_base + ws.url.path
        try:
            up = await websockets.connect(target, subprotocols=subs or None, open_timeout=10,
                                          max_size=None)
        except Exception as exc:  # upstream no acepta: se cierra el del navegador
            sys.stderr.write("[caido-proxy] ws upstream falló (%s): %s\n" % (target, exc))
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
