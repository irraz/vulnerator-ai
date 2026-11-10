"""browser_reset.py — reinicia el navegador VISIBLE cuando cambia el OBJETIVO.

Problema que arregla (a nivel de código, no un host-fix): el navegador con pantalla de
`browser-view` solo se mueve cuando Hermes llama a una tool `browser_*`. Al terminar un
engagement y arrancar otro (otro ``/v1/runs``), el agente suele empezar con recon por
``kali_run`` antes de tocar el navegador — así que la pantalla se queda mostrando el SITIO DEL
ENGAGEMENT ANTERIOR (p. ej. el login de WordPress del objetivo de ayer) mientras el nuevo ya está
en marcha contra un objetivo distinto. Parece "colgado"; en realidad es que nadie lo resetea.

Este watcher sondea las sesiones de ``vulnerator-web`` (misma API que consume la consola) y, en
cuanto la sesión RAÍZ más activa cambia (un ``/v1/runs`` nuevo = un engagement nuevo; delegar en
un SUBAGENTE de la MISMA sesión no cuenta como "cambiar de objetivo"), navega todas las pestañas
de página de Chrome de vuelta a la pantalla de bienvenida neutra. Si Hermes ya ha empezado a
navegar en el nuevo engagement para cuando esto corre, su propia llamada ``browser_navigate``
manda igualmente (este reset es solo para no dejar visible el objetivo de otro engagement).

STDLIB pura (sin dependencias, como ``cdp_proxy.py``): HTTP con ``urllib`` y un cliente WebSocket
mínimo escrito a mano, directo al Chrome local (``127.0.0.1:9223``, no hace falta pasar por el
proxy de Host — es el mismo contenedor). Best-effort en todo: un fallo aquí nunca debe tumbar el
proceso ni afectar al uso normal del navegador.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import urllib.error
import urllib.request

GUI_BASE = os.environ.get("GUI_BASE", "http://vulnerator-web:9100").rstrip("/")
VULNERATOR_WEB_USER = os.environ.get("VULNERATOR_WEB_USER", "admin")
VULNERATOR_WEB_PASSWORD = os.environ.get("VULNERATOR_WEB_PASSWORD", "")
CHROME_HOST = "127.0.0.1"
CHROME_PORT = 9223
WELCOME_URL = os.environ.get("BROWSER_VIEW_WELCOME_URL", "file:///opt/browser-view/welcome.html")
POLL_S = float(os.environ.get("BROWSER_VIEW_RESET_POLL_S", "3") or 3)


def log(msg: str) -> None:
    sys.stderr.write("[browser-reset] %s\n" % msg)
    sys.stderr.flush()


# --------------------------------------------------------------------------- lógica pura (tests)
def pick_live_root(sessions: list[dict]) -> str | None:
    """El id de la sesión RAÍZ (``parent_session_id`` vacío) con la actividad más reciente, o
    ``None`` si no hay ninguna. Las sesiones hijas (subagentes delegados) no cuentan: delegar
    dentro del MISMO engagement no es "cambiar de objetivo"."""
    roots = [s for s in sessions if not s.get("parent_session_id") and s.get("id")]
    if not roots:
        return None
    return max(roots, key=lambda s: s.get("last_active") or s.get("started_at") or 0)["id"]


def should_reset(prev: str | None, cur: str | None, seen_any: bool) -> bool:
    """True si toca resetear: hay una sesión raíz actual, YA habíamos visto alguna antes (así que
    esto no es el primer arranque del watcher), y es distinta de la última vista."""
    return bool(cur) and seen_any and cur != prev


def _ws_frame(payload: bytes) -> bytes:
    """Frame WebSocket de texto enmascarado (RFC 6455: cliente->servidor exige máscara)."""
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    n = len(payload)
    if n < 126:
        head = bytes([0x81, 0x80 | n])
    elif n < 65536:
        head = bytes([0x81, 0x80 | 126]) + n.to_bytes(2, "big")
    else:
        head = bytes([0x81, 0x80 | 127]) + n.to_bytes(8, "big")
    return head + mask + masked


def _ws_handshake(path: str, host: str) -> bytes:
    key = base64.b64encode(os.urandom(16)).decode()
    return (
        "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n" % (path, host, key)
    ).encode()


# --------------------------------------------------------------------------- red (best-effort)
def _get_chrome_json(path: str) -> list | dict:
    host = "%s:%d" % (CHROME_HOST, CHROME_PORT)
    req = urllib.request.Request("http://%s%s" % (host, path), headers={"Host": host})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.loads(r.read())


def _fetch_sessions() -> list[dict]:
    auth = base64.b64encode(
        ("%s:%s" % (VULNERATOR_WEB_USER, VULNERATOR_WEB_PASSWORD)).encode()
    ).decode()
    req = urllib.request.Request(
        GUI_BASE + "/api/sessions", headers={"Authorization": "Basic " + auth}
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        doc = json.loads(r.read())
    return doc.get("data") or []


async def _navigate_page(page_id: str, url: str) -> bool:
    """WS directo al target de PÁGINA (no al de navegador) y ``Page.navigate``. Devuelve True si
    Chrome confirmó; cualquier fallo se registra y no propaga (best-effort)."""
    host = "%s:%d" % (CHROME_HOST, CHROME_PORT)
    path = "/devtools/page/%s" % page_id
    try:
        r, w = await asyncio.open_connection(CHROME_HOST, CHROME_PORT)
    except OSError as exc:
        log("no se pudo conectar a Chrome para %s: %s" % (page_id, exc))
        return False
    try:
        w.write(_ws_handshake(path, host))
        await w.drain()
        head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=5)
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            log("Chrome no confirmó el upgrade WS para %s" % page_id)
            return False
        msg = json.dumps({"id": 1, "method": "Page.navigate", "params": {"url": url}}).encode()
        w.write(_ws_frame(msg))
        await w.drain()
        await asyncio.wait_for(r.read(4096), timeout=6)
        return True
    except Exception as exc:  # best-effort: nunca tumba el watcher
        log("fallo navegando %s: %s" % (page_id, exc))
        return False
    finally:
        try:
            w.close()
        except Exception:
            pass


async def reset_browser() -> int:
    """Navega todas las pestañas de PÁGINA (no las internas ``browser_ui``) a la pantalla de
    bienvenida. Devuelve cuántas se resetearon."""
    try:
        tabs = await asyncio.to_thread(_get_chrome_json, "/json")
    except Exception as exc:
        log("no se pudo listar pestañas: %s" % exc)
        return 0
    n = 0
    for t in tabs:
        if isinstance(t, dict) and t.get("type") == "page":
            if await _navigate_page(t["id"], WELCOME_URL):
                n += 1
    return n


async def watch() -> None:
    last: str | None = None
    seen_any = False
    log("vigilando cambios de objetivo en %s (sondeo cada %.0fs)" % (GUI_BASE, POLL_S))
    while True:
        try:
            sessions = await asyncio.to_thread(_fetch_sessions)
            cur = pick_live_root(sessions)
            if should_reset(last, cur, seen_any):
                log("objetivo nuevo (sesión %s, antes %s): reiniciando el navegador…" % (cur, last))
                n = await reset_browser()
                log("reset hecho: %d pestaña(s)" % n)
            if cur is not None:
                seen_any = True
            last = cur
        except urllib.error.URLError as exc:
            log("vulnerator-web aún no responde: %s" % exc)
        except Exception as exc:  # el watcher no debe morir por un fallo puntual
            log("sondeo falló: %s" % exc)
        await asyncio.sleep(POLL_S)


if __name__ == "__main__":
    asyncio.run(watch())
