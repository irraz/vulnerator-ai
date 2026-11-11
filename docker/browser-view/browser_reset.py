"""browser_reset.py — resets the VISIBLE browser when the TARGET changes.

Problem it fixes (at the code level, not a host-fix): the headed browser in `browser-view` only
moves when Hermes calls a `browser_*` tool. When one engagement ends and another starts (another
``/v1/runs``), the agent usually begins with recon via ``kali_run`` before touching the browser —
so the screen stays showing the SITE OF THE PREVIOUS ENGAGEMENT (e.g. yesterday's target WordPress
login) while the new one is already underway against a different target. It looks "stuck"; in
reality nobody is resetting it.

This watcher polls the ``vulnerator-web`` sessions (same API the console consumes) and, as soon as
the most active ROOT session changes (a new ``/v1/runs`` = a new engagement; delegating to a
SUBAGENT of the SAME session does not count as "changing target"), it navigates all of Chrome's
page tabs back to the neutral welcome screen. If Hermes has already started navigating in the new
engagement by the time this runs, its own ``browser_navigate`` call wins anyway (this reset only
exists to avoid leaving another engagement's target visible).

Pure STDLIB (no dependencies, like ``cdp_proxy.py``): HTTP with ``urllib`` and a minimal hand-written
WebSocket client, directly to the local Chrome (``127.0.0.1:9223``, no need to go through the Host
proxy — it is the same container). Best-effort throughout: a failure here must never bring down the
process or affect normal browser usage.
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


# --------------------------------------------------------------------------- pure logic (tests)
def pick_live_root(sessions: list[dict]) -> str | None:
    """The id of the ROOT session (empty ``parent_session_id``) with the most recent activity, or
    ``None`` if there is none. Child sessions (delegated subagents) do not count: delegating within
    the SAME engagement is not "changing target"."""
    roots = [s for s in sessions if not s.get("parent_session_id") and s.get("id")]
    if not roots:
        return None
    return max(roots, key=lambda s: s.get("last_active") or s.get("started_at") or 0)["id"]


def should_reset(prev: str | None, cur: str | None, seen_any: bool) -> bool:
    """True if a reset is due: there is a current root session, we had ALREADY seen one before (so
    this is not the watcher's first startup), and it differs from the last one seen."""
    return bool(cur) and seen_any and cur != prev


def _ws_frame(payload: bytes) -> bytes:
    """Masked text WebSocket frame (RFC 6455: client->server requires a mask)."""
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


# --------------------------------------------------------------------------- network (best-effort)
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
    """Direct WS to the PAGE target (not the browser one) and ``Page.navigate``. Returns True if
    Chrome confirmed; any failure is logged and not propagated (best-effort)."""
    host = "%s:%d" % (CHROME_HOST, CHROME_PORT)
    path = "/devtools/page/%s" % page_id
    try:
        r, w = await asyncio.open_connection(CHROME_HOST, CHROME_PORT)
    except OSError as exc:
        log("could not connect to Chrome for %s: %s" % (page_id, exc))
        return False
    try:
        w.write(_ws_handshake(path, host))
        await w.drain()
        head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=5)
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            log("Chrome did not confirm the WS upgrade for %s" % page_id)
            return False
        msg = json.dumps({"id": 1, "method": "Page.navigate", "params": {"url": url}}).encode()
        w.write(_ws_frame(msg))
        await w.drain()
        await asyncio.wait_for(r.read(4096), timeout=6)
        return True
    except Exception as exc:  # best-effort: never brings down the watcher
        log("failed navigating %s: %s" % (page_id, exc))
        return False
    finally:
        try:
            w.close()
        except Exception:
            pass


async def reset_browser() -> int:
    """Navigate all PAGE tabs (not the internal ``browser_ui`` ones) to the welcome screen.
    Returns how many were reset."""
    try:
        tabs = await asyncio.to_thread(_get_chrome_json, "/json")
    except Exception as exc:
        log("could not list tabs: %s" % exc)
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
    log("watching for target changes on %s (polling every %.0fs)" % (GUI_BASE, POLL_S))
    while True:
        try:
            sessions = await asyncio.to_thread(_fetch_sessions)
            cur = pick_live_root(sessions)
            if should_reset(last, cur, seen_any):
                log("new target (session %s, before %s): resetting the browser…" % (cur, last))
                n = await reset_browser()
                log("reset done: %d tab(s)" % n)
            if cur is not None:
                seen_any = True
            last = cur
        except urllib.error.URLError as exc:
            log("vulnerator-web not responding yet: %s" % exc)
        except Exception as exc:  # the watcher must not die from a one-off failure
            log("poll failed: %s" % exc)
        await asyncio.sleep(POLL_S)


if __name__ == "__main__":
    asyncio.run(watch())
