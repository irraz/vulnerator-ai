"""caido-director — re-enacts in the Caido UI the actions Hermes performs via the API.

Hermes drives Caido through its API (``caido_*`` tools), so its interface does not "move" on its
own. This controller listens to the vulnerator-web event stream (``/api/stream``) and, for each
Caido action the agent takes, REPLAYS that action on a real instance of the Caido UI (headed
Chromium, visible over noVNC): it opens the corresponding tab, types the HTTPQL filter, opens the
packet/session, etc. The DATA is real (the agent's); the "walkthrough" of the UI is choreographed
by this director — automatically, without human intervention.

Connection: Playwright ``connect_over_cdp`` to the local headed Chromium (127.0.0.1:9223), driving
the page that shows the Caido UI (served pre-authenticated by vulnerator-web).
"""

from __future__ import annotations

import base64
import json
import os
import queue
import re
import sys
import threading
import time
import urllib.request

from playwright.sync_api import sync_playwright

GUI = os.environ.get("GUI_BASE", "http://vulnerator-web:9100").rstrip("/")
CAIDO_UI = os.environ.get("CAIDO_UI_URL", "http://vulnerator-web:7001/")
USER = os.environ.get("VULNERATOR_WEB_USER", "admin")
PW = os.environ.get("VULNERATOR_WEB_PASSWORD", "vulnerator")
CDP = os.environ.get("CDP_URL", "http://127.0.0.1:9223")
STEP = float(os.environ.get("CAIDO_DIRECTOR_STEP", "1.4"))  # base pause between micro-actions

_events: "queue.Queue[dict]" = queue.Queue(maxsize=500)


def log(msg: str) -> None:
    sys.stderr.write("[caido-director] %s\n" % msg)
    sys.stderr.flush()


# Tool-call categories worth staging in Caido. The `caido_*` (web) ones have their own
# choreography; for the rest, if the action produced real HTTP traffic (captured in Caido by the
# proxy), the director shows it: it filters by its host/path and opens the packet. "finding" jumps
# to the Findings tab. Pure recon without a URL (dig/getent) and non-HTTP shell (nmap) are ignored.
_STAGE_CATEGORIES = {"web", "browser", "recon", "finding"}
_HTTP_CMD = re.compile(r"\b(curl|wget|http|ffuf|feroxbuster|gobuster|nuclei|sqlmap|wpscan|nikto|whatweb|httpx)\b", re.I)


def _is_stageable(ev: dict) -> bool:
    if ev.get("kind") != "tool.call":
        return False
    cat = ev.get("category")
    if cat in _STAGE_CATEGORIES:
        return True
    # shell: only if the command looks like an HTTP client (has traffic to show in Caido)
    if cat == "shell":
        args = ev.get("args") if isinstance(ev.get("args"), dict) else {}
        cmd = str(args.get("command") or args.get("code") or "")
        return bool(_HTTP_CMD.search(cmd) and ("http" in cmd.lower() or "://" in cmd))
    return False


def sse_loop() -> None:
    """Read vulnerator-web's SSE and enqueue the stageable tool-calls (see _is_stageable)."""
    auth = base64.b64encode(("%s:%s" % (USER, PW)).encode()).decode()
    after = None
    while True:
        try:
            if after is None:
                # start near "now" so the whole history is not replayed
                req = urllib.request.Request(GUI + "/api/status", headers={"Authorization": "Basic " + auth})
                after = int(json.load(urllib.request.urlopen(req, timeout=10)).get("max_seq", 0))
            url = "%s/api/stream?after=%d" % (GUI, after)
            req = urllib.request.Request(url, headers={"Authorization": "Basic " + auth})
            with urllib.request.urlopen(req, timeout=120) as r:
                for raw in r:
                    line = raw.decode("utf-8", "replace").rstrip("\n")
                    if line.startswith("id:"):
                        try:
                            after = int(line[3:].strip())
                        except ValueError:
                            pass
                    elif line.startswith("data:"):
                        try:
                            ev = json.loads(line[5:].strip())
                        except ValueError:
                            continue
                        if _is_stageable(ev):
                            try:
                                _events.put_nowait(ev)
                            except queue.Full:
                                pass
        except Exception as exc:
            log("sse reconnecting: %s" % exc)
            time.sleep(3)


def connect_page(p):
    for _ in range(40):
        try:
            br = p.chromium.connect_over_cdp(CDP)
            ctx = br.contexts[0] if br.contexts else br.new_context()
            pg = ctx.pages[0] if ctx.pages else ctx.new_page()
            return br, pg
        except Exception:
            time.sleep(1.5)
    raise RuntimeError("could not connect to Chromium (CDP)")


def wait_authed(pg) -> None:
    pg.goto(CAIDO_UI, wait_until="domcontentloaded")
    for _ in range(40):
        if "/#/" in pg.url or "caido" in (pg.title() or "").lower():
            time.sleep(2)
            return
        time.sleep(1)


def nav(pg, route: str) -> None:
    pg.evaluate("location.hash='#/%s'" % route)
    time.sleep(STEP)


def type_httpql(pg, text: str) -> None:
    box = pg.query_selector(".cm-content")
    if not box:
        return
    box.click()
    pg.keyboard.press("Control+A")
    pg.keyboard.press("Delete")
    pg.keyboard.type(text, delay=45)
    time.sleep(STEP / 2)
    pg.keyboard.press("Enter")
    time.sleep(STEP)


_URL_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)(?::\d+)?(/[^\s\"'`|>)]*)?")


def extract_target(args: dict, summary: str):
    """(host, path) of the HTTP request derived from the args (or the summary). Real data from the
    agent itself: the URL it navigated to/attacked. If there is nothing HTTP, (None, None)."""
    # 1) explicit URL in typical fields or in the command/summary
    for key in ("url", "command", "code", "goal", "target", "summary"):
        v = args.get(key) if key != "summary" else summary
        if isinstance(v, str):
            m = _URL_RE.search(v)
            if m:
                path = (m.group(2) or "").split("?")[0]
                return m.group(1).lower(), (path if path and path != "/" else "")
    m = _URL_RE.search(summary or "")
    if m:
        path = (m.group(2) or "").split("?")[0]
        return m.group(1).lower(), (path if path and path != "/" else "")
    # 2) "bare" host in target/targets/domain/host
    for key in ("target", "targets", "domain", "host"):
        v = args.get(key)
        for cand in (v if isinstance(v, list) else [v] if v else []):
            s = str(cand).strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            if re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", s) or re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", s):
                return s, ""
    return None, None


def httpql_for(host: str, path: str) -> str:
    """HTTPQL filter by host (and path if present). Host trimmed to the registrable domain so it
    matches www., subdomains, etc."""
    core = host
    parts = host.split(".")
    if len(parts) >= 2 and not re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
        core = ".".join(parts[-2:])
    q = 'req.host.cont:"%s"' % core
    if path:
        q += ' and req.path.cont:"%s"' % path[:40]
    return q


# Real data row of Caido's tables (History, Automate...). CAUTION: a generic substring selector
# like "[class*=row]" yields a false positive on the HEADER cells, whose Tailwind utility classes
# include variants such as "flex-row" (they contain the substring "row") - it ends up clicking
# "ID"/"Host"/"Method" instead of the first real request. `.c-item-row` is the stable class Caido
# puts only on data rows ("c-" prefix consistent across its UI).
_ROW_SEL = ".c-item-row"


def open_first_row(pg, settle_s: float = 2.5) -> bool:
    """Wait for the table to settle after the filter (the GraphQL query is async) and open the
    first real data row. True if there was something to open."""
    rows = pg.locator(_ROW_SEL)
    deadline = time.time() + settle_s
    last = -1
    while time.time() < deadline:
        n = rows.count()
        if n and n == last:  # two consecutive equal readings: no longer re-rendering
            break
        last = n
        time.sleep(0.25)
    if rows.count():
        rows.nth(0).click()
        time.sleep(STEP)
        return True
    return False


def open_last_session(pg) -> None:
    rows = pg.locator("div.group.cursor-pointer")
    n = rows.count()
    if n:
        rows.nth(n - 1).click()
        time.sleep(STEP)


def show_in_history(pg, args: dict, summary: str) -> bool:
    """HTTP History: filter by the host/path of the real request and open the packet. True if it acted."""
    host, path = extract_target(args, summary)
    if not host:
        return False
    nav(pg, "http-history")
    type_httpql(pg, httpql_for(host, path))
    open_first_row(pg)
    return True


def choreograph(pg, ev: dict) -> None:
    tool = (ev.get("tool_display") or ev.get("tool") or "").lower()
    cat = ev.get("category")
    args = ev.get("args") if isinstance(ev.get("args"), dict) else {}
    summary = ev.get("summary") or ""
    blob = json.dumps(args).lower()
    try:
        if "caido_history" in tool:
            nav(pg, "http-history")
            httpql = args.get("httpql")
            if isinstance(httpql, str) and httpql.strip():
                type_httpql(pg, httpql.strip())
            else:
                host, path = extract_target(args, summary)
                if host:
                    type_httpql(pg, httpql_for(host, path))
            open_first_row(pg)
        elif "caido_request" in tool:
            nav(pg, "replay")
            open_last_session(pg)
        elif "caido_automate" in tool:
            nav(pg, "automate")
            open_last_session(pg)
        elif "caido_intercept" in tool:
            nav(pg, "intercept")
        elif "caido_graphql" in tool:
            if "scope" in blob:
                nav(pg, "scope")
            elif "request(" in blob or "history" in blob:
                show_in_history(pg, args, summary)
        elif cat == "finding":
            # a finding: show it in Caido's Findings tab
            nav(pg, "findings")
        else:
            # browser / recon / curl & co.: real captured traffic -> filter it and open it
            if not show_in_history(pg, args, summary):
                return
        log("staged: %s" % (tool or cat))
    except Exception as exc:
        log("choreograph error (%s): %s" % (tool, exc))


def main() -> None:
    threading.Thread(target=sse_loop, daemon=True).start()
    with sync_playwright() as p:
        br, pg = connect_page(p)
        wait_authed(pg)
        log("connected and in the Caido UI; waiting for agent actions…")
        while True:
            try:
                ev = _events.get(timeout=30)
            except queue.Empty:
                continue
            choreograph(pg, ev)
            # drain bursts: if many are queued, process the last of each type calmly
            time.sleep(STEP / 2)


if __name__ == "__main__":
    main()
