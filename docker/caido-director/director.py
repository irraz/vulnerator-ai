"""caido-director — re-escenifica en la UI de Caido las acciones que Hermes hace por API.

Hermes conduce Caido por su API (tools ``caido_*``), así que su interfaz no "se mueve" sola.
Este controlador escucha el stream de eventos de vulnerator-web (``/api/stream``) y, por cada
acción de Caido del agente, REPRODUCE esa acción en una instancia real de la UI de Caido
(Chromium con pantalla, visible por noVNC): abre la pestaña correspondiente, teclea el filtro
HTTPQL, abre el paquete/sesión, etc. Los DATOS son reales (los del agente); el "paseo" por la
UI lo coreografía este director — automático, sin intervención humana.

Conexión: Playwright ``connect_over_cdp`` al Chromium headed local (127.0.0.1:9223) y conduce
la página que muestra la UI de Caido (servida pre-autenticada por vulnerator-web).
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
STEP = float(os.environ.get("CAIDO_DIRECTOR_STEP", "1.4"))  # pausa base entre micro-acciones

_events: "queue.Queue[dict]" = queue.Queue(maxsize=500)


def log(msg: str) -> None:
    sys.stderr.write("[caido-director] %s\n" % msg)
    sys.stderr.flush()


# Categorías de tool-call que merece la pena escenificar en Caido. Las `caido_*` (web) tienen
# coreografía propia; para el resto, si la acción produjo tráfico HTTP real (lo hay capturado en
# Caido por el proxy), el director lo enseña: filtra por su host/ruta y abre el paquete. "finding"
# salta a la pestaña Findings. Se ignoran recon puro sin URL (dig/getent) y shell no-HTTP (nmap).
_STAGE_CATEGORIES = {"web", "browser", "recon", "finding"}
_HTTP_CMD = re.compile(r"\b(curl|wget|http|ffuf|feroxbuster|gobuster|nuclei|sqlmap|wpscan|nikto|whatweb|httpx)\b", re.I)


def _is_stageable(ev: dict) -> bool:
    if ev.get("kind") != "tool.call":
        return False
    cat = ev.get("category")
    if cat in _STAGE_CATEGORIES:
        return True
    # shell: solo si el comando parece un cliente HTTP (tiene tráfico que mostrar en Caido)
    if cat == "shell":
        args = ev.get("args") if isinstance(ev.get("args"), dict) else {}
        cmd = str(args.get("command") or args.get("code") or "")
        return bool(_HTTP_CMD.search(cmd) and ("http" in cmd.lower() or "://" in cmd))
    return False


def sse_loop() -> None:
    """Lee el SSE de vulnerator-web y encola las tool-calls escenificables (ver _is_stageable)."""
    auth = base64.b64encode(("%s:%s" % (USER, PW)).encode()).decode()
    after = None
    while True:
        try:
            if after is None:
                # arranca cerca de "ahora" para no reproducir todo el histórico
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
            log("sse reconectando: %s" % exc)
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
    raise RuntimeError("no se pudo conectar al Chromium (CDP)")


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
    """(host, path) de la petición HTTP a partir de los args (o del resumen). Datos reales del
    propio agente: la URL que navegó/atacó. Si no hay nada HTTP, (None, None)."""
    # 1) URL explícita en campos típicos o en el comando/resumen
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
    # 2) host "pelado" en target/targets/domain/host
    for key in ("target", "targets", "domain", "host"):
        v = args.get(key)
        for cand in (v if isinstance(v, list) else [v] if v else []):
            s = str(cand).strip().lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
            if re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", s) or re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", s):
                return s, ""
    return None, None


def httpql_for(host: str, path: str) -> str:
    """Filtro HTTPQL por host (y ruta si la hay). Host recortado al dominio registrable para que
    case con www., subdominios, etc."""
    core = host
    parts = host.split(".")
    if len(parts) >= 2 and not re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host):
        core = ".".join(parts[-2:])
    q = 'req.host.cont:"%s"' % core
    if path:
        q += ' and req.path.cont:"%s"' % path[:40]
    return q


# Fila de datos real de las tablas de Caido (History, Automate...). OJO: un selector genérico
# por substring tipo "[class*=row]" hace falso positivo con las celdas de CABECERA, cuyas clases
# utilitarias de Tailwind incluyen variantes como "flex-row" (contienen la subcadena "row") -
# acaba clicando "ID"/"Host"/"Method" en vez de la primera petición real. `.c-item-row` es la
# clase estable que Caido pone solo en las filas de datos (prefijo "c-" consistente en su UI).
_ROW_SEL = ".c-item-row"


def open_first_row(pg, settle_s: float = 2.5) -> bool:
    """Espera a que la tabla se asiente tras el filtro (la query GraphQL es async) y abre la
    primera fila de datos real. True si había algo que abrir."""
    rows = pg.locator(_ROW_SEL)
    deadline = time.time() + settle_s
    last = -1
    while time.time() < deadline:
        n = rows.count()
        if n and n == last:  # dos lecturas seguidas iguales: ya no está re-renderizando
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
    """HTTP History: filtra por el host/ruta de la petición real y abre el paquete. True si actuó."""
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
            # un hallazgo: enséñalo en la pestaña Findings de Caido
            nav(pg, "findings")
        else:
            # navegador / recon / curl & co.: tráfico real capturado -> fíltralo y ábrelo
            if not show_in_history(pg, args, summary):
                return
        log("escenificado: %s" % (tool or cat))
    except Exception as exc:
        log("choreograph error (%s): %s" % (tool, exc))


def main() -> None:
    threading.Thread(target=sse_loop, daemon=True).start()
    with sync_playwright() as p:
        br, pg = connect_page(p)
        wait_authed(pg)
        log("conectado y en la UI de Caido; esperando acciones del agente…")
        while True:
            try:
                ev = _events.get(timeout=30)
            except queue.Empty:
                continue
            choreograph(pg, ev)
            # vacía ráfagas: si hay muchos encolados, procesa el último de cada tipo con calma
            time.sleep(STEP / 2)


if __name__ == "__main__":
    main()
