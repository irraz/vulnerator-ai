#!/bin/sh
# browser-view — VISIBLE browser for the demo: Xvfb + Chromium with remote debugging +
# x11vnc + noVNC. playwright-mcp drives it over CDP (through cdp_proxy.py, which fixes the
# Host) and the operator sees it through noVNC embedded in vulnerator-web.
#
# Security: Chrome listens on its debugging port ONLY on loopback; only the proxy (:9222) is
# exposed to the docker network and nobody else. Only noVNC (:6080) goes to the host, published by compose.
set -eu

GEOM="${BROWSER_VIEW_GEOMETRY:-1920x1080x24}"
RES="${GEOM%x*}"                      # e.g. 1920x1080
export DISPLAY=:99

cleanup() { kill 0 2>/dev/null || true; }
trap cleanup INT TERM

# 1) Virtual display + lightweight window manager (so Chrome comes up maximized and clean).
# A container restart (without recreating it) preserves /tmp: the lock and socket from the
# previous run would make Xvfb refuse to start ("Server is already active") and Chromium would
# die without a display. There is no other X here, so they are always cleaned up.
rm -f /tmp/.X99-lock /tmp/.X11-unix/X99
Xvfb :99 -screen 0 "$GEOM" -nolisten tcp >/tmp/xvfb.log 2>&1 &
XVFB_PID=$!
for i in $(seq 1 50); do [ -e /tmp/.X11-unix/X99 ] && break; sleep 0.1; done
if ! kill -0 "$XVFB_PID" 2>/dev/null || [ ! -e /tmp/.X11-unix/X99 ]; then
  echo "[$(basename "$(dirname "$0")")] Xvfb did not start:" >&2; cat /tmp/xvfb.log >&2; exit 1
fi
openbox >/tmp/openbox.log 2>&1 &

# OPT-IN proxy: if BROWSER_VIEW_PROXY is set (e.g. http://caido:8080), the browser routes its
# traffic through it, so it can be seen live in Caido. Loopback is excluded so it does not affect
# the CDP nor the welcome page (file://). HTTPS through the proxy needs the proxy's CA installed
# (for HTTP lab targets it is not needed).
PROXY_ARGS=""
if [ -n "${BROWSER_VIEW_PROXY:-}" ]; then
  PROXY_ARGS="--proxy-server=${BROWSER_VIEW_PROXY} --proxy-bypass-list=localhost;127.0.0.1;update.googleapis.com;*.gvt1.com;clients2.google.com;*.gstatic.com;optimizationguide-pa.googleapis.com;accounts.google.com;content-autofill.googleapis.com"
  echo "[browser-view] browser proxy -> ${BROWSER_VIEW_PROXY}" >&2
fi

# 2) Chromium HEADED with remote debugging ONLY on loopback (the proxy re-exposes it).
chromium \
  --no-sandbox --no-first-run --no-default-browser-check --disable-dev-shm-usage \
  --disable-infobars --disable-session-crashed-bubble --hide-crash-restore-bubble \
  --disable-background-networking --disable-component-update --disable-sync --no-pings \
  --disable-domain-reliability --disable-client-side-phishing-detection --metrics-recording-only \
  --disable-features=Translate,OptimizationHints,MediaRouter,CalculateNativeWinOcclusion \
  --remote-debugging-address=127.0.0.1 --remote-debugging-port=9223 \
  --remote-allow-origins=* --ignore-certificate-errors $PROXY_ARGS \
  --user-data-dir=/tmp/chrome-profile --window-position=0,0 --window-size="${RES%x*},${RES#*x}" \
  --start-maximized "file:///opt/browser-view/welcome.html" >/tmp/chromium.log 2>&1 &

# 3) CDP proxy (fixes the Host header for the docker network).
python3 /opt/browser-view/cdp_proxy.py >/tmp/cdp_proxy.log 2>&1 &

# 4) x11vnc over the virtual display. -viewonly if BROWSER_VIEW_VIEWONLY!=0 (demo: the audience
#    watches, does not touch). -nopw because the barrier is the host port + noVNC on a controlled machine.
VIEWONLY=""
[ "${BROWSER_VIEW_VIEWONLY:-1}" != "0" ] && VIEWONLY="-viewonly"
# wait for Chrome to paint something before exposing VNC
for i in $(seq 1 50); do [ -f /tmp/chromium.log ] && break; sleep 0.1; done
x11vnc -display :99 -forever -shared -rfbport 5900 -nopw -quiet $VIEWONLY >/tmp/x11vnc.log 2>&1 &

# 5) noVNC (web) over websockify -> 6080. Auto-connects and scales.
websockify --web /usr/share/novnc 6080 localhost:5900 >/tmp/websockify.log 2>&1 &

# 6) Target watcher: if vulnerator-web reports a NEW engagement (another root session), it returns
# the browser to the welcome page. Without this it keeps showing the previous engagement's site
# until the new one calls a browser tool. Best-effort: its failure does not affect the rest
# (neither GUI_BASE nor the credentials are mandatory for the browser to work).
python3 /opt/browser-view/browser_reset.py >/tmp/browser_reset.log 2>&1 &

wait
