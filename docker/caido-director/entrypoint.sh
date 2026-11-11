#!/bin/sh
# caido-director: headed Chromium showing the Caido UI + x11vnc + noVNC, driven by director.py
# (re-enacts the agent's Caido actions). Only noVNC (:6080) goes out to the host.
set -eu
GEOM="${CAIDO_DIRECTOR_GEOMETRY:-1600x900x24}"
RES="${GEOM%x*}"
export DISPLAY=:99
cleanup() { kill 0 2>/dev/null || true; }
trap cleanup INT TERM

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

chromium \
  --no-sandbox --no-first-run --no-default-browser-check --disable-dev-shm-usage \
  --disable-infobars --disable-session-crashed-bubble --hide-crash-restore-bubble \
  --disable-background-networking --disable-component-update --disable-sync --no-pings \
  --disable-features=Translate,OptimizationHints,MediaRouter,CalculateNativeWinOcclusion \
  --remote-debugging-address=127.0.0.1 --remote-debugging-port=9223 --remote-allow-origins=* \
  --user-data-dir=/tmp/chrome-profile --window-position=0,0 --window-size="${RES%x*},${RES#*x}" \
  --start-maximized "about:blank" >/tmp/chromium.log 2>&1 &

# noVNC always read-only: the audience watches how Caido is operated, does not touch.
for i in $(seq 1 50); do [ -f /tmp/chromium.log ] && break; sleep 0.1; done
x11vnc -display :99 -forever -shared -rfbport 5900 -nopw -quiet -viewonly >/tmp/x11vnc.log 2>&1 &
websockify --web /usr/share/novnc 6080 localhost:5900 >/tmp/websockify.log 2>&1 &

exec python3 /opt/caido-director/director.py
