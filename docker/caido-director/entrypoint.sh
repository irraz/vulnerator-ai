#!/bin/sh
# caido-director: Chromium con pantalla mostrando la UI de Caido + x11vnc + noVNC, conducido por
# director.py (re-escenifica las acciones de Caido del agente). Solo noVNC (:6080) sale al host.
set -eu
GEOM="${CAIDO_DIRECTOR_GEOMETRY:-1600x900x24}"
RES="${GEOM%x*}"
export DISPLAY=:99
cleanup() { kill 0 2>/dev/null || true; }
trap cleanup INT TERM

# Un reinicio del contenedor (sin recrearlo) conserva /tmp: el candado y el socket de la
# ejecución anterior harían que Xvfb se negara a arrancar ("Server is already active") y
# Chromium moriría sin pantalla. Aquí no hay otro X, así que se limpian siempre.
rm -f /tmp/.X99-lock /tmp/.X11-unix/X99
Xvfb :99 -screen 0 "$GEOM" -nolisten tcp >/tmp/xvfb.log 2>&1 &
XVFB_PID=$!
for i in $(seq 1 50); do [ -e /tmp/.X11-unix/X99 ] && break; sleep 0.1; done
if ! kill -0 "$XVFB_PID" 2>/dev/null || [ ! -e /tmp/.X11-unix/X99 ]; then
  echo "[$(basename "$(dirname "$0")")] Xvfb no arrancó:" >&2; cat /tmp/xvfb.log >&2; exit 1
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

# noVNC siempre en solo lectura: el público mira cómo se maneja Caido, no toca.
for i in $(seq 1 50); do [ -f /tmp/chromium.log ] && break; sleep 0.1; done
x11vnc -display :99 -forever -shared -rfbport 5900 -nopw -quiet -viewonly >/tmp/x11vnc.log 2>&1 &
websockify --web /usr/share/novnc 6080 localhost:5900 >/tmp/websockify.log 2>&1 &

exec python3 /opt/caido-director/director.py
