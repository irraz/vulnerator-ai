#!/bin/sh
# browser-view — navegador VISIBLE para la demo: Xvfb + Chromium con depuración remota +
# x11vnc + noVNC. playwright-mcp lo conduce por CDP (a través de cdp_proxy.py, que arregla el
# Host) y el operador lo ve por noVNC embebido en vulnerator-web.
#
# Seguridad: Chrome escucha su puerto de depuración SOLO en loopback; a la red docker solo se
# expone el proxy (:9222) y a nadie más. Al host solo va noVNC (:6080), publicado por compose.
set -eu

GEOM="${BROWSER_VIEW_GEOMETRY:-1920x1080x24}"
RES="${GEOM%x*}"                      # p. ej. 1920x1080
export DISPLAY=:99

cleanup() { kill 0 2>/dev/null || true; }
trap cleanup INT TERM

# 1) Pantalla virtual + gestor de ventanas ligero (para que Chrome salga maximizado y limpio).
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

# Proxy OPT-IN: si BROWSER_VIEW_PROXY está puesto (p. ej. http://caido:8080), el navegador
# enruta su tráfico por ahí, de modo que se vea en vivo en Caido. Se excluye loopback para no
# afectar al CDP ni a la página de bienvenida (file://). HTTPS por proxy necesita la CA del
# proxy instalada (para objetivos HTTP de laboratorio no hace falta).
PROXY_ARGS=""
if [ -n "${BROWSER_VIEW_PROXY:-}" ]; then
  PROXY_ARGS="--proxy-server=${BROWSER_VIEW_PROXY} --proxy-bypass-list=localhost;127.0.0.1;update.googleapis.com;*.gvt1.com;clients2.google.com;*.gstatic.com;optimizationguide-pa.googleapis.com;accounts.google.com;content-autofill.googleapis.com"
  echo "[browser-view] proxy del navegador -> ${BROWSER_VIEW_PROXY}" >&2
fi

# 2) Chromium CON pantalla y depuración remota SOLO en loopback (el proxy la reexpone).
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

# 3) Proxy CDP (arregla el Host header para la red docker).
python3 /opt/browser-view/cdp_proxy.py >/tmp/cdp_proxy.log 2>&1 &

# 4) x11vnc sobre la pantalla virtual. -viewonly si BROWSER_VIEW_VIEWONLY!=0 (demo: el público
#    mira, no toca). -nopw porque la barrera es el puerto host + noVNC en máquina controlada.
VIEWONLY=""
[ "${BROWSER_VIEW_VIEWONLY:-1}" != "0" ] && VIEWONLY="-viewonly"
# espera a que Chrome pinte algo antes de exponer VNC
for i in $(seq 1 50); do [ -f /tmp/chromium.log ] && break; sleep 0.1; done
x11vnc -display :99 -forever -shared -rfbport 5900 -nopw -quiet $VIEWONLY >/tmp/x11vnc.log 2>&1 &

# 5) noVNC (web) sobre websockify -> 6080. Auto-conecta y escala.
websockify --web /usr/share/novnc 6080 localhost:5900 >/tmp/websockify.log 2>&1 &

# 6) Vigilante de objetivo: si vulnerator-web informa de un engagement NUEVO (otra sesión raíz),
# devuelve el navegador a la bienvenida. Sin esto se queda mostrando el sitio del engagement
# anterior hasta que el nuevo llame a una tool de navegador. Best-effort: su fallo no afecta al
# resto (ni GUI_BASE ni las credenciales son obligatorias para que el navegador funcione).
python3 /opt/browser-view/browser_reset.py >/tmp/browser_reset.log 2>&1 &

wait
