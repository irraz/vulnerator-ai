# browser-view — navegador VISIBLE (Chromium) para las demos de vulnerator-web.
#
# Xvfb (pantalla virtual) + Chromium con pantalla + x11vnc + noVNC. playwright-mcp lo conduce
# por CDP (vía cdp_proxy.py, que arregla la protección anti-rebinding de Chrome) y el operador
# lo ve por noVNC embebido en la consola. NO publica el puerto de depuración; al host solo va
# noVNC (lo hace docker-compose.yml).
#
# Build (desde la raíz del repo):
#   docker build -f docker/browser-view/Dockerfile -t vulnerator-ai-browser-view:dev docker/browser-view

# syntax=docker/dockerfile:1

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Navegador + pantalla virtual + VNC/noVNC + WM ligero + fuentes + tini (init). Versiones
# pineadas (disciplina del repo). Limpieza de listas de apt en la misma capa.
RUN apt-get update && apt-get install -y --no-install-recommends \
      chromium=156.0.8078.79-1~deb12u1 \
      xvfb=2:21.1.7-3+deb12u13 \
      x11vnc=0.9.16-9 \
      novnc=1:1.3.0-1 \
      websockify=0.10.0+dfsg1-4+b1 \
      openbox=3.6.1-10 \
      python3=3.11.2-1+b1 \
      fonts-dejavu-core=2.37-6 \
      ca-certificates=20250419~deb12u2 \
      tini=0.19.0-1+b3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/browser-view
COPY cdp_proxy.py browser_reset.py entrypoint.sh welcome.html ./
RUN chmod +x entrypoint.sh \
    && useradd --system --uid 10002 --create-home --home-dir /home/bview bview

USER 10002:10002
ENV HOME=/home/bview \
    BROWSER_VIEW_GEOMETRY=1920x1080x24 \
    BROWSER_VIEW_VIEWONLY=1

# noVNC (web). El puerto de depuración (9222 del proxy, 9223 de Chrome) NO se expone aquí: solo
# lo alcanza playwright-mcp por la red interna; a nadie más.
EXPOSE 6080

# Vivo = noVNC responde Y el proxy CDP da la versión del navegador.
HEALTHCHECK --interval=15s --timeout=5s --start-period=25s --retries=5 \
  CMD ["sh", "-c", "python3 -c \"import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:6080/', timeout=3); urllib.request.urlopen('http://127.0.0.1:9222/json/version', timeout=3)\" || exit 1"]

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/browser-view/entrypoint.sh"]
