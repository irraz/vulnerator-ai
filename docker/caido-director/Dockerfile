# caido-director — UI de Caido conducida automáticamente para reflejar las acciones del agente.
# Chromium con pantalla (Xvfb) + x11vnc + noVNC + Playwright (connect_over_cdp) que ejecuta
# director.py. Base debian bookworm. Solo noVNC (:6080) se publica; el puerto de depuración no.
# syntax=docker/dockerfile:1
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      chromium=156.0.8078.79-1~deb12u1 \
      xvfb=2:21.1.7-3+deb12u13 \
      x11vnc=0.9.16-9 \
      novnc=1:1.3.0-1 \
      websockify=0.10.0+dfsg1-4+b1 \
      openbox=3.6.1-10 \
      python3=3.11.2-1+b1 \
      python3-pip=23.0.1+dfsg-1 \
      fonts-dejavu-core=2.37-6 \
      ca-certificates=20250419~deb12u2 \
      tini=0.19.0-1+b3 \
    && pip install --no-cache-dir --break-system-packages playwright==1.49.1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/caido-director
COPY director.py entrypoint.sh ./
RUN chmod +x entrypoint.sh \
    && useradd --system --uid 10003 --create-home --home-dir /home/cdir cdir
USER 10003:10003
ENV HOME=/home/cdir CAIDO_DIRECTOR_GEOMETRY=1600x900x24

EXPOSE 6080
HEALTHCHECK --interval=15s --timeout=5s --start-period=25s --retries=5 \
  CMD ["sh","-c","python3 -c \"import urllib.request;urllib.request.urlopen('http://127.0.0.1:6080/',timeout=3)\" || exit 1"]
ENTRYPOINT ["/usr/bin/tini","--","/opt/caido-director/entrypoint.sh"]
