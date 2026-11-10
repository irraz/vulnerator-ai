# vulnerator-web — la GUI web de Vulnerator-AI (consola de operador del bucle OODA).
#
# OBSERVADOR: lee la API de sesiones de Hermes (:8642) y el historial de Caido, y sirve en
# :9100 la terminal en vivo, el panel Copilot, las trazas de tool-calls (store SQLite propio),
# los PoC con su reproducción grabada, y los accesos al Dashboard/Webapp de Hermes. No lanza,
# dirige ni para runs.
#
# Base python:3.13-slim (NO Kali): wrapper HTTP fino, sin CLIs de pentest. Multi-arch.
#
# Build (desde la raíz del repo):
#   docker buildx build --platform linux/arm64,linux/amd64 \
#     -f docker/web/Dockerfile -t vulnerator-ai-web:dev .

# syntax=docker/dockerfile:1

FROM python:3.13-slim

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/vulnerator-web

# Dependencias de sistema de WeasyPrint (render HTML->PDF del informe): pango/cairo/gdk-pixbuf
# + fuentes. Sin estas libs, `import weasyprint` falla en tiempo de ejecucion.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 \
      libjpeg62-turbo fonts-dejavu-core shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

COPY docker/web/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Módulos stdlib-puros (testeables sin SDK) + la capa web fina. caido_client es el MISMO
# módulo que usa kali-mcp (stdlib pura): el feed de tráfico web no duplica el cliente.
COPY docker/kali/caido_client.py ./caido_client.py
COPY docker/web/ooda_parse.py docker/web/event_model.py docker/web/trace_store.py \
     docker/web/poc_replay.py docker/web/ingest.py docker/web/caido_proxy.py docker/web/web_app.py \
     docker/web/report.py docker/web/vulnerator_watch.py ./
COPY docker/web/static ./static
COPY media/vulnerator-ai-logo-transparent.png ./static/logo.png

# Usuario sin privilegios. /data (volumen nombrado) guarda el store de trazas y los PoC
# grabados; Docker siembra el volumen vacío con este dueño.
RUN useradd --system --uid 10001 --no-create-home --home-dir /opt/vulnerator-web vweb \
    && mkdir -p /data/pocs \
    && chown -R vweb:vweb /data
USER 10001:10001

ENV VULNERATOR_WEB_HOST=0.0.0.0 \
    VULNERATOR_WEB_PORT=9100 \
    VULNERATOR_WEB_DB=/data/vulnerator-web.db \
    VULNERATOR_WEB_POC_DIR=/data/pocs \
    HERMES_API_BASE_URL=http://ooda-agent:8642

VOLUME ["/data"]
EXPOSE 9100

# /healthz es la única ruta sin auth (match exacto). python:3.13-slim no trae curl.
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 \
  CMD ["python3", "-c", "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('VULNERATOR_WEB_PORT','9100'), timeout=3).status==200 else 1)"]

CMD ["python3", "web_app.py"]
