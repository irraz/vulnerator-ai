# vulnerator-web — Vulnerator-AI's web GUI (operator console for the OODA loop).
#
# OBSERVER: it reads Hermes' session API (:8642) and Caido's history, and serves on
# :9100 the live terminal, the Copilot panel, the tool-call traces (its own SQLite store),
# the PoCs with their recorded reproduction, and the links to Hermes' Dashboard/Webapp. It does
# not launch, steer or stop runs.
#
# Base python:3.13-slim (NOT Kali): a thin HTTP wrapper, no pentest CLIs. Multi-arch.
#
# Build (from the repo root):
#   docker buildx build --platform linux/arm64,linux/amd64 \
#     -f docker/web/Dockerfile -t vulnerator-ai-web:dev .

# syntax=docker/dockerfile:1

FROM python:3.13-slim

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/vulnerator-web

COPY docker/web/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Pure-stdlib modules (testable without an SDK) + the thin web layer. caido_client is the SAME
# module kali-mcp uses (pure stdlib): the web-traffic feed does not duplicate the client.
COPY docker/kali/caido_client.py ./caido_client.py
COPY docker/web/ooda_parse.py docker/web/event_model.py docker/web/trace_store.py \
     docker/web/poc_replay.py docker/web/ingest.py docker/web/caido_proxy.py docker/web/web_app.py \
     docker/web/report.py docker/web/vulnerator_watch.py ./
COPY docker/web/static ./static
COPY media/vulnerator-ai-logo-transparent.png ./static/logo.png
COPY media/vulnerator-ai-logo-header.png ./static/logo-header.png

# Unprivileged user. /data (named volume) holds the trace store and the recorded
# PoCs; Docker seeds the empty volume with this owner.
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

# /healthz is the only route without auth (exact match). python:3.13-slim ships no curl.
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 \
  CMD ["python3", "-c", "import os,sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('VULNERATOR_WEB_PORT','9100'), timeout=3).status==200 else 1)"]

CMD ["python3", "web_app.py"]
