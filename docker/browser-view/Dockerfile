# browser-view — VISIBLE browser (Chromium) for the vulnerator-web demos.
#
# Xvfb (virtual display) + headed Chromium + x11vnc + noVNC. playwright-mcp drives it over CDP
# (via cdp_proxy.py, which fixes Chrome's anti-rebinding protection) and the operator sees it
# through noVNC embedded in the console. It does NOT publish the debugging port; only noVNC goes
# to the host (done by docker-compose.yml).
#
# Build (from the repo root):
#   docker build -f docker/browser-view/Dockerfile -t vulnerator-ai-browser-view:dev docker/browser-view

# syntax=docker/dockerfile:1

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Browser + virtual display + VNC/noVNC + lightweight WM + fonts + tini (init). Pinned versions
# (repo discipline). Cleanup of apt lists in the same layer.
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

# noVNC (web). The debugging port (9222 of the proxy, 9223 of Chrome) is NOT exposed here: only
# playwright-mcp reaches it over the internal network; nobody else.
EXPOSE 6080

# Alive = noVNC responds AND the CDP proxy returns the browser version.
HEALTHCHECK --interval=15s --timeout=5s --start-period=25s --retries=5 \
  CMD ["sh", "-c", "python3 -c \"import urllib.request,sys; urllib.request.urlopen('http://127.0.0.1:6080/', timeout=3); urllib.request.urlopen('http://127.0.0.1:9222/json/version', timeout=3)\" || exit 1"]

ENTRYPOINT ["/usr/bin/tini", "--", "/opt/browser-view/entrypoint.sh"]
