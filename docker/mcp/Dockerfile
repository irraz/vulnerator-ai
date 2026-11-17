# vulnerator-mcp — front door MCP FINO sobre la API de runs de Hermes (:8642).
#
# UNA imagen, DOS modos de ejecucion (los selecciona entrypoint.sh):
#   - stdio (default)      : el cliente arranca el proceso (docker run -i). Superficie cero.
#   - streamable-http      : servicio por defecto (docker-compose.yml), fail-closed en el
#                            token de entrada VULNERATOR_MCP_INBOUND_TOKEN.
#
# Multi-arch (linux/arm64 + linux/amd64). Base python:3.13-slim (NO Kali): este componente
# es un wrapper HTTP fino, no necesita CLIs de pentest.
#
# Build (desde la raiz del repo):
#   docker buildx build --platform linux/arm64,linux/amd64 \
#     -f docker/mcp/Dockerfile -t vulnerator-ai-mcp:dev .

# syntax=docker/dockerfile:1

FROM python:3.15-slim

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/vulnerator-mcp

# Manifiesto de dependencias (mcp>=1.28,<2 ; httpx ; anyio>=4 ; uvicorn). Versiones y
# rationale en requirements.txt.
COPY docker/mcp/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Modulos del servidor. mcp_tool_logic/hermes_api_client son SDK-free (testeables sin mcp);
# vulnerator_mcp_server es el plano de control FastMCP que los importa.
COPY docker/mcp/mcp_tool_logic.py ./mcp_tool_logic.py
COPY docker/mcp/hermes_api_client.py ./hermes_api_client.py
COPY docker/mcp/vulnerator_mcp_server.py ./vulnerator_mcp_server.py
COPY docker/mcp/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Config por defecto (overridable por entorno). El default de proceso es stdio.
ENV VULNERATOR_MCP_HOST=0.0.0.0 \
    VULNERATOR_MCP_PORT=8700 \
    HERMES_API_BASE_URL=http://ooda-agent:8642 \
    VULNERATOR_MCP_TRANSPORT=stdio

# EXPOSE es documentacion; solo tiene sentido en modo streamable-http. 8700 no choca con
# 8642 (Hermes), 8900/8901 (kali-mcp + artifacts), 8931 (playwright-mcp).
EXPOSE 8700

# HEALTHCHECK: python:3.13-slim NO trae curl (la base Kali si), asi que se sondea con la
# stdlib (igual idioma que los healthchecks python/node del compose). Solo tiene sentido en
# modo streamable-http: sondea la ruta DEDICADA /healthz (el middleware de auth la deja
# abierta con un carve-out de match exacto), que devuelve 200. En stdio no hay listener y el
# contenedor lo arranca el cliente, asi que el healthcheck de compose no aplica.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD python3 -c "import sys,urllib.request; \
import os; \
url='http://127.0.0.1:%s/healthz' % os.environ.get('VULNERATOR_MCP_PORT','8700'); \
sys.exit(0 if urllib.request.urlopen(url, timeout=3).status==200 else 1)" || exit 1

# El entrypoint resuelve el transporte (arg o env) y arranca el servidor. CMD vacio por
# defecto -> stdio.
ENTRYPOINT ["/entrypoint.sh"]
CMD []
