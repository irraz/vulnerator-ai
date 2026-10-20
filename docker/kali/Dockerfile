# Kali — runtime determinista de tools de pentest servidas por kali-mcp.
#
# Multi-arch (linux/arm64 + linux/amd64). Base: kalilinux/kali-rolling, cuyo tag
# `latest` es un manifiesto multi-arch que resuelve a la arquitectura del host
# (en Mac M2 -> arm64 nativo).
#
# Build (desde la raíz del repo):
#   docker buildx build --platform linux/arm64,linux/amd64 \
#     -f docker/kali/Dockerfile -t vulnerator-ai-kali:dev .
#
# -----------------------------------------------------------------------------
# Compatibilidad arm64
# -----------------------------------------------------------------------------
# - kali-rolling publica imágenes para amd64 y arm64; en Mac M2 corre nativamente
#   en arm64.
# - Prowler es un paquete Python puro (PyPI) -> instalable en arm64 y amd64 sin
#   binarios específicos de arquitectura.
# - Si alguna tool determinista NO estuviera disponible para arm64, el servicio
#   kali-mcp lo REPORTA explícitamente (server_info). No se finge disponibilidad:
#   se reporta como no disponible en esta arquitectura.
#
# Nota de versión de Python: kali-rolling trae por defecto Python 3.14, pero
# Prowler aún exige `<3.14`. Por eso instalamos `python3.13` y creamos un
# virtualenv dedicado (/opt/kali-mcp/venv) donde viven Prowler + el SDK `mcp`.
# El servidor arranca con el intérprete de ese venv.

# syntax=docker/dockerfile:1

FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Dependencias de sistema mínimas para Prowler/kali-mcp. python3.13 es el
# intérprete compatible con Prowler (kali-rolling ya empaqueta 3.13).
# Prowler arrastra alguna dependencia con extensión C (p. ej. `zstd`) que compila
# en arm64; por eso se incluyen toolchain + headers + libzstd/pkg-config.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3.13 \
      python3.13-venv \
      python3.13-dev \
      build-essential \
      pkg-config \
      libzstd-dev \
      ca-certificates \
      curl \
      git \
 && rm -rf /var/lib/apt/lists/*

# CURATED set of pentest CLIs that the skills (web-pentest, recon) assume exist and invoke via
# kali_run. The base kalilinux/kali-rolling image is MINIMAL and ships NONE of these, so without
# this layer those skills would fail at runtime. We bake a SMALL, deliberate selection (NOT the
# kali-linux-headless metapackage) to fix that latent gap while keeping the image reasonably sized:
#   - nmap, whatweb, nuclei, ffuf, sqlmap, gobuster : web/recon tools used by the skills.
#   - impacket-scripts                              : Impacket CLI helpers (AD/network).
# All package names were confirmed installable in kali-rolling (apt-get install --dry-run). Own
# RUN layer with --no-install-recommends + rm -rf /var/lib/apt/lists/*, consistent with the style
# above. Tools NOT baked here (anything else a skill needs ad-hoc) are still `apt install`-able on
# the fly inside the ephemeral kali container.
#
# bloodhound.py (apt) is DELIBERATELY NOT installed here: as of 2026-10-20 its postinst
# maintainer script crashes against the current kali-rolling python3-impacket build
# (references impacket/dcerpc/v5/dhcpm.py, removed upstream), which aborts this entire RUN
# layer and the whole image build. It is an unmaintained Python 2-era package; the active
# successor is the `bloodhound-python` PyPI package (pure Python 3, no dpkg postinst hook).
# TODO: add `bloodhound-python` via pip in the venv below if/when AD-focused skills need it.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap \
      whatweb \
      nuclei \
      ffuf \
      sqlmap \
      gobuster \
      impacket-scripts \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/kali-mcp

# Virtualenv dedicado con Python 3.13 (compatible con Prowler). Ponerlo primero en
# el PATH hace que `python3`/`pip`/`prowler` del venv sean los que se usan.
ENV VIRTUAL_ENV=/opt/kali-mcp/venv \
    PATH=/opt/kali-mcp/venv/bin:$PATH
RUN python3.13 -m venv "$VIRTUAL_ENV" \
 && "$VIRTUAL_ENV/bin/pip" install --no-cache-dir --upgrade pip

# Manifiesto de dependencias del VENV DEL SERVIDOR: Prowler + el SDK `mcp` que usa
# kali-mcp. Versiones fijadas en requirements.txt.
COPY docker/kali/requirements.txt ./requirements.txt
RUN "$VIRTUAL_ENV/bin/pip" install --no-cache-dir -r requirements.txt

# Fuentes EN VIVO adicionales AISLADAS con pipx: cada herramienta en su propio venv, con
# su entrypoint expuesto en /usr/local/bin (en PATH). kali-mcp las invoca como SUBPROCESOS
# (`scout`, `cloudsplaining`), no las importa, así que NO necesitan compartir el venv del
# servidor — y NO pueden: Prowler y ScoutSuite tienen deps incompatibles (python-dateutil),
# un conflicto que tumbaría el build en un venv único. Aislar es el patrón correcto para
# ejecutables independientes y evita el acoplamiento artificial.
#
# Los instala NO-FATALMENTE (`|| true`): si una tool no es instalable en esta arquitectura /
# Python, el build NO se rompe; kali-mcp la reporta ausente (server_info -> which) y su
# collection falla claro (fail-closed). No se finge disponibilidad.
ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin
RUN "$VIRTUAL_ENV/bin/pip" install --no-cache-dir pipx \
 && ( "$VIRTUAL_ENV/bin/python" -m pipx install --python python3.13 scoutsuite==5.14.0 \
      || echo "[kali-mcp] ScoutSuite no instalable en este runtime; se reportará ausente." ) \
 && ( "$VIRTUAL_ENV/bin/python" -m pipx install --python python3.13 cloudsplaining==0.9.1 \
      || echo "[kali-mcp] Cloudsplaining no instalable en este runtime; se reportará ausente." ) \
 && ( "$VIRTUAL_ENV/bin/python" -m pipx install --python python3.13 pacu==1.6.0 \
      || echo "[kali-mcp] Pacu no instalable en este runtime; se reportará ausente." )

# Servidor kali-mcp (entrypoint real). Expone las tools de pentest sobre
# streamable-HTTP en :8900.
# tool_streaming.py: helper de streaming de salida de tools en vivo (ring buffer +
# ejecucion con kill del grupo de procesos al timeout). Lo importa kali_mcp_server.
COPY docker/kali/tool_streaming.py ./tool_streaming.py
# Plano de DATOS, STDLIB PURA: staging del crudo (artifact_store), servidor HTTP que lo
# entrega por stream (artifact_http) y finalización del escaneo (prowler_artifact). Los
# importa kali_mcp_server / collector_runner.
COPY docker/kali/artifact_store.py ./artifact_store.py
COPY docker/kali/artifact_http.py ./artifact_http.py
COPY docker/kali/prowler_artifact.py ./prowler_artifact.py
# Runner multi-herramienta genérico: registro por fuente + worker/finalize únicos que
# lanzan prowler/scoutsuite/cloudsplaining bajo el mismo contrato. Lo importa
# kali_mcp_server; reutiliza tool_streaming/artifact_store/prowler_artifact.
COPY docker/kali/collector_runner.py ./collector_runner.py
# Runner AWS: enum IAM read-only acotado (tool `iam_enum`) y simulación de permisos
# read-only (iam:SimulatePrincipalPolicy, tool `iam_simulate`). aws_exec.py/
# aws_simulate.py son STDLIB PURA (build/exec vía tool_streaming); aws_iam_enum.py/
# aws_iam_simulate.py son los scripts boto3 THIN que corren en el venv del servidor. Los
# importa/invoca kali_mcp_server.
COPY docker/kali/aws_exec.py ./aws_exec.py
COPY docker/kali/aws_iam_enum.py ./aws_iam_enum.py
COPY docker/kali/aws_simulate.py ./aws_simulate.py
COPY docker/kali/aws_iam_simulate.py ./aws_iam_simulate.py
# Runner de SHELL CRUDA (tool `kali_exec`): ejecuta un comando arbitrario de la Kali vía
# `sh -c` reutilizando tool_streaming (STDLIB PURA). Lo importa kali_mcp_server.
COPY docker/kali/shell_exec.py ./shell_exec.py
# Store de hallazgos por engagement (tools `record_finding`/`read_findings`): append
# estructurado a un JSONL sobre el plano de artefactos (STDLIB PURA, reutiliza
# artifact_store para confinar la ruta). Lo importa kali_mcp_server.
COPY docker/kali/finding_store.py ./finding_store.py
# Generador del informe de pentest (skill pentest-report): LEE el store de hallazgos y
# produce un Markdown que deja como artefacto. STDLIB PURA; se invoca con kali_run.
COPY docker/kali/report_gen.py ./report_gen.py
# Scope-guard (opt-in, v1.3.0): valida DETERMINISTAMENTE el destino de kali_run/kali_exec
# ANTES de ejecutar. STDLIB PURA. Lo importa kali_mcp_server (import scope_guard), por lo que
# DEBE estar en la imagen aunque el guard esté desactivado por defecto; sin este COPY el
# servidor aborta al arrancar con ModuleNotFoundError: No module named 'scope_guard'.
COPY docker/kali/scope_guard.py ./scope_guard.py
COPY docker/kali/kali_mcp_server.py ./kali_mcp_server.py

# Puerto del servidor kali-mcp. Overridable por entorno (KALI_MCP_PORT) sin
# reconstruir, pero el default del contrato es 8900 (KALI_MCP_URL=http://kali:8900).
ENV KALI_MCP_HOST=0.0.0.0 \
    KALI_MCP_PORT=8900

# Plano de DATOS: el servidor HTTP de artefactos stagea el crudo en KALI_ARTIFACTS_DIR y
# lo sirve en KALI_ARTIFACTS_PORT (DEDICADO, distinto del MCP). KALI_ARTIFACTS_TOKEN NO se
# fija aquí: se inyecta por el entorno (compose); sin él, el canal de datos no arranca y se
# usa el puente read_scan_findings.
ENV KALI_ARTIFACTS_HOST=0.0.0.0 \
    KALI_ARTIFACTS_DIR=/artifacts \
    KALI_ARTIFACTS_PORT=8901

EXPOSE 8900
# Puerto del plano de DATOS. Se EXPONE a la red interna de docker, pero NO se publica al
# host en compose: el crudo puede ser sensible y no debe salir del entorno docker.
EXPOSE 8901

# Healthcheck: el servidor MCP responde en la raíz (streamable-HTTP montado en "/").
# Un proceso vivo y escuchando responde al transporte MCP (4xx del handshake), no
# connection-refused; eso basta como liveness del contenedor.
HEALTHCHECK --interval=15s --timeout=5s --start-period=25s --retries=5 \
  CMD curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${KALI_MCP_PORT}/" \
      | grep -Eq '^(200|400|405|406)$'

# kali-mcp sirve las tools de pentest por este puerto; es el endpoint MCP que Hermes
# consume como cliente (kali:8900). Con `docker compose up` queda un Kali operativo como
# runner por defecto, sin configurar nada manual.
# El python del PATH es el del venv (Python 3.13 con Prowler + mcp).
CMD ["python3", "kali_mcp_server.py"]
