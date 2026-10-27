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
# BloodHound ingestor (AD): el paquete apt `bloodhound.py` NO se instala aquí a propósito.
# Su postinst de dpkg PETA contra el python3-impacket actual de kali-rolling (referencia
# impacket/dcerpc/v5/dhcpm.py, eliminado upstream) y aborta este RUN y el build entero.
# En su lugar se instala el sucesor activo `bloodhound` (PyPI, Python 3 puro, SIN postinst)
# en el venv del servidor vía requirements.txt — expone el ejecutable `bloodhound-python`
# en PATH. Ver docker/kali/requirements.txt para el pin y la nota de dependency-confusion.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap \
      whatweb \
      nuclei \
      ffuf \
      sqlmap \
      gobuster \
      impacket-scripts \
      wpscan \
 && rm -rf /var/lib/apt/lists/*

# webanalyze: motor de fingerprints de Wappalyzer (port en Go; el CLI oficial de Wappalyzer
# está descontinuado). Se usa junto a whatweb + wpscan en la tool `webtech_scan` para cruzar
# tecnologías/versiones. No está en apt: se baja el binario de release y sus fingerprints
# (`technologies.json`) a una ruta FIJA (`/opt/webanalyze`), que `webtech_scan` pasa con
# `-apps`. Versión fijada; checksum verificado contra el `checksums.txt` de la release.
ARG WEBANALYZE_VERSION=v0.4.6
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) wa_arch="x86_64" ;; \
      arm64) wa_arch="arm64" ;; \
      *) echo "[kali-mcp] webanalyze: arch $arch no soportada; se reportará ausente." && exit 0 ;; \
    esac; \
    base="https://github.com/rverton/webanalyze/releases/download/${WEBANALYZE_VERSION}"; \
    ver="${WEBANALYZE_VERSION#v}"; \
    tarball="webanalyze_Linux_${wa_arch}.tar.gz"; \
    cd /tmp; \
    curl -fsSL -o "$tarball" "${base}/${tarball}"; \
    curl -fsSL -o checksums.txt "${base}/webanalyze_${ver}_checksums.txt"; \
    grep " ${tarball}\$" checksums.txt | sha256sum -c -; \
    tar -xzf "$tarball" webanalyze; \
    install -m 0755 webanalyze /usr/local/bin/webanalyze; \
    mkdir -p /opt/webanalyze; \
    ( cd /opt/webanalyze && webanalyze -update ); \
    test -f /opt/webanalyze/technologies.json; \
    rm -f /tmp/"$tarball" /tmp/checksums.txt /tmp/webanalyze

# Ruta fija de los fingerprints de webanalyze que lee `webtech_scan` (tool `webtech_scan`).
ENV WEBANALYZE_APPS=/opt/webanalyze/technologies.json

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
# Cliente de la API de DNSDumpster (tool `dns_recon`): recon DNS + superficie de ataque de
# un dominio (hosts/IPs/ASN/PTR/banners) con rate limit y paginación. STDLIB PURA (urllib).
# Lo importa kali_mcp_server (import dnsdumpster_client); sin este COPY el servidor aborta
# al arrancar con ModuleNotFoundError.
COPY docker/kali/dnsdumpster_client.py ./dnsdumpster_client.py
# Fingerprint web por cruce whatweb+webanalyze+wpscan (tool `webtech_scan`): fusiona las
# versiones que ve cada herramienta y marca conflictos. STDLIB PURA. Lo importa
# kali_mcp_server (import webtech_scan as webtech); DEBE estar en la imagen.
COPY docker/kali/webtech_scan.py ./webtech_scan.py
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
