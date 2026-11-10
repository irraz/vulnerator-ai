#!/usr/bin/env bash
# build-local-images.sh — construye las imágenes propias de Vulnerator-AI para la arquitectura
# LOCAL (una sola plataforma). Úsalo en lugar de `docker compose build` cuando tu Docker no
# tiene buildx/containerd (el compose declara `platforms:` multi-arch para publicar, y un Docker
# normal falla con "Multi-platform build is not supported for the docker driver").
#
# Tras esto: `docker compose up -d --no-build` (o con el lab: añade -f docker-compose.target.yml).
set -euo pipefail
cd "$(dirname "$0")"

build() { echo "==> $2"; docker build -f "$1" -t "$2" "${3:-.}"; }

build docker/kali/Dockerfile            vulnerator-ai-kali:dev            .
build docker/mcp/Dockerfile             vulnerator-ai-mcp:dev            .
build docker/web/Dockerfile             vulnerator-ai-web:dev            .
build docker/browser-view/Dockerfile    vulnerator-ai-browser-view:dev   docker/browser-view
build docker/caido-director/Dockerfile  vulnerator-ai-caido-director:dev docker/caido-director

echo "OK — imágenes propias construidas. Ahora: docker compose up -d --no-build"
