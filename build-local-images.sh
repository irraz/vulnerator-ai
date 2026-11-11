#!/usr/bin/env bash
# build-local-images.sh — builds Vulnerator-AI's own images for the LOCAL architecture
# (a single platform). Use it instead of `docker compose build` when your Docker does not
# have buildx/containerd (the compose declares multi-arch `platforms:` for publishing, and a
# normal Docker fails with "Multi-platform build is not supported for the docker driver").
#
# After this: `docker compose up -d --no-build` (or with the lab: add -f docker-compose.target.yml).
set -euo pipefail
cd "$(dirname "$0")"

build() { echo "==> $2"; docker build -f "$1" -t "$2" "${3:-.}"; }

build docker/kali/Dockerfile            vulnerator-ai-kali:dev            .
build docker/mcp/Dockerfile             vulnerator-ai-mcp:dev            .
build docker/web/Dockerfile             vulnerator-ai-web:dev            .
build docker/browser-view/Dockerfile    vulnerator-ai-browser-view:dev   docker/browser-view
build docker/caido-director/Dockerfile  vulnerator-ai-caido-director:dev docker/caido-director

echo "OK — own images built. Now: docker compose up -d --no-build"
