#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$(readlink -f "$0")")"
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker Engine with Compose plugin first." >&2
  exit 1
fi
docker compose version >/dev/null
if [[ ! -f config.json ]]; then
  cp config.example.json config.json
  chmod 0600 config.json
  echo "Created config.json. Edit SNI routes and backends, then rerun ./install.sh."
  exit 0
fi
docker compose build
docker compose run --rm --no-deps xmesh-node -check -config /etc/xmesh-node/config.json
echo "Starting XMesh Node. Ensure host TCP/443 and UDP/443 are not occupied."
docker compose up -d --no-build
docker compose ps
