#!/usr/bin/env bash
# XMesh Node v6 standalone installer. v6 is strict-PQ-only: an operational
# router must never start before a durable product activation receipt verifies.
set -Eeuo pipefail
umask 077
cd "$(dirname "$(readlink -f "$0")")"

[[ "$EUID" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker Engine with Compose plugin first." >&2
  exit 1
fi
docker compose version >/dev/null

if [[ ! -f config.json ]]; then
  cp config.example.json config.json
  chmod 0644 config.json
  echo "Created config.json. Edit SNI routes and backends, then rerun ./install.sh with strict-PQ enrollment coordinates."
  exit 0
fi
if [[ ! -r config.json ]]; then echo 'config.json is not readable' >&2; exit 1; fi
chmod 0644 config.json
[[ -f VERSION && "$(tr -d '\r\n' < VERSION)" == "6.0.0" ]] || { echo 'XMesh Node v6 VERSION marker missing' >&2; exit 1; }

revision="$(git rev-parse HEAD)"
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid Node source revision' >&2; exit 1; }

# A retry/upgrade must not leave an older router serving while the v6 identity
# has not yet proven strict-PQ activation. Only the managed container is touched.
if docker inspect xmesh-node >/dev/null 2>&1; then
  docker update --restart=no xmesh-node >/dev/null 2>&1 || true
  docker stop -t 5 xmesh-node >/dev/null 2>&1 || true
fi
if docker inspect xmesh-managed-xray >/dev/null 2>&1; then
  docker update --restart=no xmesh-managed-xray >/dev/null 2>&1 || true
  docker stop -t 5 xmesh-managed-xray >/dev/null 2>&1 || true
fi

# Install both reviewed v6 PQ runtimes before any operational startup.
bash deploy/install-xsp-v2-production-agent.sh "$revision"
PRODUCT=/usr/local/bin/xmesh-agent-xspv2-product
[[ -x "$PRODUCT" ]] || { echo 'strict-PQ product client missing after installation' >&2; exit 1; }

PANEL="${XMESH_API_URL:-}"
NODE="${XMESH_NODE_ID:-}"
TOKEN_FILE="${XMESH_ENROLLMENT_TOKEN_FILE:-}"
[[ "$PANEL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || {
  echo 'XMESH_API_URL=https://panel.example.com is required for XMesh Node v6.' >&2
  exit 2
}
[[ "$NODE" =~ ^[1-9][0-9]*$ ]] || { echo 'XMESH_NODE_ID is required for XMesh Node v6.' >&2; exit 2; }

if ! "$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null 2>&1; then
  [[ -n "$TOKEN_FILE" && -f "$TOKEN_FILE" && ! -L "$TOKEN_FILE" ]] || {
    echo 'No verified strict-PQ activation. Set XMESH_ENROLLMENT_TOKEN_FILE to the root-owned one-time token file.' >&2
    exit 1
  }
  [[ "$(stat -c '%a:%u' "$TOKEN_FILE")" == "600:0" ]] || {
    echo 'XMESH_ENROLLMENT_TOKEN_FILE must be a regular root-owned mode-0600 file.' >&2
    exit 1
  }
  "$PRODUCT" bootstrap --panel "$PANEL" --node-id "$NODE" --token-file "$TOKEN_FILE"
fi

# This is the mandatory security gate. No router/Xray startup exists above it.
"$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null
python3 - /var/lib/xmesh-agent/product/active.json "$NODE" <<'PY'
import json,sys
with open(sys.argv[1],encoding='utf-8') as f: state=json.load(f)
assert state.get('schema')=='xmesh-v6-strict-pq-active-1', state
assert state.get('nodeId')==int(sys.argv[2]), state
assert state.get('productionActivation') is True, state
assert state.get('strictPQEnabled') is True, state
assert state.get('automaticClassicalFallback') is False, state
PY

echo "STRICT-PQ GATE PASSED. Building and starting XMesh Node v6.0.0."
# Host mode requires TCP/443 (and UDP/443 if configured) to be available.
docker compose build
docker compose run --rm --no-deps xmesh-node -check -config /etc/xmesh-node/config.json
docker compose up -d --no-build
[[ "$(docker inspect -f '{{.State.Running}}' xmesh-node 2>/dev/null || true)" == true ]] || {
  echo 'XMesh router failed to start after verified strict-PQ activation.' >&2
  exit 1
}
docker compose ps
echo "XMesh Node v6.0.0 POSTQUANTUM active; automatic classical fallback is disabled."
