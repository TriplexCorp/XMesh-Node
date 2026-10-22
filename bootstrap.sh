#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
if [[ $EUID -ne 0 ]]; then exec sudo bash "$0" "$@"; fi
if [[ $# -ne 3 ]]; then echo "Usage: bash install.sh https://panel.example.com NODE_ID ONE_TIME_TOKEN" >&2; exit 2; fi
PANEL="${1%/}"; NODE="$2"; TOKEN="$3"
[[ "$PANEL" =~ ^https://[a-zA-Z0-9.-]+(:[0-9]{1,5})?$ ]] || { echo "Expected HTTPS panel origin" >&2; exit 2; }
[[ "$NODE" =~ ^[1-9][0-9]*$ && "$TOKEN" =~ ^[a-f0-9]{64}$ ]] || { echo "Invalid node ID or token" >&2; exit 2; }
command -v docker >/dev/null || { echo "Install Docker Engine and Compose first." >&2; exit 1; }
docker compose version >/dev/null
command -v python3 >/dev/null
command -v openssl >/dev/null
command -v curl >/dev/null
INSTALL_DIR=/opt/xmesh-node
if [[ -d /root/XMesh-Node/.git ]]; then INSTALL_DIR=/root/XMesh-Node; fi
if [[ ! -d "$INSTALL_DIR/.git" ]]; then
 command -v git >/dev/null || { echo "git required" >&2; exit 1; }
 git clone --depth 1 https://github.com/TriplexCorp/XMesh-Node.git "$INSTALL_DIR"
else
 git -C "$INSTALL_DIR" pull --ff-only
fi
mkdir -p /etc/xmesh-node-metrics
KEY=/etc/xmesh-node-metrics/node.key
if [[ ! -f "$KEY" ]];then
 openssl genpkey -algorithm Ed25519 -out "$KEY"
 chmod 600 "$KEY"
fi
PUB="$(openssl pkey -in "$KEY" -pubout -outform DER | tail -c 32 | od -An -tx1 -v | tr -d '[:space:]')"
JSON="$(python3 -c 'import json,sys; print(json.dumps({"token":sys.argv[1],"publicKey":sys.argv[2]}))' "$TOKEN" "$PUB")"
curl --proto '=https' --tlsv1.2 -fsS --max-time 20 \
 -H 'Content-Type: application/json' \
 --data-binary "$JSON" "$PANEL/api/v1/node/enroll" >/dev/null
cd "$INSTALL_DIR"
# Preserve existing routing settings and never overwrite a user-edited configuration.
if [[ ! -f config.json ]]; then
 python3 - "$PANEL" "$NODE" <<'PY'
import json,sys
config={"panel_url":sys.argv[1],"node_id":int(sys.argv[2]),
"private_key_file":"/etc/xmesh-node-metrics/node.key",
"listen_tcp":":8443","listen_udp":"",
"default_tcp":"127.0.0.1:9443","routes":[],
"hello_timeout_seconds":5,"idle_timeout_seconds":120,
"max_tcp_connections":4096,"max_udp_sessions":2048}
with open("config.json","w") as f:json.dump(config,f,indent=2)
PY
else
 python3 - "$PANEL" "$NODE" <<'PY'
import json,sys
p="config.json"
with open(p) as f:d=json.load(f)
d.update(panel_url=sys.argv[1],node_id=int(sys.argv[2]),private_key_file="/etc/xmesh-node-metrics/node.key")
# Automatically repair an unsafe self-referential test backend.
if d.get("listen_tcp") and d.get("default_tcp"):
 from urllib.parse import urlsplit
 if d["listen_tcp"].rsplit(":",1)[-1]==d["default_tcp"].rsplit(":",1)[-1]:
  d["default_tcp"]="127.0.0.1:9443"
  print("Corrected self-referential default TCP backend to 127.0.0.1:9443")
with open(p,"w") as f:json.dump(d,f,indent=2)
PY
fi
chmod 644 config.json
docker compose build
docker compose run --rm --no-deps xmesh-node -check -config /etc/xmesh-node/config.json
docker compose up -d --no-build
docker compose ps
echo "Node enrolled. Router initially listens on :8443; port 443 is NOT taken over automatically."
