#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
if [[ $EUID -ne 0 ]]; then exec sudo bash "$0" "$@"; fi
if [[ $# -ne 3 ]]; then echo "Usage: bash bootstrap.sh https://panel.example.com NODE_ID ONE_TIME_TOKEN" >&2; exit 2; fi
PANEL="${1%/}"; NODE="$2"; TOKEN="$3"
[[ "$PANEL" =~ ^https://[a-zA-Z0-9.-]+(:[0-9]{1,5})?$ ]] || { echo "Expected HTTPS panel origin" >&2; exit 2; }
[[ "$NODE" =~ ^[1-9][0-9]*$ && "$TOKEN" =~ ^[a-f0-9]{64}$ ]] || { echo "Invalid node ID or token" >&2; exit 2; }
# Prepare dependencies before redeeming the short-lived enrollment token.
command -v apt-get >/dev/null || { echo "Automatic bootstrap currently supports Ubuntu with apt." >&2; exit 1; }
. /etc/os-release
[[ "${ID:-}" == "ubuntu" ]] || { echo "Automatic Docker installation currently supports Ubuntu only." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required for the metrics collector" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
 echo "Installing Docker Engine and Compose from Docker's official Ubuntu repository..."
 apt-get update
 apt-get install -y ca-certificates curl gnupg
 install -m 0755 -d /etc/apt/keyrings
 curl --proto '=https' --tlsv1.2 -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
 chmod a+r /etc/apt/keyrings/docker.asc
 arch="$(dpkg --print-architecture)"
 case "$arch" in amd64|arm64|armhf|s390x|ppc64el) ;; *) echo "Unsupported Docker architecture: $arch" >&2; exit 1;; esac
 printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' "$arch" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
 apt-get update
 # Do not silently uninstall an existing alternative Docker installation.
 if command -v docker >/dev/null; then
  apt-get install -y docker-compose-plugin docker-buildx-plugin
 else
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
 fi
 systemctl enable --now docker
fi
docker compose version >/dev/null
docker info >/dev/null || { echo "Docker daemon is unavailable." >&2; exit 1; }
apt-get install -y git python3 openssl curl
INSTALL_DIR=/opt/xmesh-node
if [[ -d /root/XMesh-Node/.git ]]; then INSTALL_DIR=/root/XMesh-Node; fi
if [[ ! -d "$INSTALL_DIR/.git" ]]; then
 command -v git >/dev/null || { echo "git required" >&2; exit 1; }
 git clone --depth 1 https://github.com/TriplexCorp/XMesh-Node.git "$INSTALL_DIR"
else
 git -C "$INSTALL_DIR" pull --ff-only
fi
# Validate any existing configuration BEFORE consuming the one-use token.
if [[ -f "$INSTALL_DIR/config.json" ]]; then
 python3 - "$INSTALL_DIR/config.json" "$NODE" <<'PY'
import json,sys
with open(sys.argv[1],encoding="utf-8") as f: d=json.load(f)
if not isinstance(d,dict): raise SystemExit("config.json must contain an object")
previous=d.get("node_id")
if previous is not None and int(previous)!=int(sys.argv[2]):
 raise SystemExit("Refusing to move an existing node to a different ID; use the original node or migrate deliberately.")
PY
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
import os,tempfile
fd,tmp=tempfile.mkstemp(prefix=".config.",dir=".")
try:
 with os.fdopen(fd,"w") as f:
  json.dump(d,f,indent=2)
  f.write("\\n")
 os.replace(tmp,p)
except:
 os.unlink(tmp)
 raise
PY
fi
chmod 644 config.json
docker compose build
docker compose run --rm --no-deps xmesh-node -check -config /etc/xmesh-node/config.json
docker compose up -d --no-build
docker compose ps
# One installer, two services: always reconcile system metrics agent configuration.
# Re-running the metrics installer preserves the Ed25519 identity, but updates
# panel URL, node ID, timers and collector to the current release.
echo "Configuring XMesh system metrics collector..."
METRICS_INSTALLER="$(mktemp /tmp/xmesh-metrics.XXXXXXXX)"
trap 'rm -f "$METRICS_INSTALLER"' EXIT
curl --proto '=https' --tlsv1.2 -fsSLo "$METRICS_INSTALLER" https://raw.githubusercontent.com/TriplexCorp/XMesh-Nexus/main/deploy/install-node-metrics-agent.sh
bash "$METRICS_INSTALLER" "$PANEL" "$NODE"
systemctl enable --now xmesh-node-metrics.timer
echo "Node enrolled. Router initially listens on :8443; port 443 is NOT taken over automatically."
