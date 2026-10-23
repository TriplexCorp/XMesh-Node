#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
if [[ $EUID -ne 0 ]]; then exec sudo bash "$0" "$@"; fi
if [[ $# -lt 2 || $# -gt 3 ]]; then echo "Usage: bash bootstrap.sh https://panel.example.com NODE_ID [suggested-node-port] (token requested securely)" >&2; exit 2; fi
PANEL="${1%/}"; NODE="$2"; SUGGESTED_PORT="${3:-8443}"
TOKEN=""
[[ "$PANEL" =~ ^https://[a-zA-Z0-9.-]+(:[0-9]{1,5})?$ ]] || { echo "Expected HTTPS panel origin" >&2; exit 2; }
[[ "$NODE" =~ ^[1-9][0-9]*$ ]] || { echo "Invalid node ID" >&2; exit 2; }
# Port is the TCP entrypoint for XMesh Node, not a separate metrics listener.
[[ "$SUGGESTED_PORT" =~ ^[0-9]{1,5}$ ]] && (( 10#$SUGGESTED_PORT >= 1 && 10#$SUGGESTED_PORT <= 65535 )) || { echo "Invalid suggested port" >&2; exit 2; }
if [[ -t 0 ]]; then
 read -r -p "TCP port for XMesh Node [$SUGGESTED_PORT]: " INPUT_PORT
 NODE_PORT="${INPUT_PORT:-$SUGGESTED_PORT}"
else
 NODE_PORT="$SUGGESTED_PORT"
 echo "Non-interactive installation: using TCP port $NODE_PORT."
fi
[[ "$NODE_PORT" =~ ^[0-9]{1,5}$ ]] && (( 10#$NODE_PORT >= 1 && 10#$NODE_PORT <= 65535 )) || { echo "Port must be 1–65535" >&2; exit 2; }
NODE_PORT="$((10#$NODE_PORT))"
echo "XMesh Node will be configured to listen on TCP/$NODE_PORT."
if (( NODE_PORT == 443 )); then
 echo "NOTE: TCP/443 can be owned by XMesh Node OR another listener, not both on the same address."
 echo "Place Xray and other services behind XMesh Node on separate loopback ports."
fi
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
# Read the one-time secret without shell-history or process-argument exposure.
# Prompt only after installing dependencies to preserve the 10-minute token TTL.
[[ -r /dev/tty ]] || { echo "Interactive TTY required for secure token entry." >&2; exit 1; }
printf 'Paste the one-time enrollment token (input hidden): ' > /dev/tty
IFS= read -r -s TOKEN < /dev/tty
printf '\n' > /dev/tty
[[ "$TOKEN" =~ ^[a-f0-9]{64}$ ]] || { echo "Invalid enrollment token" >&2; exit 2; }
# Proof of private-key possession. Never send the private key to the panel.
PROOF_FILE="$(mktemp /tmp/xmesh-proof.XXXXXXXX)"
trap 'rm -f "$PROOF_FILE"' EXIT
printf 'XMESH-ENROLL-V1\n%s\n%s\n' "$TOKEN" "$PUB" > "$PROOF_FILE"
PROOF="$(openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$PROOF_FILE" | od -An -tx1 -v | tr -d '[:space:]')"
[[ "${#PROOF}" -eq 128 ]] || { echo "Could not create Ed25519 enrollment proof" >&2; exit 1; }
JSON="$(printf '%s' "$TOKEN" | python3 -c 'import json,sys; print(json.dumps({"token":sys.stdin.read(),"publicKey":sys.argv[1],"proof":sys.argv[2]}))' "$PUB" "$PROOF")"
printf '%s' "$JSON" | curl --proto '=https' --tlsv1.2 -fsS --max-time 20 \
 -H 'Content-Type: application/json' \
 --data-binary @- "$PANEL/api/v1/node/enroll" >/dev/null
unset TOKEN JSON PROOF
cd "$INSTALL_DIR"
# Preserve existing routing settings and never overwrite a user-edited configuration.
if [[ ! -f config.json ]]; then
 python3 - "$PANEL" "$NODE" "$NODE_PORT" <<'PY'
import json,sys
config={"panel_url":sys.argv[1],"node_id":int(sys.argv[2]),
"private_key_file":"/etc/xmesh-node-metrics/node.key",
"listen_tcp":":"+sys.argv[3],"listen_udp":"",
"default_tcp":"127.0.0.1:9443","routes":[],
"hello_timeout_seconds":5,"idle_timeout_seconds":120,
"max_tcp_connections":4096,"max_udp_sessions":2048}
with open("config.json","w") as f:json.dump(config,f,indent=2)
PY
else
 python3 - "$PANEL" "$NODE" "$NODE_PORT" <<'PY'
import json,sys
p="config.json"
with open(p) as f:d=json.load(f)
d.update(panel_url=sys.argv[1],node_id=int(sys.argv[2]),private_key_file="/etc/xmesh-node-metrics/node.key")
requested_port=":"+sys.argv[3]
if d.get("listen_tcp")!=requested_port:
 print("Updating node TCP listener from",d.get("listen_tcp"),"to",requested_port)
 d["listen_tcp"]=requested_port
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
  f.write("\n")
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
# The panel is the source of truth for the assigned XRAY STUDIO profile.
# Agent pulls via signed HTTPS requests. No inbound admin port is exposed.
echo "Installing managed Xray reconciliation agent..."
curl --proto '=https' --tlsv1.2 -fsSLo /usr/local/sbin/xmesh-xray-sync \
 https://raw.githubusercontent.com/TriplexCorp/XMesh-Node/main/deploy/xmesh-xray-sync.sh
chmod 0700 /usr/local/sbin/xmesh-xray-sync
cat > /etc/systemd/system/xmesh-xray-sync.service <<'SERVICE'
[Unit]
Description=XMesh managed Xray profile reconciliation
After=docker.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/xmesh-xray-sync
SERVICE
cat > /etc/systemd/system/xmesh-xray-sync.timer <<'TIMER'
[Unit]
Description=Reconcile assigned Xray configuration from XMesh Nexus
[Timer]
OnBootSec=35s
OnUnitActiveSec=60s
AccuracySec=10s
Unit=xmesh-xray-sync.service
[Install]
WantedBy=timers.target
TIMER
systemctl daemon-reload
systemctl enable --now xmesh-xray-sync.timer
echo "Running first Xray configuration sync now..."
if systemctl start xmesh-xray-sync.service; then
 echo "Xray synchronization completed. Managed container:"
 docker ps --filter name=xmesh-managed-xray --format '{{.Names}}: {{.Status}}'
else
 echo "ERROR: Xray profile was NOT applied. XMesh router remains installed." >&2
 journalctl -u xmesh-xray-sync.service -n 35 --no-pager >&2 || true
 echo "Fix the error above, then run: systemctl start xmesh-xray-sync.service" >&2
 exit 1
fi
echo "Xray desired-state sync installed and first run completed."

echo "Node enrolled. Router TCP listener configured for :$NODE_PORT (verify docker compose ps and ss -ltn)."
