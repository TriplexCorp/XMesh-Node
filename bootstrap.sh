#!/usr/bin/env bash
# XMesh Node v6 fresh installer. Security invariant:
# NO router, Xray, metrics, control or reconciliation runtime may start until
# the strict-PQ product client has verified a durable activation receipt.
set -Eeuo pipefail
umask 077
export LC_ALL=C

if [[ $EUID -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || { echo "Run as root (sudo is unavailable)." >&2; exit 1; }
  exec sudo bash "$0" "$@"
fi
if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: bash bootstrap.sh https://panel.example.com NODE_ID [node-port]" >&2
  exit 2
fi

PANEL="${1%/}"
NODE="$2"
SUGGESTED_PORT="${3:-8443}"
[[ "$PANEL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || { echo "Expected HTTPS panel origin." >&2; exit 2; }
[[ "$NODE" =~ ^[1-9][0-9]*$ ]] || { echo "Invalid node ID." >&2; exit 2; }
[[ "$SUGGESTED_PORT" =~ ^[0-9]{1,5}$ ]] && (( 10#$SUGGESTED_PORT >= 1 && 10#$SUGGESTED_PORT <= 65535 )) || {
  echo "Invalid suggested node port." >&2; exit 2;
}
if [[ -t 0 ]]; then
  read -r -p "TCP port for XMesh Node [$SUGGESTED_PORT]: " INPUT_PORT
  NODE_PORT="${INPUT_PORT:-$SUGGESTED_PORT}"
else
  NODE_PORT="$SUGGESTED_PORT"
fi
[[ "$NODE_PORT" =~ ^[0-9]{1,5}$ ]] && (( 10#$NODE_PORT >= 1 && 10#$NODE_PORT <= 65535 )) || {
  echo "Port must be 1-65535." >&2; exit 2;
}
NODE_PORT="$((10#$NODE_PORT))"

apt_get() { DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 "$@"; }
command -v apt-get >/dev/null 2>&1 || { echo "Automatic bootstrap supports Ubuntu with apt only." >&2; exit 1; }
[[ -r /etc/os-release ]] || { echo "Cannot detect host OS." >&2; exit 1; }
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || { echo "Automatic bootstrap supports Ubuntu only." >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required." >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt_get update
apt_get install -y ca-certificates curl gnupg git python3 openssl coreutils util-linux
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl --proto '=https' --tlsv1.2 -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  arch="$(dpkg --print-architecture)"
  case "$arch" in amd64|arm64|armhf|s390x|ppc64el) ;; *) echo "Unsupported Docker architecture: $arch" >&2; exit 1;; esac
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$arch" "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
  apt_get update
  apt_get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
docker info >/dev/null
docker compose version >/dev/null

INSTALL_DIR=/opt/xmesh-node
if [[ -d /root/XMesh-Node/.git ]]; then INSTALL_DIR=/root/XMesh-Node; fi
if [[ ! -d "$INSTALL_DIR/.git" ]]; then
  git clone --depth 1 https://github.com/TriplexCorp/XMesh-Node.git "$INSTALL_DIR"
else
  git -C "$INSTALL_DIR" pull --ff-only
fi
NODE_RELEASE_SHA="$(git -C "$INSTALL_DIR" rev-parse HEAD)"
[[ "$NODE_RELEASE_SHA" =~ ^[0-9a-f]{40}$ ]] || { echo "Invalid Node release SHA." >&2; exit 1; }
[[ "$(tr -d '\r\n' < "$INSTALL_DIR/VERSION")" == "6.0.0" ]] || {
  echo "Fresh strict-PQ bootstrap requires XMesh Node v6.0.0." >&2; exit 1;
}

echo "XMesh Node revision: $NODE_RELEASE_SHA"
echo "Enforcing pre-activation fail-closed state..."
# An upgrade/retry must never leave an older managed runtime serving while the
# new v6 identity is not yet PQ-active. Unknown/unmanaged containers are not touched.
for unit in \
  xmesh-node-metrics.timer xmesh-node-metrics.service \
  xmesh-node-control.timer xmesh-node-control.service \
  xmesh-xray-sync.timer xmesh-xray-sync.service \
  xmesh-node-tls-renew.timer xmesh-node-tls-renew.service \
  xmesh-geodata-sync.timer xmesh-geodata-sync.service; do
  systemctl disable --now "$unit" >/dev/null 2>&1 || true
done
for container in xmesh-node xmesh-managed-xray; do
  if docker inspect "$container" >/dev/null 2>&1; then
    docker update --restart=no "$container" >/dev/null 2>&1 || true
    docker stop -t 5 "$container" >/dev/null 2>&1 || true
  fi
done

# Install the product client before consuming the short-lived owner token.
bash "$INSTALL_DIR/deploy/install-xsp-v2-product-client.sh" "$NODE_RELEASE_SHA"
PRODUCT=/usr/local/bin/xmesh-agent-xspv2-product
[[ -x "$PRODUCT" ]] || { echo "strict-PQ product client installation failed." >&2; exit 1; }

if "$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null 2>&1; then
  echo "Existing strict-PQ activation receipt verified."
else
  [[ -r /dev/tty ]] || { echo "Interactive TTY required for secure one-time enrollment token entry." >&2; exit 1; }
  TOKEN_FILE="$(mktemp /run/xmesh-v6-enroll.XXXXXXXX)"
  chmod 0600 "$TOKEN_FILE"
  cleanup_token() {
    if [[ -f "$TOKEN_FILE" ]]; then
      command -v shred >/dev/null 2>&1 && shred -u "$TOKEN_FILE" 2>/dev/null || rm -f "$TOKEN_FILE"
    fi
  }
  trap cleanup_token EXIT
  printf 'Paste the one-time v6 strict-PQ enrollment token (input hidden): ' > /dev/tty
  IFS= read -r -s TOKEN < /dev/tty
  printf '\n' > /dev/tty
  [[ "$TOKEN" =~ ^[0-9a-f]{64}$ ]] || { unset TOKEN; echo "Invalid enrollment token." >&2; exit 2; }
  printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
  unset TOKEN

  echo "Performing owner-authorized dual-key enrollment and hybrid PQ activation..."
  "$PRODUCT" bootstrap --panel "$PANEL" --node-id "$NODE" --token-file "$TOKEN_FILE"
  cleanup_token
  trap - EXIT
fi

# This is THE gate. Nothing operational appears above this line.
"$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null
[[ -s /var/lib/xmesh-agent/product/active.json ]] || { echo "Missing durable strict-PQ active state." >&2; exit 1; }
python3 - /var/lib/xmesh-agent/product/active.json "$NODE" <<'PY'
import json,sys
with open(sys.argv[1],encoding='utf-8') as f: state=json.load(f)
assert state.get('schema')=='xmesh-v6-strict-pq-active-1'
assert state.get('nodeId')==int(sys.argv[2])
assert state.get('productionActivation') is True
assert state.get('strictPQEnabled') is True
assert state.get('automaticClassicalFallback') is False
PY
echo "STRICT-PQ GATE PASSED: productionActivation=true strictPQEnabled=true fallback=false"

# Persist only non-secret product coordinates for root-owned service units.
install -d -o root -g root -m 0700 /etc/xmesh-node
cat > /etc/xmesh-node/product.env <<EOF
XMESH_API_URL=$PANEL
XMESH_NODE_ID=$NODE
XMESH_STRICT_PQ_REQUIRED=1
EOF
chmod 0600 /etc/xmesh-node/product.env

cd "$INSTALL_DIR"
if [[ -f config.json ]]; then
  python3 - config.json "$NODE_PORT" <<'PY'
import json,os,sys,tempfile
path=sys.argv[1]; requested=':'+sys.argv[2]
with open(path,encoding='utf-8') as f: data=json.load(f)
if not isinstance(data,dict): raise SystemExit('config.json must contain an object')
data['listen_tcp']=requested
data.pop('panel_url',None); data.pop('node_id',None); data.pop('private_key_file',None)
if not data.get('default_tcp'): data['default_tcp']='127.0.0.1:9443'
fd,tmp=tempfile.mkstemp(prefix='.config.',dir='.')
try:
 with os.fdopen(fd,'w',encoding='utf-8') as f:
  json.dump(data,f,indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
 os.replace(tmp,path)
finally:
 try: os.unlink(tmp)
 except FileNotFoundError: pass
PY
else
  python3 - "$NODE_PORT" <<'PY'
import json,sys
config={"listen_tcp":":"+sys.argv[1],"listen_udp":"","default_tcp":"127.0.0.1:9443","routes":[],
        "hello_timeout_seconds":5,"idle_timeout_seconds":120,"max_tcp_connections":4096,"max_udp_sessions":2048}
with open('config.json','w',encoding='utf-8') as f: json.dump(config,f,indent=2); f.write('\n')
PY
fi
chmod 0644 config.json

# Router startup is intentionally after the strict-PQ gate.
docker compose build
docker compose run --rm --no-deps xmesh-node -check -config /etc/xmesh-node/config.json
docker compose up -d --no-build
if [[ "$(docker inspect -f '{{.State.Running}}' xmesh-node 2>/dev/null || true)" != true ]]; then
  echo "XMesh router failed to start after PQ activation." >&2
  exit 1
fi

# Keep Xray stopped until the v6 strict-PQ reconciliation agent has fetched and
# verified a policy over the product tunnel. There is deliberately no legacy
# direct-HTTPS fallback in this installer.
if docker inspect xmesh-managed-xray >/dev/null 2>&1; then
  docker update --restart=no xmesh-managed-xray >/dev/null 2>&1 || true
  docker stop -t 5 xmesh-managed-xray >/dev/null 2>&1 || true
fi

echo
echo "XMesh Node v6 strict-PQ bootstrap gate complete."
echo "Router started only after verified PQ activation receipt."
echo "Managed Xray and operational agents remain fail-closed until strict-PQ reconciliation is installed."
echo "No classical operational fallback was enabled."
