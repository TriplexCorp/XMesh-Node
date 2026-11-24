#!/usr/bin/env bash
# XMesh Node v6 fresh installer. Security invariant:
# NO router, Xray, metrics, control or reconciliation runtime may start until
# the strict-PQ product client has verified a durable activation receipt.
set -Eeuo pipefail
umask 077
export LC_ALL=C

if [[ $EUID -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || { echo "Run as root (sudo is unavailable)." >&2; exit 1; }
  exec sudo --preserve-env=XMESH_NODE_RELEASE_REF,XMESH_NEXUS_RELEASE_REF,XMESH_QUOTA_V2_METERED_INSTALL,XMESH_QUOTA_V2_WAL_STAGE_AGENT,XMESH_QUOTA_V2_AUTO_RENEW_STAGING bash "$0" "$@"
fi
if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "Usage: XMESH_NODE_RELEASE_REF=<40-hex-reviewed-sha> bash bootstrap.sh https://panel.example.com NODE_ID [node-port]" >&2
  exit 2
fi

RELEASE_REF="${XMESH_NODE_RELEASE_REF:-}"
[[ "$RELEASE_REF" =~ ^[0-9a-f]{40}$ ]] || {
  echo "XMESH_NODE_RELEASE_REF must be the exact reviewed 40-hex XMesh-Node release SHA." >&2
  exit 2
}

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

# A cold install replaces systemd units and re-enrolls the Node. With a
# signed spending ledger that operation needs an explicit migration path.
for quota_evidence in /var/lib/xmesh-xray-sync/{genesis-quarantine-envelope.json,genesis-reservation-prepared-u*.json,genesis-reservation-confirmed-u*.json,genesis-positive-cap-u*.json,genesis-renewal-u*.json,genesis-renewal-request-u*.json,calendar-*-u*.json,wal-cap-u*.json,wal-charge-*.json,ingress-u*,xmesh-quota-u*}; do
  if [[ -e "$quota_evidence" || -L "$quota_evidence" ]]; then
    echo "Quota V2 spending state exists; cold bootstrap is blocked before changing the installed Agent." >&2
    exit 2
  fi
done

apt_get() { DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 "$@"; }
command -v apt-get >/dev/null 2>&1 || { echo "Automatic bootstrap supports Ubuntu with apt only." >&2; exit 1; }
[[ -r /etc/os-release ]] || { echo "Cannot detect host OS." >&2; exit 1; }
. /etc/os-release
[[ "${ID:-}" == ubuntu ]] || { echo "Automatic bootstrap supports Ubuntu only." >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required." >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive
apt_get update
# Certbot is a bootstrap dependency, not a reconciliation dependency. The
# hardened xmesh-xray-sync.service cannot and must not invoke apt/dpkg itself.
apt_get install -y ca-certificates curl gnupg git python3 openssl coreutils util-linux certbot
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl --proto '=https' --tlsv1.2 -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  arch="$(dpkg --print-architecture)"
  case "$arch" in amd64|arm64|armhf|s390x|ppc64el) ;; *) echo "Unsupported Docker architecture: $arch" >&2; exit 1;; esac
  printf 'deb [arch=%s signed-by=%s] https://download.docker.com/linux/ubuntu %s stable\n' \
    "$arch" /etc/apt/keyrings/docker.asc "$VERSION_CODENAME" > /etc/apt/sources.list.d/docker.list
  apt_get update
  apt_get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
docker info >/dev/null
docker compose version >/dev/null

# Runtime source/config lives outside /root because the reconciliation service
# intentionally uses ProtectHome=true. Reusing a historical /root checkout
# makes the router bind-mounted config invisible to that sandbox and prevents
# the first desired-config reconciliation from remounting the router safely.
INSTALL_DIR=/opt/xmesh-node
if [[ ! -d "$INSTALL_DIR/.git" ]]; then
  rm -rf "$INSTALL_DIR"
  git clone --filter=blob:none --no-checkout https://github.com/TriplexCorp/XMesh-Node.git "$INSTALL_DIR"
fi
# A v6 product install never consumes moving main. Fetch and detach at the
# exact release SHA supplied by the authenticated panel command.
git -C "$INSTALL_DIR" fetch --force --depth 1 origin "$RELEASE_REF"
git -C "$INSTALL_DIR" checkout --detach --force FETCH_HEAD
NODE_RELEASE_SHA="$(git -C "$INSTALL_DIR" rev-parse HEAD)"
[[ "$NODE_RELEASE_SHA" == "$RELEASE_REF" ]] || {
  echo "Refusing unpinned Node source: checkout SHA does not match XMESH_NODE_RELEASE_REF." >&2
  exit 1
}
[[ "$(tr -d '\r\n' < "$INSTALL_DIR/VERSION")" == "6.0.0" ]] || {
  echo "Fresh strict-PQ bootstrap requires XMesh Node v6.0.0." >&2; exit 1;
}
AGENT_VERSION="$(tr -d '\r\n' < "$INSTALL_DIR/AGENT_VERSION")"
METERED_INSTALL="${XMESH_QUOTA_V2_METERED_INSTALL:-0}"
[[ "$METERED_INSTALL" == 0 || "$METERED_INSTALL" == 1 ]] || { echo "Invalid metered Xray install mode." >&2; exit 2; }
WAL_STAGE_AGENT="${XMESH_QUOTA_V2_WAL_STAGE_AGENT:-0}"
WAL_AUTO_RENEW="${XMESH_QUOTA_V2_AUTO_RENEW_STAGING:-0}"
if [[ "$WAL_AUTO_RENEW" != 0 && "$WAL_AUTO_RENEW" != 1 ]];then
  echo "Invalid quota auto renewal staging flag" >&2;exit 2
fi
if [[ "$WAL_AUTO_RENEW" == 1 && ( "$WAL_STAGE_AGENT" != 1 || "$AGENT_VERSION" != control-v6.0.31 ) ]];then
  echo "Quota auto renewal requires the explicit control-v6.0.31 WAL staging Agent." >&2;exit 2
fi
if [[ "$AGENT_VERSION" == control-v6.0.31 && ! "${XMESH_NEXUS_RELEASE_REF:-}" =~ ^[a-f0-9]{40}$ ]];then
  echo "control-v6.0.31 requires an exact Nexus release revision." >&2
  exit 2
fi
if [[ "$WAL_STAGE_AGENT" != 0 || "$AGENT_VERSION" == control-v6.0.25 ]];then
  if [[ ( "$AGENT_VERSION" != control-v6.0.25 && "$AGENT_VERSION" != control-v6.0.31 ) || "$WAL_STAGE_AGENT" != 1 ||
        ! "${XMESH_NEXUS_RELEASE_REF:-}" =~ ^[a-f0-9]{40}$ ]];then
    echo "Experimental WAL/Genesis Agent requires explicit staging and an exact Nexus revision." >&2
    exit 2
  fi
  for path in /usr/local/sbin/xmesh-node-control /etc/systemd/system/xmesh-node-control.{service,timer};do
    [[ ! -e "$path" && ! -L "$path" ]] || {
      echo "WAL staging requires a fresh test node without an existing control worker." >&2; exit 2
    }
  done
fi

# A bound product must prove the candidate is byte-identical BEFORE we
# disable any working services. The direct installer is an exact no-op on
# an enrolled artifact; it refuses an uncoordinated identity replacement.
source "$INSTALL_DIR/deploy/xmesh-pq-install-guard.sh"
# A verified artifact is still not authorization to serve traffic. Keep the
# metering installation path isolated until lease and ingress units can take
# ownership of the data plane without a legacy Xray fallback.
if [[ "$METERED_INSTALL" == 1 ]]; then
  [[ "$WAL_STAGE_AGENT" == 0 && "$WAL_AUTO_RENEW" == 0 ]] || exit 2
  xmesh_refuse_quota_cold_install /var/lib/xmesh-xray-sync
  if docker inspect xmesh-node >/dev/null 2>&1 ||
      docker inspect xmesh-managed-xray >/dev/null 2>&1; then
    echo "Metered Xray first installation requires a clean node." >&2
    exit 2
  fi
  bash "$INSTALL_DIR/deploy/install-metered-xray.sh" "${XMESH_NEXUS_RELEASE_REF:?}"
else
  xmesh_refuse_metered_legacy_install
fi

xmesh_refuse_quota_cold_install /var/lib/xmesh-xray-sync
PRODUCT_PREINSTALLED=0
PRODUCT_ACTIVATION_STATE=fresh
if xmesh_product_binding_exists /var/lib/xmesh-agent/product; then
  bash "$INSTALL_DIR/deploy/install-xsp-v2-product-client.sh" "$NODE_RELEASE_SHA"
  PRODUCT_PREINSTALLED=1
  # This must complete before ANY running services are stopped.
  PRODUCT_ACTIVATION_STATE="$(xmesh_verify_or_resume_enrolled_product /var/lib/xmesh-agent/product /usr/local/bin/xmesh-agent-xspv2-product "$PANEL" "$NODE")"
fi
echo "XMesh Node reviewed revision: $NODE_RELEASE_SHA"
echo "Enforcing pre-activation fail-closed state..."
# An upgrade/retry must never leave an older managed runtime serving while the
# new v6 identity is not yet PQ-active. Unknown/unmanaged containers are not touched.
for unit in \
  xmesh-node-metrics.timer xmesh-node-metrics.service \
  xmesh-node-control.timer xmesh-node-control.service \
  xmesh-xray-sync.timer xmesh-xray-sync.service \
  xmesh-quota-v2-renewal.timer xmesh-quota-v2-renewal.service \
  xmesh-node-user-meter.timer xmesh-node-user-meter.service \
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
if [[ "$PRODUCT_PREINSTALLED" == 0 ]]; then
  bash "$INSTALL_DIR/deploy/install-xsp-v2-product-client.sh" "$NODE_RELEASE_SHA"
fi
PRODUCT=/usr/local/bin/xmesh-agent-xspv2-product
[[ -x "$PRODUCT" ]] || { echo "strict-PQ product client installation failed." >&2; exit 1; }

if [[ "$PRODUCT_ACTIVATION_STATE" == active || "$PRODUCT_ACTIVATION_STATE" == resumed ]]; then
  echo "Existing original strict-PQ activation receipt verified or recovered."
else
  [[ "$PRODUCT_ACTIVATION_STATE" == fresh ]] || { echo "Invalid PQ activation state" >&2; exit 2; }
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
if [[ "$METERED_INSTALL" == 1 ]]; then
  exec bash "$INSTALL_DIR/deploy/install-metered-services.sh" "$PANEL" "$NODE"
fi

# Persist only non-secret product coordinates for root-owned service units.
install -d -o root -g root -m 0700 /etc/xmesh-node
cat > /etc/xmesh-node/product.env <<EOF
XMESH_API_URL=$PANEL
XMESH_NODE_ID=$NODE
XMESH_STRICT_PQ_REQUIRED=1
XMESH_NODE_RELEASE_REF=$NODE_RELEASE_SHA
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

# Keep Xray stopped until the first strict-PQ desired-config reconciliation.
if docker inspect xmesh-managed-xray >/dev/null 2>&1; then
  docker update --restart=no xmesh-managed-xray >/dev/null 2>&1 || true
  docker stop -t 5 xmesh-managed-xray >/dev/null 2>&1 || true
fi

# Installs metrics/control/Xray reconciliation with a PATH-scoped transport
# adapter. Their panel POST cannot reach classical HTTPS; the adapter invokes
# the product client, which re-verifies the durable PQ receipt on every call.
bash "$INSTALL_DIR/deploy/install-v6-strict-operational-agents.sh" "$PANEL" "$NODE" auto

# Final installation proof is local and cryptographic, not inferred from
# service names or containers.
"$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null
systemctl is-enabled --quiet xmesh-xray-sync.timer
systemctl is-enabled --quiet xmesh-node-metrics.timer
if [[ "$WAL_STAGE_AGENT" == 0 ]];then
  systemctl is-enabled --quiet xmesh-node-control.timer
else
  if systemctl is-enabled --quiet xmesh-node-control.timer ||
     systemctl is-active --quiet xmesh-node-control.service;then
    echo "Independent control worker must stay disabled on a WAL staging Node." >&2
    exit 1
  fi
  echo "Staged WAL qualification services installed; cold Xray remains stopped."
fi

echo
echo "XMesh Node v6.0.0 POSTQUANTUM installation complete."
echo "strictPQEnabled=true; automaticClassicalFallback=false."
echo "Router and operational agents were started only after verified PQ activation."
echo "Managed Xray is started only by a desired-config reconciliation transported through strict-PQ."
