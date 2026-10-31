#!/usr/bin/env bash
# Install v6 operational workers only after strict-PQ activation. Existing
# worker business logic is preserved, but their only `curl` is shadowed by a
# narrow adapter that can communicate with Nexus solely through the product
# XSP/2 hybrid/dual-signature tunnel.
set -Eeuo pipefail
umask 077
export LC_ALL=C

[[ "$EUID" -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
[[ $# -ge 2 && $# -le 3 ]] || { echo "Usage: $0 https://panel.example.com NODE_ID [interface]" >&2; exit 2; }
PANEL="${1%/}"
NODE="$2"
INTERFACE="${3:-auto}"
[[ "$PANEL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || exit 2
[[ "$NODE" =~ ^[1-9][0-9]*$ ]] || exit 2
[[ "$INTERFACE" == auto || "$INTERFACE" =~ ^[A-Za-z0-9_.:-]+$ ]] || exit 2

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
[[ "$(tr -d '\r\n' < "$ROOT/VERSION")" == "6.0.0" ]] || { echo "XMesh Node v6.0.0 required" >&2; exit 1; }
PRODUCT=/usr/local/bin/xmesh-agent-xspv2-product
[[ -x "$PRODUCT" ]] || { echo "strict-PQ product client missing" >&2; exit 1; }
"$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null || {
  echo "strict-PQ activation receipt is not valid; operational agents will not be installed" >&2
  exit 1
}

for command in curl openssl python3 systemctl docker install; do
  command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 1; }
done

install -d -o root -g root -m 0755 /usr/local/libexec /usr/local/libexec/xmesh-strict-pq-bin
install -o root -g root -m 0700 "$ROOT/deploy/xmesh-strict-pq-curl.sh" /usr/local/libexec/xmesh-strict-pq-curl
ln -sfn /usr/local/libexec/xmesh-strict-pq-curl /usr/local/libexec/xmesh-strict-pq-bin/curl

# Helpers are taken from the exact checked-out Node release.
for helper in xmesh-policy-guard.py xmesh-profile-attest.py xmesh-geodata-sync.py xmesh-tls-provision.py xmesh-tls-status.py; do
  [[ -f "$ROOT/deploy/$helper" && ! -L "$ROOT/deploy/$helper" ]] || { echo "missing Node helper: $helper" >&2; exit 1; }
  python3 -m py_compile "$ROOT/deploy/$helper"
  install -o root -g root -m 0700 "$ROOT/deploy/$helper" "/usr/local/libexec/$helper"
done
install -o root -g root -m 0700 "$ROOT/deploy/xmesh-xray-sync.sh" /usr/local/sbin/xmesh-xray-sync
if [[ -f "$ROOT/deploy/xmesh-tls-renew-hook.sh" ]]; then
  install -o root -g root -m 0700 "$ROOT/deploy/xmesh-tls-renew-hook.sh" /usr/local/libexec/xmesh-tls-renew-hook
fi

# Metrics/control implementations live with Nexus. During branch integration a
# reviewed ref may be supplied explicitly; production defaults to main.
NEXUS_REF="${XMESH_NEXUS_RELEASE_REF:-main}"
[[ "$NEXUS_REF" =~ ^[A-Za-z0-9._/-]{1,160}$ && "$NEXUS_REF" != *..* && "$NEXUS_REF" != /* ]] || {
  echo "invalid XMESH_NEXUS_RELEASE_REF" >&2; exit 2;
}
RAW="https://raw.githubusercontent.com/TriplexCorp/XMesh-Nexus/$NEXUS_REF/deploy"
fetch_install(){
  local remote="$1" target="$2" mode="$3" tmp
  tmp="$(mktemp /tmp/xmesh-v6-agent.XXXXXXXX)"
  trap 'rm -f "$tmp"' RETURN
  /usr/bin/curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --max-time 30 "$RAW/$remote" -o "$tmp"
  case "$remote" in *.sh) bash -n "$tmp";; *.py) python3 -m py_compile "$tmp";; esac
  install -o root -g root -m "$mode" "$tmp" "$target"
  rm -f "$tmp"
  trap - RETURN
}
fetch_install node-metrics-agent.sh /usr/local/sbin/xmesh-node-metrics 0700
fetch_install node-control-agent.sh /usr/local/sbin/xmesh-node-control 0700
fetch_install xray-stats-collector.py /usr/local/libexec/xmesh-xray-stats-collector.py 0700

grep -Fq '/api/v1/metrics/ingest' /usr/local/sbin/xmesh-node-metrics || { echo "invalid metrics worker" >&2; exit 1; }
grep -Fq 'AGENT_VERSION="control-v6.0.0"' /usr/local/sbin/xmesh-node-control || { echo "invalid control worker" >&2; exit 1; }

install -d -o root -g root -m 0700 /etc/xmesh-node-metrics /var/lib/xmesh-node-metrics /var/lib/xmesh-node-control /var/lib/xmesh-xray-sync
cat > /etc/xmesh-node-metrics.env <<EOF
XMESH_API_URL=$PANEL
XMESH_NODE_ID=$NODE
XMESH_STRICT_PQ_REQUIRED=1
XMESH_METRICS_PRIVATE_KEY=/etc/xmesh-node-metrics/node.key
XMESH_INTERFACE=$INTERFACE
XMESH_XRAY_API_ADDRESS=127.0.0.1:10085
XMESH_XRAY_UNIT=xray.service
XMESH_AUTONOMOUS_POLICY=1
EOF
chmod 0600 /etc/xmesh-node-metrics.env

# Existing workers still build their historical Ed25519 header locally before
# invoking curl. The adapter discards those headers and sends no XMESH1 bytes
# over the network. This compatibility key is deliberately NOT enrolled as a
# Nexus credential and therefore cannot authorize a direct/classical request.
COMPAT_KEY=/etc/xmesh-node-metrics/node.key
if [[ ! -e "$COMPAT_KEY" ]]; then
  openssl genpkey -algorithm Ed25519 -out "$COMPAT_KEY"
fi
chown root:root "$COMPAT_KEY"
chmod 0600 "$COMPAT_KEY"
printf 'local-only; network authorization is strict XSP/2 PQ product transport\n' > /etc/xmesh-node-metrics/compatibility-key-purpose
chmod 0600 /etc/xmesh-node-metrics/compatibility-key-purpose

STRICT_PATH=/usr/local/libexec/xmesh-strict-pq-bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
cat > /etc/systemd/system/xmesh-xray-sync.service <<EOF
[Unit]
Description=XMesh v6 strict-PQ managed Xray reconciliation
After=network-online.target docker.service
Wants=network-online.target docker.service
ConditionPathExists=/var/lib/xmesh-agent/product/active.json
[Service]
Type=oneshot
EnvironmentFile=/etc/xmesh-node-metrics.env
Environment="PATH=$STRICT_PATH"
ExecStart=/usr/local/sbin/xmesh-xray-sync
User=root
Group=root
UMask=0077
TimeoutStartSec=180s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
# The reconciler atomically replaces the router's bind-mounted config.json and
# may force-recreate the router from its reviewed Compose directory. Keep the
# host filesystem read-only everywhere else; no other operational unit receives
# write access to the Node checkout.
ReadWritePaths=/run /var/lib/xmesh-xray-sync /var/lib/xmesh-node-control /opt/xmesh-node -/etc/letsencrypt
EOF
cat > /etc/systemd/system/xmesh-xray-sync.timer <<'EOF'
[Unit]
Description=Reconcile XMesh v6 Xray policy over strict-PQ transport
[Timer]
OnBootSec=5s
OnUnitInactiveSec=20s
AccuracySec=2s
Persistent=true
Unit=xmesh-xray-sync.service
[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/xmesh-node-metrics.service <<EOF
[Unit]
Description=XMesh v6 metrics over strict-PQ product transport
After=network-online.target
Wants=network-online.target
ConditionPathExists=/var/lib/xmesh-agent/product/active.json
[Service]
Type=oneshot
EnvironmentFile=/etc/xmesh-node-metrics.env
Environment="PATH=$STRICT_PATH"
ExecStart=/usr/local/sbin/xmesh-node-metrics
User=root
Group=root
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectHostname=true
ProtectClock=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/run /var/lib/xmesh-node-metrics
EOF
cat > /etc/systemd/system/xmesh-node-metrics.timer <<'EOF'
[Unit]
Description=Send XMesh v6 strict-PQ metrics every five seconds
[Timer]
OnBootSec=5s
OnUnitInactiveSec=5s
AccuracySec=1s
Persistent=true
Unit=xmesh-node-metrics.service
[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/xmesh-node-control.service <<EOF
[Unit]
Description=XMesh v6 control over strict-PQ product transport
After=network-online.target docker.service
Wants=network-online.target docker.service
ConditionPathExists=/var/lib/xmesh-agent/product/active.json
[Service]
Type=oneshot
EnvironmentFile=/etc/xmesh-node-metrics.env
Environment="PATH=$STRICT_PATH"
ExecStart=/usr/local/sbin/xmesh-node-control
User=root
Group=root
UMask=0077
TimeoutStartSec=175s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectHostname=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=/run /var/lib/xmesh-node-control -/var/lib/xmesh-xray-sync
EOF
cat > /etc/systemd/system/xmesh-node-control.timer <<'EOF'
[Unit]
Description=Poll XMesh v6 control commands over strict-PQ transport
[Timer]
OnBootSec=7s
OnUnitInactiveSec=7s
AccuracySec=1s
Persistent=true
Unit=xmesh-node-control.service
[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/xmesh-node-user-meter.service <<'EOF'
[Unit]
Description=XMesh verified per-user Xray traffic sampler
After=docker.service
Wants=docker.service
ConditionPathExists=/var/lib/xmesh-agent/product/active.json
[Service]
Type=oneshot
EnvironmentFile=/etc/xmesh-node-metrics.env
ExecStart=/usr/bin/python3 /usr/local/libexec/xmesh-policy-guard.py sample --state /var/lib/xmesh-xray-sync --node-id ${XMESH_NODE_ID}
User=root
Group=root
UMask=0077
TimeoutStartSec=20s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectHostname=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=/run /var/lib/xmesh-xray-sync
EOF
cat > /etc/systemd/system/xmesh-node-user-meter.timer <<'EOF'
[Unit]
Description=Sample Xray per-user traffic every ten seconds
[Timer]
OnBootSec=10s
OnUnitInactiveSec=10s
AccuracySec=1s
Unit=xmesh-node-user-meter.service
[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload

# Re-check the exact durable receipt immediately before first operational I/O.
"$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null
# First reconciliation is synchronous. If there is no profile yet it exits
# cleanly while leaving Xray stopped; any auth/transport/policy failure aborts.
systemctl start xmesh-xray-sync.service
# First metrics run establishes a baseline and performs no unsafe fallback.
systemctl start xmesh-node-metrics.service || true
systemctl start xmesh-node-control.service || true

systemctl enable --now xmesh-xray-sync.timer xmesh-node-metrics.timer xmesh-node-control.timer xmesh-node-user-meter.timer

echo "XMesh v6 operational agents installed behind strict-PQ-only transport."
echo "Direct operational HTTPS is not configured; all panel POSTs traverse the product tunnel."
