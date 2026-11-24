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
AGENT_VERSION_FILE="$ROOT/AGENT_VERSION"
[[ -f "$AGENT_VERSION_FILE" && ! -L "$AGENT_VERSION_FILE" ]] || { echo "AGENT_VERSION file missing" >&2; exit 1; }
AGENT_VERSION="$(tr -d '\r\n' < "$AGENT_VERSION_FILE")"
[[ "$AGENT_VERSION" =~ ^control-v6\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid Agent release version: $AGENT_VERSION" >&2; exit 1; }
WAL_STAGE_AGENT="${XMESH_QUOTA_V2_WAL_STAGE_AGENT:-0}"
WAL_AUTO_RENEW="${XMESH_QUOTA_V2_AUTO_RENEW_STAGING:-0}"
if [[ "$WAL_AUTO_RENEW" != 0 && "$WAL_AUTO_RENEW" != 1 ]]; then
  echo "Invalid staged automatic renewal flag" >&2; exit 2
fi
if [[ "$WAL_AUTO_RENEW" == 1 && ( "$WAL_STAGE_AGENT" != 1 || "$AGENT_VERSION" != control-v6.0.27 ) ]]; then
  echo "Automatic quota renewal requires the exact opt-in WAL staging Agent." >&2; exit 2
fi
if [[ "$WAL_AUTO_RENEW" == 0 ]]; then
  for quota_evidence in /var/lib/xmesh-xray-sync/{genesis-quarantine-envelope.json,genesis-reservation-prepared-u*.json,genesis-reservation-confirmed-u*.json,genesis-positive-cap-u*.json,genesis-renewal-u*.json,genesis-renewal-request-u*.json,calendar-*-u*.json,wal-cap-u*.json,wal-charge-*.json,ingress-u*,xmesh-quota-u*}; do
    if [[ -e "$quota_evidence" || -L "$quota_evidence" ]]; then
      echo "Quota V2 spending state exists; refusing to replace installed renewal services." >&2
      exit 2
    fi
  done
fi
NEXUS_REF="${XMESH_NEXUS_RELEASE_REF:-main}"
[[ "$NEXUS_REF" =~ ^[A-Za-z0-9._/-]{1,160}$ && "$NEXUS_REF" != *..* && "$NEXUS_REF" != /* ]] || {
  echo "invalid XMESH_NEXUS_RELEASE_REF" >&2; exit 2;
}
if [[ "$AGENT_VERSION" == control-v6.0.27 && ! "$NEXUS_REF" =~ ^[a-f0-9]{40}$ ]];then
  echo "control-v6.0.27 requires an exact Nexus release revision." >&2; exit 2
fi
if [[ "$AGENT_VERSION" == control-v6.0.25 || "$WAL_STAGE_AGENT" != 0 ]];then
  if [[ ( "$AGENT_VERSION" != control-v6.0.25 && "$AGENT_VERSION" != control-v6.0.27 ) || "$WAL_STAGE_AGENT" != 1 || ! "$NEXUS_REF" =~ ^[a-f0-9]{40}$ ]];then
    echo "Experimental WAL/Genesis Agent requires isolated staging and an exact Nexus revision." >&2; exit 2
  fi
fi
if [[ "$WAL_STAGE_AGENT" == 1 ]];then
  for path in /usr/local/sbin/xmesh-node-control /etc/systemd/system/xmesh-node-control.{service,timer};do
    [[ ! -e "$path" && ! -L "$path" ]] || {
      echo "WAL staging requires a fresh test node without an existing control worker." >&2; exit 2
    }
  done
fi

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

# Helpers are taken from the exact checked-out Node release. The policy wrapper,
# its reviewed base, profile attester and hot-user reconciler are installed
# together so runtime does not depend on the source checkout after bootstrap.
for helper in xmesh-policy-guard.py xmesh-policy-guard-base.py xmesh-quota-revocation-marker.py xmesh-profile-attest.py xmesh-hot-user-reconcile.py xmesh-geodata-sync.py xmesh-tls-provision.py xmesh-tls-status.py xmesh-xray-update.py; do
  [[ -f "$ROOT/deploy/$helper" && ! -L "$ROOT/deploy/$helper" ]] || { echo "missing Node helper: $helper" >&2; exit 1; }
  python3 -m py_compile "$ROOT/deploy/$helper"
  install -o root -g root -m 0700 "$ROOT/deploy/$helper" "/usr/local/libexec/$helper"
done
install -o root -g root -m 0700 "$ROOT/deploy/xmesh-xray-sync.sh" /usr/local/sbin/xmesh-xray-sync
# Install the nonauthorizing WAL operator command beside its reviewed modules.
# The optional systemd environment file enables staged WAL verification.
WAL_ROOT=/usr/local/libexec/xmesh-quota-wal
for family in quota-v2-physical-stop xray-dataplane-fence; do
  install -d -o root -g root -m 0700 "$WAL_ROOT/$family"
done
for helper in quota-v2-physical-stop/{wal_transport,quarantine_policy,genesis_reservation,first_cap_handoff,cap_install,renewal_worker,calendar_fence,successor_meter,successor_positive,vless_ingress,charge_worker,witness_inventory,verify_nexus_wal_anchor,journal_integrity,meter_inventory_audit} xray-dataplane-fence/{sign_observation,runtime_identity,meter_floor}; do
  python3 -m py_compile "$ROOT/experiments/$helper.py"
  install -o root -g root -m 0700 "$ROOT/experiments/$helper.py" "$WAL_ROOT/$helper.py"
done
ln -sfn "$WAL_ROOT/quota-v2-physical-stop/wal_transport.py" /usr/local/sbin/xmesh-quota-wal
# Expose the opt-in ZERO-AUTHORITY first-Genesis handoff alongside the already
# reviewed WAL operator. It does not run automatically, open ingress, install
# any cap or alter the existing systemd Xray synchronizer.
ln -sfn "$WAL_ROOT/quota-v2-physical-stop/quarantine_policy.py" /usr/local/sbin/xmesh-quota-genesis-quarantine
# First-Genesis SQL lease helper is zero-authority and intentionally opt-in.
# The positive signed-cap verifier is installed as a library, not a daemon.
ln -sfn "$WAL_ROOT/quota-v2-physical-stop/genesis_reservation.py" /usr/local/sbin/xmesh-quota-genesis-reservation
if [[ "$WAL_STAGE_AGENT" == 1 && "$AGENT_VERSION" == control-v6.0.27 ]]; then
  ln -sfn "$WAL_ROOT/quota-v2-physical-stop/first_cap_handoff.py" /usr/local/sbin/xmesh-quota-genesis-cap-rehearsal
fi

if [[ -f "$ROOT/deploy/xmesh-tls-renew-hook.sh" ]]; then
  install -o root -g root -m 0700 "$ROOT/deploy/xmesh-tls-renew-hook.sh" /usr/local/libexec/xmesh-tls-renew-hook
fi

# Metrics/control implementations live with Nexus. During branch integration a
# reviewed ref may be supplied explicitly; production defaults to main.
RAW="https://raw.githubusercontent.com/TriplexCorp/XMesh-Nexus/$NEXUS_REF/deploy"
fetch_install(){
  local remote="$1" target="$2" mode="$3" tmp
  tmp="$(mktemp /tmp/xmesh-v6-agent.XXXXXXXX)"
  trap 'rm -f "$tmp"' RETURN
  /usr/bin/curl --proto '=https' --tlsv1.3 --tls-max 1.3 --fail --silent --show-error --location --max-time 30 "$RAW/$remote" -o "$tmp"
  case "$remote" in *.sh) bash -n "$tmp";; *.py) python3 -m py_compile "$tmp";; esac
  install -o root -g root -m "$mode" "$tmp" "$target"
  rm -f "$tmp"
  trap - RETURN
}
fetch_install node-metrics-agent.sh /usr/local/sbin/xmesh-node-metrics 0700
fetch_install xray-stats-collector.py /usr/local/libexec/xmesh-xray-stats-collector.py 0700

grep -Fq '/api/v1/metrics/ingest' /usr/local/sbin/xmesh-node-metrics || { echo "invalid metrics worker" >&2; exit 1; }
if [[ "$WAL_STAGE_AGENT" == 0 ]];then
  fetch_install node-control-agent.sh /usr/local/sbin/xmesh-node-control 0700
  grep -Fq "AGENT_VERSION=\"$AGENT_VERSION\"" /usr/local/sbin/xmesh-node-control || { echo "control worker version does not match canonical Agent release" >&2; exit 1; }
  if [[ "$AGENT_VERSION" == control-v6.0.27 ]];then
    grep -Fxq "AGENT_VERSION = \"$AGENT_VERSION\"" /usr/local/libexec/xmesh-xray-update.py || { echo "Xray update worker version does not match canonical Agent release" >&2; exit 1; }
  fi
fi

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
WAL_SERVICE_ENV=EnvironmentFile=-/etc/xmesh-quota-wal.env
if [[ "$WAL_STAGE_AGENT" == 1 ]];then
  WAL_SERVICE_ENV=Environment=XMESH_QUOTA_V2_WAL_RECONCILE=1
fi
cat > /etc/systemd/system/xmesh-xray-sync.service <<EOF
[Unit]
Description=XMesh v6 strict-PQ managed Xray reconciliation
After=network-online.target docker.service
Wants=network-online.target docker.service
ConditionPathExists=/var/lib/xmesh-agent/product/active.json
[Service]
Type=oneshot
EnvironmentFile=/etc/xmesh-node-metrics.env
$WAL_SERVICE_ENV
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

if [[ "$WAL_STAGE_AGENT" == 0 ]];then
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

fi

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

# Automatic quota renewal is a separately gated STAGING worker. Never
# install it on ordinary v6 nodes or activate it merely because a quota
# helper exists on disk. Its WAL charge receipts are pre-debit intents, not
# evidence of remote Xray integrity or final delivered bytes.
if [[ "$WAL_AUTO_RENEW" == 1 ]];then
cat > /etc/systemd/system/xmesh-quota-v2-ingress.service <<EOF
[Unit]
Description=XMesh isolated per-user VLESS ingress
After=docker.service
# This is an explicit root-owned 0600 operator-controlled STAGING marker.
# The Python worker additionally verifies ownership, nlink, pinned Xray
# executable, enrolled signed policy and private user-specific routes.
ConditionPathExists=/etc/xmesh-quota-v2-staging
ConditionPathExists=/var/lib/xmesh-xray-sync/genesis-quarantine-envelope.json
[Service]
Type=simple
Environment=XMESH_QUOTA_V2_INGRESS_STAGING=1
ExecStart=/usr/bin/python3 $WAL_ROOT/quota-v2-physical-stop/vless_ingress.py --panel $PANEL --node $NODE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
UMask=0077
Restart=on-failure
RestartSec=5s
EOF
cat > /etc/systemd/system/xmesh-quota-v2-renewal.service <<EOF
[Unit]
Description=XMesh staged strict-PQ signed Xray WAL charge and cap renewal
After=network-online.target docker.service
Wants=network-online.target docker.service
ConditionPathExists=/var/lib/xmesh-agent/product/active.json
ConditionPathExists=/var/lib/xmesh-xray-sync/genesis-quarantine-envelope.json
[Service]
Type=oneshot
EnvironmentFile=/etc/xmesh-node-metrics.env
Environment=XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY=1
Environment=XMESH_QUOTA_V2_AUTO_RENEW_STAGING=1
EnvironmentFile=-/etc/xmesh-quota-generations-staging.env
Environment="PATH=$STRICT_PATH"
ExecStart=/usr/bin/python3 $WAL_ROOT/quota-v2-physical-stop/renewal_worker.py --panel $PANEL --node-id $NODE
User=root
Group=root
UMask=0077
TimeoutStartSec=350s
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=/run /var/lib/xmesh-xray-sync /var/lib/xmesh-measured-lab/wal
EOF
cat > /etc/systemd/system/xmesh-quota-v2-renewal.timer <<'EOF'
[Unit]
Description=Reconcile staged signed Xray WAL charges and quota renewals
[Timer]
OnBootSec=20s
OnUnitInactiveSec=20s
AccuracySec=3s
Persistent=true
Unit=xmesh-quota-v2-renewal.service
[Install]
WantedBy=timers.target
EOF
else
  systemctl disable --now xmesh-quota-v2-renewal.timer xmesh-quota-v2-renewal.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/xmesh-quota-v2-renewal.service /etc/systemd/system/xmesh-quota-v2-renewal.timer
fi

# The reviewed 6.0.27 product can recover the ORIGINAL signed activation
# after reboot without re-enrollment. Existing production Agent binaries do
# not implement resume-activation; leave their unit topology unchanged.
if [[ "$AGENT_VERSION" == control-v6.0.27 ]]; then
cat > /etc/systemd/system/xmesh-pq-activation-recovery.service <<'EOF'
[Unit]
Description=XMesh strict-PQ recover original signed Agent activation before operations
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=root
Group=root
UMask=0077
ExecStart=/usr/local/bin/xmesh-agent-xspv2-product resume-activation
TimeoutStartSec=45s
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
ReadWritePaths=/var/lib/xmesh-agent/product
[Install]
WantedBy=multi-user.target
EOF
  RECOVERY_WORKERS=(xmesh-xray-sync xmesh-node-metrics xmesh-node-user-meter)
  if [[ "$WAL_STAGE_AGENT" == 0 ]]; then
    RECOVERY_WORKERS+=(xmesh-node-control)
  fi
  if [[ "$WAL_AUTO_RENEW" == 1 ]]; then
    RECOVERY_WORKERS+=(xmesh-quota-v2-ingress xmesh-quota-v2-renewal)
  fi
  for worker in "${RECOVERY_WORKERS[@]}"; do
    install -d -o root -g root -m 0755 "/etc/systemd/system/${worker}.service.d"
    cat > "/etc/systemd/system/${worker}.service.d/10-pq-activation-recovery.conf" <<'EOF'
[Unit]
Requires=xmesh-pq-activation-recovery.service
After=xmesh-pq-activation-recovery.service
EOF
  done
fi

systemctl daemon-reload

# Re-check the exact durable receipt immediately before first operational I/O.
"$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null

# Persist the retry topology before the first reconciliation. A transient
# desired-config/TLS/router failure must never strand an enrolled v6 node with
# unit files installed but its sync/heartbeat/metrics timers disabled.
OPERATIONAL_TIMERS=(
  xmesh-xray-sync.timer
  xmesh-node-metrics.timer
  xmesh-node-user-meter.timer
)
if [[ "$WAL_STAGE_AGENT" == 0 ]];then
  OPERATIONAL_TIMERS+=(xmesh-node-control.timer)
fi
if [[ "$WAL_AUTO_RENEW" == 1 ]];then
  OPERATIONAL_TIMERS+=(xmesh-quota-v2-renewal.timer)
fi
# Ensure reboot recovery is attempted before operational traffic.
if [[ "$AGENT_VERSION" == control-v6.0.27 ]]; then
  systemctl enable xmesh-pq-activation-recovery.service >/dev/null
fi
systemctl enable "${OPERATIONAL_TIMERS[@]}" >/dev/null

# Heartbeat/metrics are independent of whether the very first Xray policy can
# be applied. Start them now so Nexus can keep observing the enrolled node.
systemctl start xmesh-node-metrics.service || true
if [[ "$WAL_STAGE_AGENT" == 0 ]];then
  systemctl start xmesh-node-control.service || true
fi

if [[ "$WAL_STAGE_AGENT" == 1 ]];then
  # A fresh staging Node has no qualified Xray yet. Arm the reconciler in
  # quarantine without treating the expected cold-start denial as an install
  # failure or using the ordinary bootstrap path to start unmetered traffic.
  systemctl start "${OPERATIONAL_TIMERS[@]}"
  echo "WAL staging timers active. Xray is quarantined until runtime qualification."
  exit 0
fi

# First reconciliation is synchronous. If there is no profile yet it exits
# cleanly while leaving Xray stopped. On any other failure arm the timers before
# returning non-zero: the node stays fail-closed but can self-heal on the next
# authenticated strict-PQ poll after the operator fixes the profile/TLS/router.
if ! systemctl start xmesh-xray-sync.service; then
  systemctl start "${OPERATIONAL_TIMERS[@]}" || true
  echo "Initial Xray reconciliation failed; strict-PQ operational timers remain active and will retry automatically." >&2
  exit 1
fi

systemctl start "${OPERATIONAL_TIMERS[@]}"

echo "XMesh v6 operational agents installed behind strict-PQ-only transport."
echo "Direct operational HTTPS is not configured; all panel POSTs traverse the product tunnel."
