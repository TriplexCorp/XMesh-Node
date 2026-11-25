#!/usr/bin/env bash
# Install the measured services after verifying the enrolled product.
set -Eeuo pipefail
umask 077
[[ "$EUID" == 0 && "$#" == 2 ]] || exit 2
panel="$1"
node="$2"
[[ "$panel" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ && "$node" =~ ^[1-9][0-9]*$ ]] || exit 2
/usr/local/bin/xmesh-agent-xspv2-product verify-active --panel "$panel" --node-id "$node" >/dev/null
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
modules="$root/experiments/quota-v2-physical-stop"
[[ "$root" == /opt/xmesh-node ]]
install -d -o root -g root -m 0700 /var/lib/xmesh-xray-sync
cat > /etc/systemd/system/xmesh-quota-v2-egress.service <<EOF
[Unit]
Description=XMesh root-owned outbound TCP bridge for signed metered Xray
After=docker.service network-online.target
Requires=docker.service
Wants=network-online.target
Before=xmesh-quota-v2-meter.service
[Service]
Type=exec
UMask=0077
Environment=XMESH_QUOTA_V2_AGENT_MODE=installed
ExecStart=/usr/bin/python3 $modules/metered_tcp_egress.py
User=root
Group=root
RuntimeDirectory=xmesh-quota-egress
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=restart
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run/xmesh-quota-egress
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/xmesh-quota-v2-meter.service <<EOF
[Unit]
Description=XMesh qualified first meter and signed Genesis
After=docker.service network-online.target xmesh-quota-v2-egress.service
Requires=docker.service xmesh-quota-v2-egress.service
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
UMask=0077
Environment=XMESH_QUOTA_V2_AGENT_MODE=installed
ExecStart=/usr/bin/python3 $modules/qualified_first_meter.py --panel $panel --node $node
Restart=on-failure
RestartSec=20s
TimeoutStartSec=5min
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/xmesh-quota-v2-ingress.service <<EOF
[Unit]
Description=XMesh signed VLESS ingress
After=xmesh-quota-v2-meter.service
Requires=xmesh-quota-v2-meter.service
[Service]
Type=simple
Environment=XMESH_QUOTA_V2_AGENT_MODE=installed
ExecStart=/usr/bin/python3 $modules/vless_ingress.py --installed --panel $panel --node $node
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
UMask=0077
Restart=on-failure
RestartSec=5s
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/xmesh-quota-v2-renewal.service <<EOF
[Unit]
Description=XMesh authenticated WAL reconciliation and signed cap renewal
After=xmesh-quota-v2-meter.service
Requires=xmesh-quota-v2-meter.service
[Service]
Type=oneshot
Environment=XMESH_QUOTA_V2_AGENT_MODE=installed
ExecStart=/usr/bin/python3 $modules/renewal_worker.py --panel $panel --node-id $node --socket /var/lib/xmesh-first-meter/runtime/drain.sock
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/run /var/lib/xmesh-xray-sync /var/lib/xmesh-first-meter
TimeoutStartSec=350s
EOF
cat > /etc/systemd/system/xmesh-quota-v2-renewal.timer <<'EOF'
[Unit]
Description=Reconcile measured Xray traffic and renew signed quotas
[Timer]
OnBootSec=5s
OnUnitInactiveSec=10s
AccuracySec=1s
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable xmesh-quota-v2-egress.service xmesh-quota-v2-meter.service xmesh-quota-v2-ingress.service xmesh-quota-v2-renewal.timer
systemctl start xmesh-quota-v2-egress.service
systemctl start xmesh-quota-v2-meter.service
systemctl start xmesh-quota-v2-renewal.timer xmesh-quota-v2-ingress.service
