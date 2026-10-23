#!/usr/bin/env bash
set -Eeuo pipefail
# Upgrade only the existing desired-Xray reconciliation timer.
# Safe for enrolled nodes: does not re-enroll, restart Xray, or touch secrets.
[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
timer=/etc/systemd/system/xmesh-xray-sync.timer
[[ -f "$timer" ]] || { echo "Managed Xray sync timer is not installed." >&2; exit 1; }
[[ -f /etc/systemd/system/xmesh-xray-sync.service ]] || {
 echo "Managed Xray sync service is not installed." >&2; exit 1;
}
cp -p "$timer" "$timer.bak"
cat > "$timer" <<'TIMER'
[Unit]
Description=Reconcile XMesh managed Xray authorization and configuration

[Timer]
OnBootSec=10s
OnUnitInactiveSec=10s
AccuracySec=1s
Unit=xmesh-xray-sync.service

[Install]
WantedBy=timers.target
TIMER
systemctl daemon-reload
systemctl enable xmesh-xray-sync.timer >/dev/null
systemctl restart xmesh-xray-sync.timer
systemctl list-timers --all xmesh-xray-sync.timer
echo "XMesh Xray sync interval is now 10 seconds after each completed run."
