#!/usr/bin/env python3
"""Regression: a newly enrolled managed node MUST start per-user Xray stats."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
bootstrap = (root / "bootstrap.sh").read_text()
guard = (root / "deploy/xmesh-policy-guard.py").read_text()
assert "install-node-metrics-agent.sh" in bootstrap
install_at = bootstrap.index('bash "$METRICS_INSTALLER" "$PANEL" "$NODE"')
policy_at = bootstrap.index('install -o root -g root -m 0700 "$GUARD_TMP" /usr/local/libexec/xmesh-policy-guard.py')
sync_at = bootstrap.index('if systemctl start xmesh-xray-sync.service; then')
meter_at = bootstrap.index("systemctl enable --now xmesh-node-user-meter.timer")
assert install_at < policy_at < sync_at < meter_at
assert "systemctl start xmesh-node-user-meter.service" in bootstrap[meter_at:]
assert "if ! systemctl start xmesh-node-user-meter.service; then" in bootstrap[meter_at:]
assert 'choices=["prepare", "offline", "commit", "sample"]' in guard
print("Fresh managed node enables verified per-user metering: OK")
