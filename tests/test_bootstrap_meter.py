#!/usr/bin/env python3
"""Regression: fresh v6 cannot become operational before strict-PQ activation."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
bootstrap = (root / "bootstrap.sh").read_text()
operational = (root / "deploy/install-v6-strict-operational-agents.sh").read_text()
adapter = (root / "deploy/xmesh-strict-pq-curl.sh").read_text()
guard = (root / "deploy/xmesh-policy-guard.py").read_text()

# Fresh v6 must not use the historical classical enrollment/install path.
assert "/api/v1/node/enroll" not in bootstrap
assert "install-node-metrics-agent.sh" not in bootstrap
assert 'deploy/install-xsp-v2-product-client.sh' in bootstrap
assert 'deploy/install-v6-strict-operational-agents.sh' in bootstrap

verify_at = bootstrap.index('"$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null')
router_at = bootstrap.index("docker compose up -d --no-build")
ops_at = bootstrap.index('bash "$INSTALL_DIR/deploy/install-v6-strict-operational-agents.sh"')
assert verify_at < router_at < ops_at

# The managed Xray is explicitly kept down until desired-config is reconciled
# by the strict operational installer.
stop_xray_at = bootstrap.index('docker stop -t 5 xmesh-managed-xray')
assert stop_xray_at < verify_at
assert 'docker stop -t 5 xmesh-managed-xray' in bootstrap[router_at:ops_at]

# Operational workers must re-check the receipt before their first panel I/O.
assert '"$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null' in operational
first_sync = operational.index("systemctl start xmesh-xray-sync.service")
ops_verify = operational.rindex('"$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null', 0, first_sync)
assert ops_verify < first_sync
assert "systemctl enable --now xmesh-xray-sync.timer" in operational
assert "xmesh-node-user-meter.timer" in operational

# The adapter has no direct HTTP client fallback: it accepts only the fixed
# operational POST set and delegates every network request to the PQ product client.
assert 'PRODUCT=/usr/local/bin/xmesh-agent-xspv2-product' in adapter
assert '"$PRODUCT" request' in adapter
for path in (
    "/api/v1/metrics/ingest",
    "/api/v1/node/heartbeat",
    "/api/v1/node/restart/poll",
    "/api/v1/node/restart/ack",
    "/api/v1/node/desired-config",
):
    assert path in adapter
assert "command curl" not in adapter
assert "curl --" not in adapter
assert "http.Client" not in adapter

assert 'choices=["prepare", "offline", "commit", "sample"]' in guard
print("Fresh v6 strict-PQ fail-closed bootstrap and verified per-user metering contract: OK")
