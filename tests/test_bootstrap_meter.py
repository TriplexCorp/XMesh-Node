#!/usr/bin/env python3
"""Regression: fresh v6 cannot become operational before strict-PQ activation."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
bootstrap = (root / "bootstrap.sh").read_text()
standalone = (root / "install.sh").read_text()
operational = (root / "deploy/install-v6-strict-operational-agents.sh").read_text()
adapter = (root / "deploy/xmesh-strict-pq-curl.sh").read_text()
guard = (root / "deploy/xmesh-policy-guard.py").read_text()
guard_base = (root / "deploy/xmesh-policy-guard-base.py").read_text()
tls_provision = (root / "deploy/xmesh-tls-provision.py").read_text()

# Fresh v6 must not use the historical classical enrollment/install path.
assert "/api/v1/node/enroll" not in bootstrap
assert "install-node-metrics-agent.sh" not in bootstrap
assert 'deploy/install-xsp-v2-product-client.sh' in bootstrap
assert 'deploy/install-v6-strict-operational-agents.sh' in bootstrap

verify_at = bootstrap.index('"$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null')
router_at = bootstrap.index("docker compose up -d --no-build")
ops_at = bootstrap.index('bash "$INSTALL_DIR/deploy/install-v6-strict-operational-agents.sh"')
assert verify_at < router_at < ops_at

# Before the first activation check the installer disables all managed units
# and stops the exact managed containers through the bounded container loop.
pre_gate = bootstrap[:verify_at]
assert "for container in xmesh-node xmesh-managed-xray; do" in pre_gate
assert 'docker update --restart=no "$container"' in pre_gate
assert 'docker stop -t 5 "$container"' in pre_gate
assert "xmesh-xray-sync.timer" in pre_gate
assert "xmesh-node-metrics.timer" in pre_gate
assert "xmesh-node-control.timer" in pre_gate

# The managed Xray is explicitly kept down again after router startup until
# desired-config is reconciled by the strict operational installer.
assert 'docker stop -t 5 xmesh-managed-xray' in bootstrap[router_at:ops_at]

# The sandboxed reconciler uses ProtectHome=true, so its router source/config
# must live outside /root. Managed ACME packages are prepared here as well;
# package-manager execution inside reconciliation is forbidden.
assert "INSTALL_DIR=/opt/xmesh-node" in bootstrap
assert "/root/XMesh-Node" not in bootstrap
assert "certbot" in bootstrap.split("apt_get install -y", 1)[1].split("\n", 1)[0]
assert 'subprocess.run(["apt-get"' not in tls_provision
assert 'shutil.which("certbot")' in tls_provision
assert "rerun the reviewed XMesh Node bootstrap" in tls_provision

# xmesh-xray-sync keeps ProtectSystem=strict but must be able to atomically
# replace the router's bind-mounted config in /opt/xmesh-node. The broader
# metrics/control/meter units must not inherit this checkout write access.
sync_unit = operational.split("cat > /etc/systemd/system/xmesh-xray-sync.service <<EOF", 1)[1].split("EOF", 1)[0]
assert "ProtectSystem=strict" in sync_unit
assert "ProtectHome=true" in sync_unit
assert "ReadWritePaths=" in sync_unit and "/opt/xmesh-node" in sync_unit
for marker in (
    "cat > /etc/systemd/system/xmesh-node-metrics.service <<EOF",
    "cat > /etc/systemd/system/xmesh-node-control.service <<EOF",
    "cat > /etc/systemd/system/xmesh-node-user-meter.service <<'EOF'",
):
    unit = operational.split(marker, 1)[1].split("EOF", 1)[0]
    assert "/opt/xmesh-node" not in unit

# Standalone install is also fail-closed. It installs the product client and
# verifies/creates strict-PQ activation before the first managed router start.
assert 'XMESH_API_URL' in standalone
assert 'XMESH_NODE_ID' in standalone
assert 'XMESH_ENROLLMENT_TOKEN_FILE' in standalone
assert 'deploy/install-xsp-v2-production-agent.sh' in standalone
standalone_verify = standalone.index('"$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null')
standalone_up = standalone.index('docker compose up -d --no-build')
assert standalone_verify < standalone_up
assert 'docker stop -t 5 xmesh-node' in standalone[:standalone_verify]
assert 'automaticClassicalFallback' in standalone[:standalone_up]

# Operational workers must re-check the receipt before their first panel I/O.
assert '"$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null' in operational
first_sync = operational.index("if ! systemctl start xmesh-xray-sync.service; then")
ops_verify = operational.rindex('"$PRODUCT" verify-active --panel "$PANEL" --node-id "$NODE" >/dev/null', 0, first_sync)
assert ops_verify < first_sync

# Timer persistence must no longer depend on the first reconciliation being
# successful. The topology is enabled before sync, and both the failure path
# and normal path start the same fixed timer set.
timer_enable = operational.index('systemctl enable "${OPERATIONAL_TIMERS[@]}" >/dev/null')
assert timer_enable < first_sync
failure_end = operational.index('fi\n\nsystemctl start "${OPERATIONAL_TIMERS[@]}"', first_sync)
failure_block = operational[first_sync:failure_end]
assert 'systemctl start "${OPERATIONAL_TIMERS[@]}" || true' in failure_block
assert operational.count('systemctl start "${OPERATIONAL_TIMERS[@]}"') >= 2
assert "xmesh-xray-sync.timer" in operational
assert "xmesh-node-metrics.timer" in operational
assert "xmesh-node-control.timer" in operational
assert "xmesh-node-user-meter.timer" in operational
assert "systemctl enable --now xmesh-xray-sync.timer" not in operational

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

# The v6 policy entrypoint intentionally layers independent protocol credentials
# over the reviewed historical accounting/replay guard. Both files must ship as
# one runtime unit; the base retains the CLI and the wrapper redirects only the
# account identity helpers.
assert 'choices=["prepare", "offline", "commit", "sample"]' in guard_base
assert 'base.configured_accounts = configured_accounts' in guard
assert 'base.account_uuid = account_uuid' in guard
assert 'xmesh-policy-guard-base.py' in operational.split('for helper in ', 1)[1].split('; do', 1)[0]
assert '--tlsv1.3 --tls-max 1.3' in operational
print("Fresh v6 strict-PQ fail-closed bootstrap, durable operational timers, layered policy guard, TLS/router sandbox boundaries, standalone install and verified per-user metering contract: OK")
