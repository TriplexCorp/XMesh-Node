#!/usr/bin/env python3
from pathlib import Path

src = Path('bootstrap.sh').read_text(encoding='utf-8')

required = [
    'XMESH_NODE_RELEASE_REF',
    '--preserve-env=XMESH_NODE_RELEASE_REF',
    'git -C "$INSTALL_DIR" fetch --force --depth 1 origin "$RELEASE_REF"',
    'git -C "$INSTALL_DIR" checkout --detach --force FETCH_HEAD',
    '[[ "$NODE_RELEASE_SHA" == "$RELEASE_REF" ]]',
    'XMESH_NODE_RELEASE_REF=$NODE_RELEASE_SHA',
    'STRICT-PQ GATE PASSED: productionActivation=true strictPQEnabled=true fallback=false',
]
for needle in required:
    assert needle in src, f'missing strict release-pin contract: {needle}'

assert 'git -C "$INSTALL_DIR" pull --ff-only' not in src, 'fresh v6 bootstrap must not consume moving main'
assert 'git clone --depth 1 https://github.com/TriplexCorp/XMesh-Node.git' not in src, 'fresh v6 bootstrap must not clone moving HEAD'

ops = Path('deploy/install-v6-strict-operational-agents.sh').read_text(encoding='utf-8')
enable = 'systemctl enable "${OPERATIONAL_TIMERS[@]}" >/dev/null'
first_sync = 'if ! systemctl start xmesh-xray-sync.service; then'
retry_start = 'systemctl start "${OPERATIONAL_TIMERS[@]}" || true'
normal_start = 'systemctl start "${OPERATIONAL_TIMERS[@]}"\n'

for needle in (enable, first_sync, retry_start, normal_start):
    assert needle in ops, f'missing operational timer durability contract: {needle}'

assert ops.index(enable) < ops.index(first_sync), (
    'operational timers must be enabled before first synchronous Xray reconciliation'
)
failure_block = ops[ops.index(first_sync):ops.index('fi\n\nsystemctl start "${OPERATIONAL_TIMERS[@]}"', ops.index(first_sync))]
assert retry_start in failure_block, (
    'first reconciliation failure must start the already-enabled retry timers before exiting'
)
assert 'systemctl enable --now xmesh-xray-sync.timer' not in ops, (
    'timer durability must not depend on reaching a post-reconciliation enable --now line'
)

print('strict-PQ v6 bootstrap release pin and operational timer durability: OK')

# Fresh update recovery must be established before enabling any control
# timer, and must never download from a moving branch or run bridge1.
recovery_install = 'fetch_install xmesh-product-upgrade-coordinator.py'
recovery_init = '/usr/bin/python3 -I /usr/local/libexec/xmesh-product-upgrade-coordinator.py --fresh initialize'
recovery_timer = 'OPERATIONAL_TIMERS+=(xmesh-product-release-update.timer)'
assert ops.index(recovery_install) < ops.index(recovery_init) < ops.index(enable)
assert ops.index(recovery_timer) < ops.index(enable)
assert 'fetch_install xmesh-product-release-update.service' in ops
assert 'fetch_install xmesh-product-release-update.timer' in ops
assert 'Pending signed Agent update; recover it before repairing the installation.' in ops
assert '/usr/local/libexec/xmesh-agent-release-bridge' not in ops
print('first-release update supervisor installation contract: OK')

# Recovery is a shared, repeatedly executed cryptographic prerequisite, not a
# permanently active unit. The default systemd burst of five starts can be
# consumed by successful bootstrap/control/metrics operations in two seconds.
recovery_unit = ops.split("cat > /etc/systemd/system/xmesh-pq-activation-recovery.service <<'EOF'\n", 1)[1].split("\nEOF", 1)[0]
assert "StartLimitIntervalSec=10s\nStartLimitBurst=32\n" in recovery_unit
assert "ExecStart=/usr/local/bin/xmesh-agent-xspv2-product resume-activation" in recovery_unit
assert "RemainAfterExit=yes" not in recovery_unit
assert "Requires=xmesh-pq-activation-recovery.service" in ops
assert "After=xmesh-pq-activation-recovery.service" in ops
print("shared activation recovery burst and fail-closed dependency: OK")
