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
