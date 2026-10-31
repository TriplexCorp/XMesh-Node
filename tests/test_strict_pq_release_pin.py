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

print('strict-PQ v6 bootstrap release pin: OK')
