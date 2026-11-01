from pathlib import Path
import subprocess

FILES = [
    '.github/workflows/ci.yml',
    '.github/workflows/xsp-p0d-agent.yml',
    'AGENT_VERSION',
    'agent/xspv2/cmd/xmesh-agent-xspv2-activate/identity_version_test.go',
    'agent/xspv2/cmd/xmesh-agent-xspv2-product/identity_version_test.go',
    'deploy/install-v6-strict-operational-agents.sh',
    'deploy/install-xsp-v2-product-client.sh',
    'docs/AGENT_RELEASE_POLICY.md',
    'scripts/check-agent-version-policy.py',
]

for name in FILES:
    p = Path(name)
    p.write_text(p.read_text().replace('control-v6.0.5', 'control-v6.0.6'))

if Path('AGENT_VERSION').read_text().strip() != 'control-v6.0.6':
    raise SystemExit('canonical Agent version bump failed')
subprocess.run(['python3', 'scripts/check-agent-version-policy.py', '--base-ref', 'origin/main'], check=True)
subprocess.run(['go', 'test', './...'], cwd='agent/xspv2', check=True)
subprocess.run(['git', 'diff', '--check'], check=True)
