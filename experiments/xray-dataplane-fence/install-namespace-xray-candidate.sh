#!/usr/bin/env bash
# Side-by-side candidate installation only. Never enroll, start or enable.
set -Eeuo pipefail
umask 077
[[ "$EUID" == 0 && "$#" == 2 && "$1" =~ ^[0-9a-f]{40}$ ]] || exit 2
[[ "$(uname -s):$(uname -m)" == Linux:x86_64 ]] || exit 2
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
REVISION="$1"
INPUT="$(realpath -e -- "$2")"
[[ -d "$INPUT" && "$(git -c safe.directory="$ROOT" -C "$ROOT" rev-parse HEAD)" == "$REVISION" ]] || exit 2
# Same independently pinned Sigstore verifier distribution used by the
# existing metered Xray installer, never an arbitrary PATH executable.
WORK="$(mktemp -d /tmp/xmesh-namespace-candidate-install.XXXXXXXX)"
trap 'rm -rf -- "$WORK"' EXIT
curl --proto '=https' --proto-redir '=https' --tlsv1.3 --fail --silent --show-error \
  --location --connect-timeout 12 --max-time 180 --max-filesize 33554432 \
  --output "$WORK/gh.tar.gz" https://github.com/cli/cli/releases/download/v2.105.0/gh_2.105.0_linux_amd64.tar.gz
printf '%s  %s\n' 79e7ab5db738c48777b696e374f8b428f0647debfb424f44d2f426370407fe2f "$WORK/gh.tar.gz" | sha256sum --check --status
tar -xzf "$WORK/gh.tar.gz" --strip-components=2 -C "$WORK" gh_2.105.0_linux_amd64/bin/gh
env -i PATH=/usr/bin:/bin HOME="$WORK" /usr/bin/python3 -I -B "$ROOT/experiments/xray-dataplane-fence/install_namespace_candidate.py" \
  "$ROOT" "$REVISION" "$INPUT" "$WORK/gh"
