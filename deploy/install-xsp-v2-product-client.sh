#!/usr/bin/env bash
# Build and install the v6 strict-PQ product client from the exact checked-out
# XMesh-Node revision. This installer does NOT activate the node by itself.
set -Eeuo pipefail
umask 077
export LC_ALL=C

[[ "${EUID}" -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION_FILE="$ROOT/VERSION"
[[ -f "$VERSION_FILE" && ! -L "$VERSION_FILE" ]] || { echo "VERSION file missing" >&2; exit 1; }
NODE_VERSION="$(tr -d '\r\n' < "$VERSION_FILE")"
[[ "$NODE_VERSION" == "6.0.0" ]] || { echo "Unexpected Node release version: $NODE_VERSION" >&2; exit 1; }
PRODUCT_VERSION="control-v6.0.0"
SOURCE_REVISION="${1:-$(git -C "$ROOT" rev-parse HEAD)}"
[[ "$SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]] || { echo "Invalid source revision" >&2; exit 2; }
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$SOURCE_REVISION" ]] || {
  echo "Refusing to build product client from a revision different from the checked-out source" >&2
  exit 1
}
for cmd in docker git python3 sha256sum install mv timeout; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "$cmd is required" >&2; exit 1; }
done
docker info >/dev/null 2>&1 || { echo "Docker daemon unavailable" >&2; exit 1; }

BUILD_DIR="$(mktemp -d /tmp/xmesh-pq-product.XXXXXXXX)"
trap 'rm -rf "$BUILD_DIR"' EXIT

docker run --rm \
  -v "$ROOT:/src:ro" \
  -v "$BUILD_DIR:/out" \
  -w /src/agent/xspv2 \
  golang:1.27.3-trixie \
  sh -ec "CGO_ENABLED=0 go build -trimpath -ldflags '-X main.version=$PRODUCT_VERSION -X main.sourceRevision=$SOURCE_REVISION' -o /out/xmesh-agent-xspv2-product ./cmd/xmesh-agent-xspv2-product"

BINARY="$BUILD_DIR/xmesh-agent-xspv2-product"
[[ -f "$BINARY" && ! -L "$BINARY" ]] || { echo "strict-PQ product client build output missing" >&2; exit 1; }
chmod 0755 "$BINARY"
DIGEST="$(sha256sum "$BINARY" | awk '{print $1}')"
[[ "$DIGEST" =~ ^[0-9a-f]{64}$ ]] || { echo "Invalid strict-PQ product client digest" >&2; exit 1; }
IDENTITY="$(timeout 10 "$BINARY" --identity)"
python3 - "$IDENTITY" "$PRODUCT_VERSION" "$SOURCE_REVISION" "$DIGEST" <<'PY'
import json,sys
value=json.loads(sys.argv[1])
expected={"version":sys.argv[2],"sourceRevision":sys.argv[3],"artifactSha256":sys.argv[4]}
if value != expected:
    raise SystemExit(f"strict-PQ product client identity mismatch: {value!r}")
PY

install -d -o root -g root -m 0755 /usr/local/bin
install -o root -g root -m 0755 "$BINARY" /usr/local/bin/.xmesh-agent-xspv2-product.v6.new
mv -f /usr/local/bin/.xmesh-agent-xspv2-product.v6.new /usr/local/bin/xmesh-agent-xspv2-product

INSTALLED_DIGEST="$(sha256sum /usr/local/bin/xmesh-agent-xspv2-product | awk '{print $1}')"
[[ "$INSTALLED_DIGEST" == "$DIGEST" ]] || { echo "Installed strict-PQ product client digest mismatch" >&2; exit 1; }
/usr/local/bin/xmesh-agent-xspv2-product --identity
printf 'XMesh Node v%s strict-PQ product client installed: sha256:%s\n' "$NODE_VERSION" "$DIGEST"
