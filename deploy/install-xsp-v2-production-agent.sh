#!/usr/bin/env bash
# Install all XMesh v6 strict-PQ production runtimes from the exact checked-out
# Node revision. Both artifacts are required: installation is fail-closed.
set -Eeuo pipefail
umask 077
export LC_ALL=C

[[ "${EUID}" -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
VERSION_FILE="$ROOT/VERSION"
[[ -f "$VERSION_FILE" && ! -L "$VERSION_FILE" ]] || { echo "VERSION file missing" >&2; exit 1; }
NODE_VERSION="$(tr -d '\r\n' < "$VERSION_FILE")"
[[ "$NODE_VERSION" == "6.0.0" ]] || { echo "Unexpected Node release version: $NODE_VERSION" >&2; exit 1; }
AGENT_VERSION="control-v6.0.0"
SOURCE_REVISION="${1:-$(git -C "$ROOT" rev-parse HEAD)}"
[[ "$SOURCE_REVISION" =~ ^[0-9a-f]{40}$ ]] || { echo "Invalid source revision" >&2; exit 2; }
[[ "$(git -C "$ROOT" rev-parse HEAD)" == "$SOURCE_REVISION" ]] || {
  echo "Refusing to build PQ Agent from a revision different from the checked-out source" >&2
  exit 1
}
for cmd in docker git python3 sha256sum install mv timeout; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "$cmd is required" >&2; exit 1; }
done
docker info >/dev/null 2>&1 || { echo "Docker daemon unavailable" >&2; exit 1; }

BUILD_DIR="$(mktemp -d /tmp/xmesh-pq-agent.XXXXXXXX)"
trap 'rm -rf "$BUILD_DIR"' EXIT

# Go 1.27.3 is the reviewed production toolchain for the v6 strict-PQ runtime.
docker run --rm \
  -v "$ROOT:/src:ro" \
  -v "$BUILD_DIR:/out" \
  -w /src/agent/xspv2 \
  golang:1.27.3-trixie \
  sh -ec "CGO_ENABLED=0 go build -trimpath -ldflags '-X main.version=$AGENT_VERSION -X main.sourceRevision=$SOURCE_REVISION' -o /out/xmesh-agent-xspv2-activate ./cmd/xmesh-agent-xspv2-activate && \
          CGO_ENABLED=0 go build -trimpath -ldflags '-X main.version=$AGENT_VERSION -X main.sourceRevision=$SOURCE_REVISION' -o /out/xmesh-agent-xspv2-product ./cmd/xmesh-agent-xspv2-product"

ACTIVATION_BINARY="$BUILD_DIR/xmesh-agent-xspv2-activate"
PRODUCT_BINARY="$BUILD_DIR/xmesh-agent-xspv2-product"
for binary in "$ACTIVATION_BINARY" "$PRODUCT_BINARY"; do
  [[ -f "$binary" && ! -L "$binary" ]] || { echo "PQ Agent build output missing: $binary" >&2; exit 1; }
  chmod 0755 "$binary"
done
ACTIVATION_DIGEST="$(sha256sum "$ACTIVATION_BINARY" | awk '{print $1}')"
PRODUCT_DIGEST="$(sha256sum "$PRODUCT_BINARY" | awk '{print $1}')"
[[ "$ACTIVATION_DIGEST" =~ ^[0-9a-f]{64}$ && "$PRODUCT_DIGEST" =~ ^[0-9a-f]{64}$ ]] || { echo "Invalid PQ Agent digest" >&2; exit 1; }

ACTIVATION_IDENTITY="$(timeout 10 "$ACTIVATION_BINARY" --identity)"
PRODUCT_IDENTITY="$(timeout 10 "$PRODUCT_BINARY" --identity)"
python3 - "$ACTIVATION_IDENTITY" "$PRODUCT_IDENTITY" "$AGENT_VERSION" "$SOURCE_REVISION" "$ACTIVATION_DIGEST" "$PRODUCT_DIGEST" <<'PY'
import json,sys
activation=json.loads(sys.argv[1]); product=json.loads(sys.argv[2])
version,revision,activation_sha,product_sha=sys.argv[3:]
assert activation=={"version":version,"sourceRevision":revision,"artifactSha256":activation_sha}, activation
assert product=={"version":version,"sourceRevision":revision,"artifactSha256":product_sha}, product
PY

install -d -o root -g root -m 0700 /var/lib/xmesh-agent /var/lib/xmesh-agent/xsp-v2 /var/lib/xmesh-agent/product
install -d -o root -g root -m 0755 /usr/local/bin
install -o root -g root -m 0755 "$ACTIVATION_BINARY" /usr/local/bin/.xmesh-agent-xspv2-activate.v6.new
install -o root -g root -m 0755 "$PRODUCT_BINARY" /usr/local/bin/.xmesh-agent-xspv2-product.v6.new
mv -f /usr/local/bin/.xmesh-agent-xspv2-activate.v6.new /usr/local/bin/xmesh-agent-xspv2-activate
mv -f /usr/local/bin/.xmesh-agent-xspv2-product.v6.new /usr/local/bin/xmesh-agent-xspv2-product

python3 - /var/lib/xmesh-agent/v6-production-identity.json "$AGENT_VERSION" "$SOURCE_REVISION" "$ACTIVATION_DIGEST" "$PRODUCT_DIGEST" <<'PY'
import json,os,sys,tempfile
path=sys.argv[1]
value={"version":sys.argv[2],"sourceRevision":sys.argv[3],
       "activationArtifactSha256":sys.argv[4],"productArtifactSha256":sys.argv[5],
       "strictPQCapable":True,"strictPQRequired":True,"automaticClassicalFallback":False}
fd,tmp=tempfile.mkstemp(prefix='.v6-identity.',dir=os.path.dirname(path),text=True)
try:
    with os.fdopen(fd,'w',encoding='utf-8') as f:
        json.dump(value,f,separators=(',',':'));f.write('\n');f.flush();os.fsync(f.fileno())
    os.chmod(tmp,0o600);os.replace(tmp,path)
    d=os.open(os.path.dirname(path),os.O_RDONLY)
    try: os.fsync(d)
    finally: os.close(d)
finally:
    try: os.unlink(tmp)
    except FileNotFoundError: pass
PY
chmod 0600 /var/lib/xmesh-agent/v6-production-identity.json
/usr/local/bin/xmesh-agent-xspv2-activate --identity
/usr/local/bin/xmesh-agent-xspv2-product --identity
echo "XMesh Node v${NODE_VERSION}: strict-PQ activation and product runtimes installed."
