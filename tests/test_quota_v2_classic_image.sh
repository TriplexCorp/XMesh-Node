#!/usr/bin/env bash
# Hosted disposable nested daemon regression using the actual qualified Xray.
set -Eeuo pipefail
[[ "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted ]]
[[ "$EUID" == 0 && "$#" == 1 ]]
root="$1"
name="xmesh-classic-image-$(openssl rand -hex 8)"
[[ -f /usr/local/libexec/xmesh-metered-xray && -f /var/lib/xmesh-metered-xray/identity ]]
context="$(mktemp -d)"
image=""
cleanup() {
    docker rm -f -v "$name" >/dev/null 2>&1 || true
    [[ -z "$image" ]] || docker image rm "$image" >/dev/null 2>&1 || true
    rm -rf -- "$context"
}
trap cleanup EXIT
cat > "$context/Dockerfile" <<'DOCKERFILE'
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates docker.io iptables iproute2 python3 && rm -rf /var/lib/apt/lists/*
CMD ["/usr/bin/dockerd", "--storage-driver=vfs"]
DOCKERFILE
image="$(docker build -q "$context")"
docker run -d --name "$name" --privileged --tmpfs /run:rw,nosuid,nodev "$image"
for _ in $(seq 1 60); do
    if docker exec "$name" docker info >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
docker exec "$name" docker info >/dev/null
if docker exec "$name" docker buildx version; then
    echo "Classic regression unexpectedly has buildx installed" >&2
    exit 1
fi
docker exec "$name" install -d -m 0700 /var/lib/xmesh-metered-xray
docker exec "$name" install -d -m 0755 /usr/local/libexec
docker cp /usr/local/libexec/xmesh-metered-xray "$name:/usr/local/libexec/xmesh-metered-xray"
docker cp /var/lib/xmesh-metered-xray/identity "$name:/var/lib/xmesh-metered-xray/identity"
docker cp "$root/experiments/quota-v2-physical-stop/qualified_runtime_image.py" "$name:/tmp/qualified_runtime_image.py"
report="$(docker exec "$name" python3 /tmp/qualified_runtime_image.py)"
image_id="$(python3 -c 'import json,sys; r=json.loads(sys.argv[1]); assert r["productionActivationAuthorized"] is False; print(r["imageId"])' "$report")"
[[ "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]]
[[ "$(docker exec "$name" docker image inspect --format '{{.Config.User}}' "$image_id")" == 0:0 ]]
[[ -z "$(docker exec "$name" docker ps -aq)" ]]
echo 'PASS: actual attested Xray scratch image built/read back by Ubuntu classic nested Docker, explicit root identity, no running container.'
