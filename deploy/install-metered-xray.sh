#!/usr/bin/env bash
# Install the exact signed metering candidate. This does not authorize ingress.
set -Eeuo pipefail
umask 077

[[ "$EUID" -eq 0 ]] || { echo 'Metered Xray installation requires root.' >&2; exit 2; }
[[ "${1:-}" =~ ^[0-9a-f]{40}$ && "$#" -eq 1 ]] || { echo 'An exact Nexus release revision is required.' >&2; exit 2; }
[[ "$(uname -s):$(uname -m)" == Linux:x86_64 ]] || { echo 'No qualified metered Xray for this platform.' >&2; exit 2; }
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
NEXUS_REF="$1"
DESTINATION=/usr/local/libexec/xmesh-metered-xray
QUALIFICATION=/var/lib/xmesh-metered-xray
SIGNER=TriplexCorp/XMesh-Node
SIGNER_WORKFLOW="$SIGNER/.github/workflows/xray-dataplane-fence-experiment.yml"
WORK="$(mktemp -d /tmp/xmesh-metered-xray.XXXXXXXX)"
stage=
cleanup() {
    if [[ -n "$stage" ]]; then rm -f -- "$stage"; fi
    rm -rf -- "$WORK"
}
trap cleanup EXIT

fetch() {
    curl --proto '=https' --proto-redir '=https' --tlsv1.3 --fail --silent --show-error \
        --location --connect-timeout 12 --max-time 180 --max-filesize "$3" --output "$2" "$1"
}
check_sha() {
    printf '%s  %s\n' "$2" "$1" | sha256sum --check --status
}

release="https://raw.githubusercontent.com/TriplexCorp/XMesh-Nexus/$NEXUS_REF/scripts"
for name in metered-xray-qualification metered-xray-candidate-manifest metered-xray-provenance; do
    fetch "$release/$name.json" "$WORK/$name.json" 65536
done

# The verifier itself comes from the pinned Nexus checkout. Bootstrap the
# Sigstore client from its exact public archive, independent of the Xray pin.
fetch https://github.com/cli/cli/releases/download/v2.105.0/gh_2.105.0_linux_amd64.tar.gz "$WORK/gh.tar.gz" 33554432
check_sha "$WORK/gh.tar.gz" 79e7ab5db738c48777b696e374f8b428f0647debfb424f44d2f426370407fe2f
tar -xzf "$WORK/gh.tar.gz" --strip-components=2 -C "$WORK" gh_2.105.0_linux_amd64/bin/gh

read_metadata="$(python3 - "$WORK" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
qualification = json.loads((root / "metered-xray-qualification.json").read_bytes())
manifest = json.loads((root / "metered-xray-candidate-manifest.json").read_bytes())
expected = {
    "schemaVersion": 1,
    "kind": "xmesh.metered-xray-candidate",
    "goVersion": "go version go1.27.4 linux/amd64",
    "independentRebuildMatched": True,
    "candidateOnly": True,
    "productionActivationAuthorized": False,
}
for key in ("nodeSourceRevision", "upstreamSourceRevision", "artifactSha256"):
    expected[key] = qualification[key]
for key, value in expected.items():
    if type(manifest.get(key)) is not type(value) or manifest[key] != value:
        raise SystemExit("Incompatible metered Xray qualification: " + key)
flags = ["GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "CGO_ENABLED=0", "-trimpath"]
if set(manifest) != set(expected) | {"buildFlags"} or manifest["buildFlags"] != flags:
    raise SystemExit("Unexpected metered Xray manifest or build flags")
print(*(qualification[k] for k in ("nodeSourceRevision", "upstreamSourceRevision", "patchSourceTree", "artifactSha256")))
PY
)"
read -r signer_revision upstream_revision patch_tree digest <<<"$read_metadata"
for revision in "$signer_revision" "$upstream_revision" "$patch_tree"; do
    [[ "$revision" =~ ^[0-9a-f]{40}$ ]] || exit 2
done
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || exit 2

attest() {
    env -i PATH=/usr/bin:/bin GH_PROMPT_DISABLED=1 GH_CONFIG_DIR="$WORK/gh-config" \
        "$WORK/gh" attestation verify "$1" --bundle "$WORK/metered-xray-provenance.json" \
        --repo "$SIGNER" --signer-workflow "$SIGNER_WORKFLOW" --source-ref refs/heads/main \
        --source-digest "$signer_revision" --deny-self-hosted-runners
}
attest "$WORK/metered-xray-candidate-manifest.json"

# Persist a non-authorizing, immutable local qualification fence before
# publishing the executable. It is not a spending permit. A missing binary
# must never silently return the Node to ordinary Xray installation.
# A different Nexus revision requires a coordinated transition, not repair.
record_qualification() {
    [[ ! -L "$QUALIFICATION" ]] || return 2
    install -d -o root -g root -m 0700 "$QUALIFICATION"
    [[ "$(stat -c '%u:%a' "$QUALIFICATION")" == 0:700 ]] || return 2
    local record="$QUALIFICATION/identity" candidate
    candidate="$(mktemp "$QUALIFICATION/.identity.XXXXXXXX")"
    printf 'nexusRevision=%s\nnodeSourceRevision=%s\nupstreamSourceRevision=%s\npatchSourceTree=%s\nartifactSha256=%s\n' \
        "$NEXUS_REF" "$signer_revision" "$upstream_revision" "$patch_tree" "$digest" > "$candidate"
    chmod 0600 "$candidate"
    sync -d "$candidate"
    if [[ ! -e "$record" && ! -L "$record" ]]; then
        ln -T -- "$candidate" "$record" || true
    fi
    if [[ ! -f "$record" || -L "$record" ]] || ! cmp -s "$candidate" "$record"; then
        rm -f -- "$candidate"
        echo 'Metered Xray qualification differs; coordinated recovery required.' >&2
        return 2
    fi
    rm -f -- "$candidate"
    [[ "$(stat -c '%u:%a:%h' "$record")" == 0:600:1 ]] || return 2
    sync -f "$QUALIFICATION"
    sync -f /var/lib
}

# A cold bootstrap may repair a missing artifact, but it must never replace
# an existing executable. Live upgrades need an authorized runtime handoff.
[[ ! -L /usr/local/libexec ]] || exit 2
if [[ -e "$DESTINATION" || -L "$DESTINATION" ]]; then
    [[ -f "$DESTINATION" && ! -L "$DESTINATION" && "$(stat -c '%u:%a:%h' "$DESTINATION")" == 0:755:1 ]]
    check_sha "$DESTINATION" "$digest"
    attest "$DESTINATION"
    record_qualification
    exit 0
fi

# GitHub Actions artifacts expire. Reconstruct the binary from the same
# stable sources, then verify its bytes against the independently signed
# subject before installing it. Do not run the candidate during the build.
# The attested Node commit fixes the exact ordinary-meter inputs. Fetch
# separately: the reviewed namespace-only extension must never influence
# the ordinary-meter patcher or become its implicit authorization.
git init -q "$WORK/patch-source"
git -C "$WORK/patch-source" fetch --no-tags --depth=1 "https://github.com/$SIGNER.git" "$signer_revision"
git -C "$WORK/patch-source" checkout -q --detach FETCH_HEAD
python3 -I -B "$ROOT/deploy/verify-metered-xray-patch-source.py" \
    "$ROOT" "$WORK/patch-source" "$signer_revision" "$patch_tree"
git init -q "$WORK/source"
git -C "$WORK/source" fetch --no-tags --depth=1 https://github.com/XTLS/Xray-core.git "$upstream_revision"
git -C "$WORK/source" checkout -q --detach FETCH_HEAD
[[ "$(git -C "$WORK/source" rev-parse HEAD)" == "$upstream_revision" ]]
# The signed patcher itself invokes gofmt. A clean VPS may have no Go
# installed, and a host-provided gofmt must not alter the signed build.
# Authenticate the toolchain before running either patch or build.
fetch https://go.dev/dl/go1.27.4.linux-amd64.tar.gz "$WORK/go.tar.gz" 83886080
check_sha "$WORK/go.tar.gz" 7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
tar -xzf "$WORK/go.tar.gz" -C "$WORK"
[[ -x "$WORK/go/bin/gofmt" && -x "$WORK/go/bin/go" ]]
[[ "$(env -i PATH="$WORK/go/bin:/usr/bin:/bin" HOME="$WORK" GOENV=off GOTOOLCHAIN=local "$WORK/go/bin/go" version)" == 'go version go1.27.4 linux/amd64' ]]
env -i PATH="$WORK/go/bin:/usr/bin:/bin" HOME="$WORK" GOENV=off GOWORK=off GOTOOLCHAIN=local \
    python3 -I -B "$WORK/patch-source/experiments/xray-dataplane-fence/apply-experiment.py" "$WORK/source"

(
    cd "$WORK/source"
    env -i PATH="$WORK/go/bin:/usr/bin:/bin" HOME="$WORK" GOENV=off GOWORK=off GOTOOLCHAIN=local \
        GOPATH="$WORK/gopath" GOCACHE="$WORK/cache" GOFLAGS= \
        GOOS=linux GOARCH=amd64 GOAMD64=v1 CGO_ENABLED=0 \
        "$WORK/go/bin/go" build -trimpath -o "$WORK/xray" ./main
)
check_sha "$WORK/xray" "$digest"
attest "$WORK/xray"
record_qualification

install -o root -g root -m 0755 -d /usr/local/libexec
[[ "$(stat -c '%u:%a' /usr/local/libexec)" == 0:755 ]]
stage="$(mktemp /usr/local/libexec/.xmesh-metered-xray.XXXXXXXX)"
install -o root -g root -m 0755 "$WORK/xray" "$stage"
check_sha "$stage" "$digest"
sync -d "$stage"
# Link rather than rename over a possibly concurrently installed executable.
ln -T -- "$stage" "$DESTINATION"
rm -f -- "$stage"
stage=
sync -f /usr/local/libexec
echo "Verified metered Xray installed: sha256:$digest (ingress unauthorized)."
