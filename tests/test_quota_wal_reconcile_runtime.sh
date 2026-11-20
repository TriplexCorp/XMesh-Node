#!/usr/bin/env bash
# Isolated real Docker/Xray test of the installed reconciler's startup cutoff.
set -Eeuo pipefail
umask 077
[[ "$EUID" == 0 && "${GITHUB_ACTIONS:-}" == true &&
   "${RUNNER_ENVIRONMENT:-}" == github-hosted && "${XMESH_DISPOSABLE_WAL_RUNTIME:-}" == 1 ]] || exit 2
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
state=/var/lib/xmesh-xray-sync
settings=/etc/xmesh-node-metrics.env
identity=/etc/xmesh-node-metrics
marker=/usr/local/libexec/xmesh-quota-revocation-marker.py
guard=/usr/local/libexec/xmesh-policy-guard-base.py
worker=/usr/local/sbin/xmesh-quota-wal
helpers=/usr/local/libexec/xmesh-quota-wal
name=xmesh-managed-xray
docker info >/dev/null
if docker inspect "$name" >/dev/null 2>&1;then exit 2;fi
for path in "$state" "$settings" "$identity" "$marker" "$guard" "$worker" "$helpers";do
    [[ ! -e "$path" && ! -L "$path" ]] || exit 2
done
scratch="$(mktemp -d)"
cleanup(){
    local status=$?
    if ((status != 0));then
        for log in "$scratch/health.log" "$scratch/restart.log";do
            if [[ -f "$log" ]];then cat "$log" >&2;fi
        done
        docker logs --tail 20 "$name" >&2 || true
    fi
    docker rm -f "$name" >/dev/null 2>&1 || true
    rm -rf -- "$scratch" "$state" "$settings" "$identity" "$marker" "$guard" "$worker" "$helpers"
}
trap cleanup EXIT
install -d -m 0700 "$identity" "$helpers/quota-v2-physical-stop" "$helpers/xray-dataplane-fence"
install -D -m 0700 "$root/deploy/xmesh-quota-revocation-marker.py" "$marker"
install -D -m 0700 "$root/deploy/xmesh-policy-guard-base.py" "$guard"
for file in quota-v2-physical-stop/{wal_transport,witness_inventory,verify_nexus_wal_anchor,journal_integrity,meter_inventory_audit} xray-dataplane-fence/{sign_observation,runtime_identity,meter_floor};do
    install -m 0700 "$root/experiments/$file.py" "$helpers/$file.py"
done
ln -s "$helpers/quota-v2-physical-stop/wal_transport.py" "$worker"
openssl genpkey -algorithm Ed25519 -out "$identity/node.key"
cat >"$settings" <<'SETTINGS'
XMESH_API_URL=https://localhost.invalid
XMESH_NODE_ID=42
XMESH_QUOTA_V2_WAL_RECONCILE=1
SETTINGS
cat >"$scratch/config.json" <<'CONFIG'
{"log":{"loglevel":"warning"},"inbounds":[{"port":10809,"listen":"127.0.0.1","protocol":"socks","settings":{"auth":"noauth"}}],"outbounds":[{"protocol":"blackhole"}]}
CONFIG
docker run -d --name "$name" --network none --restart=no --user 0:0 --cap-drop ALL \
    --security-opt no-new-privileges --entrypoint xray \
    -v "$scratch/config.json:/etc/xray/config.json:ro" ghcr.io/xtls/xray-core:26.10.31@sha256:ceabeac03a89d991d2a247361825c1d1d2e9c91cd5dc010f298c7dc0c2f325c9 \
    run -config /etc/xray/config.json >/dev/null
sleep 1
[[ "$(docker inspect -f '{{.State.Running}}' "$name")" == true ]]
original="$(docker inspect -f '{{.Id}}' "$name")"
if bash "$root/deploy/xmesh-xray-sync.sh" >"$scratch/health.log" 2>&1;then
    echo "Reconciler accepted an Xray runtime without the verified private WAL bind." >&2;exit 1
fi
grep -Fq 'managed Xray has no configured private WAL bind' "$scratch/health.log"
grep -Fq 'External WAL continuity could not be verified' "$scratch/health.log"
[[ "$(docker inspect -f '{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}' "$name")" == 'false no' ]]
if bash "$root/deploy/xmesh-xray-sync.sh" >"$scratch/restart.log" 2>&1;then
    echo "Cold startup unexpectedly qualified the stopped Xray." >&2;exit 1
fi
grep -Fq 'requires a running managed Xray with restart disabled' "$scratch/restart.log"
[[ "$(docker inspect -f '{{.State.Running}} {{.Id}}' "$name")" == "false $original" ]]
echo 'Actual Xray stopped on missing WAL bind and remains stopped on the next reconciliation.'
