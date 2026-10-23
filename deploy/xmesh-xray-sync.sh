#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
# Signed pull-based reconciliation. Only the explicit XMesh-managed container is touched.
[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
source /etc/xmesh-node-metrics.env
KEY=/etc/xmesh-node-metrics/node.key
[[ -r "$KEY" ]] || { echo "Missing Ed25519 node identity" >&2; exit 1; }
command -v docker >/dev/null
command -v python3 >/dev/null
command -v openssl >/dev/null
STATE=/var/lib/xmesh-xray-sync
mkdir -p "$STATE"; chmod 700 "$STATE"
exec 9>"$STATE/lock"
flock -n 9 || exit 0
REQUEST="$(printf '{"node_id":%s}' "$XMESH_NODE_ID")"
PATH_API=/api/v1/node/desired-config
STAMP="$(date +%s)"
NONCE="$(openssl rand -hex 16)"
HASH="$(printf %s "$REQUEST" | openssl dgst -sha256 -r | awk '{print $1}')"
SIGN_FILE="$(mktemp "$STATE/sign.XXXXXXXX")"
RESP_FILE="$(mktemp "$STATE/response.XXXXXXXX")"
CONFIG_FILE="$(mktemp "$STATE/config.XXXXXXXX")"
trap 'rm -f "$SIGN_FILE" "$RESP_FILE" "$CONFIG_FILE"' EXIT
printf 'XMESH1\nPOST\n%s\n%s\n%s\n%s\n%s\n' "$PATH_API" "$XMESH_NODE_ID" "$STAMP" "$NONCE" "$HASH" > "$SIGN_FILE"
SIG="$(openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$SIGN_FILE" | od -An -tx1 -v | tr -d ' \n')"
HTTP_STATUS="$(curl -sS --max-time 20 -X POST "$XMESH_API_URL$PATH_API" \
 -H "Content-Type: application/json" -H "X-XMesh-Timestamp: $STAMP" \
 -H "X-XMesh-Nonce: $NONCE" -H "X-XMesh-Signature: $SIG" \
 --data-binary "$REQUEST" -o "$RESP_FILE" -w '%{http_code}')" || {
 echo "Cannot reach XMesh desired-config API; preserving existing Xray configuration." >&2
 exit 1
}
if [[ "$HTTP_STATUS" != 200 ]]; then
 # Never print arbitrary API responses: they could contain confidential data.
 # Only display a bounded, known server-side error message.
 python3 - "$RESP_FILE" "$HTTP_STATUS" <<'PY'
import json,sys
status=sys.argv[2]
try:
 with open(sys.argv[1],encoding="utf-8") as f: payload=json.load(f)
 msg=payload.get("error") or payload.get("message") or ""
 if not isinstance(msg,str):msg=""
except (OSError,ValueError):
 msg=""
msg="".join(c for c in msg if c.isprintable())[:240]
print("XMesh desired-config rejected request (HTTP %s): %s"%(status,msg or "check node profile and local Xray port"),file=sys.stderr)
print("Existing Xray configuration was not modified.",file=sys.stderr)
PY
 exit 1
fi
python3 - "$RESP_FILE" "$CONFIG_FILE" "$XMESH_NODE_ID" <<'PY'
import json,sys,ipaddress
data=json.load(open(sys.argv[1]))
if data.get("nodeId")!=int(sys.argv[3]): raise SystemExit("Wrong node identity")
cfg=data.get("config")
if not isinstance(cfg,dict):raise SystemExit("Invalid configuration")
ibs=cfg.get("inbounds")
if not isinstance(ibs,list) or len(ibs)!=1:raise SystemExit("Exactly one inbound required")
ib=ibs[0]
if ib.get("listen")!="127.0.0.1" or ib.get("port")!=data.get("port"):raise SystemExit("Unsafe inbound listen/port")
if not isinstance(data.get("port"),int) or not 1<=data["port"]<=65535:raise SystemExit("Invalid port")
# Refuse unrelated public listeners in this managed profile.
for entry in cfg.get("inbounds",[]):
 if entry.get("listen")!="127.0.0.1":raise SystemExit("Public inbound denied")
with open(sys.argv[2],"w") as f:json.dump(cfg,f,indent=2)
PY
# A 0600 configuration may contain Reality private keys. Keep it private on host.
# Run Xray as root inside the confined container (all Linux capabilities dropped)
# so the read-only bind mount remains accessible without chmod 0644.
IMAGE=ghcr.io/xtls/xray-core:latest
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"
docker run --rm --network none --user 0:0 --cap-drop ALL --security-opt no-new-privileges --entrypoint xray -v "$CONFIG_FILE:/etc/xray/config.json:ro" \
 "$IMAGE" run -test -config /etc/xray/config.json
NEW_HASH="$(sha256sum "$CONFIG_FILE" | cut -d' ' -f1)"
ACTIVE="$STATE/config.json"
OLD_HASH="$(test -f "$ACTIVE" && sha256sum "$ACTIVE" | cut -d' ' -f1 || true)"
if [[ "$NEW_HASH" == "$OLD_HASH" ]] && docker inspect -f '{{.State.Running}}' xmesh-managed-xray 2>/dev/null | grep -qx true; then
 echo "Xray configuration unchanged, container healthy."
 exit 0
fi
# Never interrupt unrelated processes on the requested local port.
PORT="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["inbounds"][0]["port"])' "$CONFIG_FILE")"
if ss -ltnH | awk '{print $4}' | grep -Eq "(^|:)$PORT$" &&
   ! docker inspect xmesh-managed-xray >/dev/null 2>&1; then
 echo "Port $PORT is already occupied; refusing deployment." >&2; exit 1
fi
PREVIOUS="$STATE/previous.json"
if [[ -f "$ACTIVE" ]];then cp "$ACTIVE" "$PREVIOUS";fi
install -m 0600 "$CONFIG_FILE" "$ACTIVE"
docker rm -f xmesh-managed-xray >/dev/null 2>&1 || true
if ! docker run -d --name xmesh-managed-xray --restart unless-stopped \
 --network host --user 0:0 --read-only --security-opt no-new-privileges \
 --cap-drop ALL -v "$ACTIVE:/etc/xray/config.json:ro" \
 "$IMAGE" run -config /etc/xray/config.json;then
 echo "Xray start failed; attempting rollback." >&2
 if [[ -f "$PREVIOUS" ]];then
  cp "$PREVIOUS" "$ACTIVE"
  docker rm -f xmesh-managed-xray >/dev/null 2>&1 || true
  docker run -d --name xmesh-managed-xray --restart unless-stopped --network host \
   --user 0:0 --read-only --security-opt no-new-privileges --cap-drop ALL \
   -v "$ACTIVE:/etc/xray/config.json:ro" "$IMAGE" run -config /etc/xray/config.json || true
 fi
 exit 1
fi
sleep 2
if [[ "$(docker inspect -f '{{.State.Running}}' xmesh-managed-xray)" != true ]];then
 echo "New Xray instance exited; attempting rollback." >&2
 docker logs --tail 20 xmesh-managed-xray >&2 || true
 docker rm -f xmesh-managed-xray >/dev/null 2>&1 || true
 if [[ -f "$PREVIOUS" ]];then
  cp "$PREVIOUS" "$ACTIVE"
  docker run -d --name xmesh-managed-xray --restart unless-stopped --network host \
   --user 0:0 --read-only --security-opt no-new-privileges --cap-drop ALL \
   -v "$ACTIVE:/etc/xray/config.json:ro" "$IMAGE" run -config /etc/xray/config.json || true
 fi
 exit 1
fi
# Only auto-route a virgin router configuration. Never replace user SNI routes.
ROUTER=/opt/xmesh-node/config.json
[[ -f /root/XMesh-Node/config.json ]] && ROUTER=/root/XMesh-Node/config.json
if [[ -f "$ROUTER" ]];then
 ROUTER_FLAG="$STATE/router-updated"
 rm -f "$ROUTER_FLAG"
 python3 - "$ROUTER" "$PORT" "$ROUTER_FLAG" <<'PY'
import json,sys,os,tempfile
path=sys.argv[1];port=int(sys.argv[2])
with open(path) as f:d=json.load(f)
old=d.get("default_tcp")
if d.get("routes") or old not in (None,"127.0.0.1:9443",f"127.0.0.1:{port}"):
 print("Router has custom routes/default; leaving router configuration unchanged.")
else:
 target=f"127.0.0.1:{port}"
 if old!=target:
  d["default_tcp"]=target
  fd,temp=tempfile.mkstemp(dir=os.path.dirname(path),prefix=".config.")
  try:
   with os.fdopen(fd,"w") as f:json.dump(d,f,indent=2)
   os.chmod(temp,0o644)
   os.replace(temp,path)
   with open(sys.argv[3],"w") as marker: marker.write("updated")
  finally:
   if os.path.exists(temp):os.unlink(temp)
  print("Default TCP backend updated to",target)
PY
 if [[ -f /root/XMesh-Node/config.json ]];then ROUTER_DIR=/root/XMesh-Node;else ROUTER_DIR=/opt/xmesh-node;fi
 if [[ -f "$ROUTER_FLAG" ]] && [[ "$(docker inspect -f '{{.State.Running}}' xmesh-node 2>/dev/null)" == true ]];then
   (cd "$ROUTER_DIR" && docker compose restart xmesh-node)
   rm -f "$ROUTER_FLAG"
 fi
fi
echo "Xray deployed on 127.0.0.1:$PORT; configured safe default router when applicable."

