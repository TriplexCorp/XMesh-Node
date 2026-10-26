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
POLICY_GUARD=/usr/local/libexec/xmesh-policy-guard.py
POLICY_ENABLED=false
if [[ -r "$POLICY_GUARD" && "${XMESH_AUTONOMOUS_POLICY:-1}" == 1 ]];then
 POLICY_ENABLED=true
fi
OFFLINE_POLICY=false
GEO_WORKER=/usr/local/libexec/xmesh-geodata-sync.py
trap 'if [[ -f "$STATE/geo-changed" && -r "$GEO_WORKER" ]];then python3 "$GEO_WORKER" rollback "$STATE" || true;fi; rm -f "$SIGN_FILE" "$RESP_FILE" "$CONFIG_FILE"' EXIT
printf 'XMESH1\nPOST\n%s\n%s\n%s\n%s\n%s\n' "$PATH_API" "$XMESH_NODE_ID" "$STAMP" "$NONCE" "$HASH" > "$SIGN_FILE"
SIG="$(openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$SIGN_FILE" | od -An -tx1 -v | tr -d ' \n')"
HTTP_STATUS="$(curl --proto '=https' --tlsv1.2 -sS --max-time 20 -X POST "$XMESH_API_URL$PATH_API" \
 -H "Content-Type: application/json" -H "X-XMesh-Timestamp: $STAMP" \
 -H "X-XMesh-Nonce: $NONCE" -H "X-XMesh-Signature: $SIG" \
 --data-binary "$REQUEST" -o "$RESP_FILE" -w '%{http_code}')" || HTTP_STATUS=000
if [[ "$HTTP_STATUS" == 000 ]];then
 echo "Panel unavailable; preserving current Xray and checking cached offline policy." >&2
 OFFLINE_POLICY=true
fi
if [[ "$HTTP_STATUS" == 403 ]];then
 # A signed request was authenticated, but the control plane denied this node.
 # The only supported 403 reason is a disabled node. A disabled node MUST
 # cease serving traffic even if the separate control timer is unavailable.
 if python3 - "$RESP_FILE" <<'PY'
import json,sys
try:
 with open(sys.argv[1],encoding="utf-8") as f:data=json.load(f)
 msg=data.get("error") or data.get("message") or ""
except (OSError,ValueError,TypeError):
 sys.exit(1)
sys.exit(0 if isinstance(msg,str) and msg.startswith("Node disabled:") else 1)
PY
 then
  echo "Node disabled by control plane: enforcing Xray shutdown." >&2
  if docker inspect xmesh-managed-xray >/dev/null 2>&1;then
   docker update --restart=no xmesh-managed-xray >/dev/null
   docker stop -t 3 xmesh-managed-xray >/dev/null
   if [[ "$(docker inspect -f '{{.State.Running}}' xmesh-managed-xray)" != false ]];then
    echo "CRITICAL: Xray is still running after stop" >&2;exit 1
   fi
   install -d -m 0700 /var/lib/xmesh-node-control
   printf 'docker\n' > /var/lib/xmesh-node-control/forced-stop
   chmod 600 /var/lib/xmesh-node-control/forced-stop
  else
   # The managed container is absent; do not touch unrelated Xray instances.
   echo "No XMesh-managed Xray container to stop." >&2
  fi
  echo "Managed Xray is stopped. Waiting for explicit reactivation." >&2
  exit 0
 fi
fi
# An unrelated 403 (e.g. reverse proxy/WAF) must not disable local
# quota/expiry enforcement. Only the recognized disabled-node response above
# can authoritatively stop the entire Xray instance.
if [[ "$HTTP_STATUS" != 200 && "$POLICY_ENABLED" == true ]];then
 echo "XMesh desired-config returned HTTP $HTTP_STATUS; using signed offline policy; panel changes NOT applied." >&2
 OFFLINE_POLICY=true
fi
if [[ "$HTTP_STATUS" != 200 && "$OFFLINE_POLICY" == false ]]; then
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
# The control agent owns reactivation. Never bypass its forced-stop marker
# by recreating a container during ordinary profile reconciliation.
if [[ -f /var/lib/xmesh-node-control/forced-stop ]];then
 echo "Xray forced-stop marker present; awaiting signed control-agent reactivation." >&2
 exit 0
fi
if [[ "$POLICY_ENABLED" == true ]];then
 if [[ "$OFFLINE_POLICY" == true ]];then
  python3 "$POLICY_GUARD" offline --state "$STATE" --node-id "$XMESH_NODE_ID" --output "$CONFIG_FILE" || {
   echo "No valid cached offline policy; leaving existing Xray intact." >&2;exit 1
  }
 else
  python3 "$POLICY_GUARD" prepare --state "$STATE" --node-id "$XMESH_NODE_ID" \
   --response "$RESP_FILE" --output "$CONFIG_FILE" || {
   echo "Invalid signed desired policy; refusing to replace active Xray." >&2;exit 1
  }
 fi
else
 if [[ "$OFFLINE_POLICY" == true ]];then
  echo "Panel offline and no autonomous policy guard installed; preserving current Xray." >&2;exit 1
 fi
python3 - "$RESP_FILE" "$CONFIG_FILE" "$XMESH_NODE_ID" <<'PY'
import json,sys,ipaddress
data=json.load(open(sys.argv[1]))
if data.get("nodeId")!=int(sys.argv[3]): raise SystemExit("Wrong node identity")
cfg=data.get("config")
if not isinstance(cfg,dict):raise SystemExit("Invalid configuration")
ibs=cfg.get("inbounds")
if not isinstance(ibs,list) or len(ibs) not in (1,2):raise SystemExit("Invalid managed inbound count")
if len(ibs)==2:
 api=ibs[1]
 if (api.get("tag")!="xmesh_stats_in" or api.get("listen")!="127.0.0.1" or
     api.get("port")!=10085 or api.get("protocol")!="dokodemo-door" or
     cfg.get("api",{}).get("tag")!="xmesh_stats_api"):
  raise SystemExit("Unexpected additional inbound; only loopback StatsService allowed")
ib=ibs[0]
if ib.get("listen")!="127.0.0.1" or ib.get("port")!=data.get("port"):raise SystemExit("Unsafe inbound listen/port")
if not isinstance(data.get("port"),int) or not 1<=data["port"]<=65535:raise SystemExit("Invalid port")
# Refuse unrelated public listeners in this managed profile.
for entry in cfg.get("inbounds",[]):
 if entry.get("listen")!="127.0.0.1":raise SystemExit("Public inbound denied")
with open(sys.argv[2],"w") as f:json.dump(cfg,f,indent=2)
PY
fi
# An active signed GeoData manifest is downloaded by the node itself. The
# autonomous guard has already verified the signature above, before URLs are read.
# A failed refresh preserves the last verified files; new rules cannot silently
# deploy without their required datasets.
GEO_SOURCE="$RESP_FILE"
if [[ "$OFFLINE_POLICY" == true ]];then GEO_SOURCE="$STATE/policy-envelope.json";fi
if [[ "$POLICY_ENABLED" == true ]] && \
 python3 - "$GEO_SOURCE" <<'PY'
import json,sys
with open(sys.argv[1],encoding="utf-8") as f: response=json.load(f)
sys.exit(0 if isinstance(response.get("policy",{}).get("geoData"),dict) else 1)
PY
then
 [[ -r "$GEO_WORKER" ]] || { echo "GeoData helper missing: update the node agent." >&2;exit 1; }
 python3 "$GEO_WORKER" prepare "$STATE" "$GEO_SOURCE"
fi
# The signed policy may request explicitly configured per-node TLS provisioning.
# Only the verified online response is eligible; cached/offline policies never
# trigger new ACME issuance. This runs before Xray's config validation.
TLS_WORKER=/usr/local/libexec/xmesh-tls-provision.py
if [[ "$POLICY_ENABLED" == true && "$OFFLINE_POLICY" == false ]] && python3 - "$RESP_FILE" <<'PYTLS'
import json,sys
with open(sys.argv[1], encoding="utf-8") as f: data=json.load(f)
sys.exit(0 if data.get("policy",{}).get("tlsProvision") is not None else 1)
PYTLS
then
 [[ -r "$TLS_WORKER" ]] || { echo "TLS provisioner missing: update node bootstrap." >&2;exit 1; }
 python3 "$TLS_WORKER" "$RESP_FILE" "$CONFIG_FILE" || {
  echo "Managed TLS prerequisites not satisfied; preserving current Xray." >&2;exit 1;
 }
fi
GEO_BIND=()
if compgen -G "$STATE/assets/*.dat" >/dev/null;then
 GEO_BIND=(-e XRAY_LOCATION_ASSET=/usr/local/share/xray -v "$STATE/assets:/usr/local/share/xray:ro")
fi
# Let's Encrypt live/ symlinks resolve into archive/. Mount the whole tree
# read-only for both validation and the managed Xray container.
TLS_BIND=()
if [[ -d /etc/letsencrypt/live && -d /etc/letsencrypt/archive ]];then
 TLS_BIND=(-v /etc/letsencrypt:/etc/letsencrypt:ro)
fi
# A 0600 configuration may contain Reality private keys. Keep it private on host.
# Run Xray as root inside the confined container (all Linux capabilities dropped)
# so the read-only bind mount remains accessible without chmod 0644.
# Use the administrator-pinned version when available. This prevents a
# configuration update or container recovery from silently reverting to latest.
IMAGE=ghcr.io/xtls/xray-core:latest
if [[ -f "$STATE/pinned-image" ]];then
 IFS= read -r IMAGE < "$STATE/pinned-image" || true
 [[ "$IMAGE" =~ ^ghcr[.]io/xtls/xray-core:[0-9]+[.][0-9]+[.][0-9]+([._+-][A-Za-z0-9._+-]+)?$ ]] || {
  echo "Invalid pinned Xray image identity; refusing to deploy latest" >&2
  exit 1
 }
fi
if [[ "$OFFLINE_POLICY" == true ]];then
 # A disconnected node must never download or switch to a different Xray image.
 # Reconcile cached authorizations using the exact locally installed image.
 IMAGE="$(docker inspect -f '{{.Image}}' xmesh-managed-xray 2>/dev/null)" || {
  echo "Offline policy requires an existing managed Xray image." >&2;exit 1
 }
 [[ "$IMAGE" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
 docker image inspect "$IMAGE" >/dev/null 2>&1 || exit 1
else
 docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE"
fi
if ! docker run --rm --network none --user 0:0 --cap-drop ALL --security-opt no-new-privileges --entrypoint xray -v "$CONFIG_FILE:/etc/xray/config.json:ro" \
 "${GEO_BIND[@]}" "${TLS_BIND[@]}" "$IMAGE" run -test -config /etc/xray/config.json;then
 echo "GeoData/config validation failed; keeping previous Xray and files." >&2
 exit 1
fi
NEW_HASH="$(sha256sum "$CONFIG_FILE" | cut -d' ' -f1)"
ACTIVE="$STATE/config.json"
PREVIOUS="$STATE/previous.json"
OLD_HASH="$(test -f "$ACTIVE" && sha256sum "$ACTIVE" | cut -d' ' -f1 || true)"
PORT="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["inbounds"][0]["port"])' "$CONFIG_FILE")"
INBOUND_NETWORK="$(python3 -c '
import json,sys
i=json.load(open(sys.argv[1]))["inbounds"][0]
s=i.get("streamSettings",{})
network=s.get("network")
alpn=s.get("tlsSettings",{}).get("alpn",[])
quic= i.get("protocol")=="hysteria" or network in ("hysteria","quic") or (s.get("security")=="tls" and network in ("masque","xhttp") and alpn==["h3"])
print("udp" if quic else "tcp")
' "$CONFIG_FILE")"

# Reconcile even when Xray's JSON is unchanged: the router may have drifted.
# Discover the *mounted* path, not a stale copy in /root/XMesh-Node.
reconcile_router_default() {
 local router dir flag backup action
 router="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/etc/xmesh-node/config.json"}}{{.Source}}{{end}}{{end}}' xmesh-node 2>/dev/null || true)"
 if [[ -z "$router" || ! -f "$router" ]];then
  echo "Router config bind mount missing; cannot verify TCP forwarding." >&2;return 1
 fi
 dir="$(dirname "$router")"
 if [[ ! -f "$dir/compose.yaml" && ! -f "$dir/docker-compose.yml" ]];then
  echo "Router Compose file missing; no unsafe port switch." >&2;return 1
 fi
 flag="$(mktemp "$STATE/router-action.XXXXXXXX")"
 backup="$(mktemp "$STATE/router-backup.XXXXXXXX")"
 cp -p "$router" "$backup"
 # BEGIN ROUTER_PORT_RECONCILER
 if ! python3 - "$router" "$PORT" "$INBOUND_NETWORK" "$PREVIOUS" "$STATE/router-managed-port" "$STATE/router-managed-udp-port" "$flag" <<'PY'
import json, os, sys, tempfile
router_path, port_str, network, previous_path, tcp_marker, udp_marker, flag_path = sys.argv[1:]
port = int(port_str)
target = f"127.0.0.1:{port}"
with open(router_path, encoding="utf-8") as f:
    router = json.load(f)
routes = router.get("routes", [])
# Match the public TCP port chosen in bootstrap, not a fixed UDP/443.
public_port = int(str(router.get("listen_tcp", ":443")).rsplit(":", 1)[-1])
if not 1 <= public_port <= 65535:
    raise ValueError("invalid public router port")
udp_listen = f":{public_port}"
def marked(path):
    try:
        with open(path, encoding="ascii") as f:
            n = int(f.read().strip())
        return f"127.0.0.1:{n}" if 1 <= n <= 65535 else None
    except (OSError, ValueError):
        return None
previous_tcp = previous_udp = None
try:
    with open(previous_path, encoding="utf-8") as f:
        inbound = json.load(f)["inbounds"][0]
    old_port = int(inbound["port"])
    old_stream = inbound.get("streamSettings", {})
    old_network = "udp" if inbound.get("protocol") == "hysteria" or old_stream.get("network") in ("hysteria", "quic") or (old_stream.get("security") == "tls" and old_stream.get("network") in ("masque", "xhttp") and old_stream.get("tlsSettings", {}).get("alpn", []) == ["h3"]) else "tcp"
    if old_network == "udp":
        previous_udp = f"127.0.0.1:{old_port}"
    else:
        previous_tcp = f"127.0.0.1:{old_port}"
except (OSError, ValueError, TypeError, KeyError, IndexError):
    pass
action = "aligned"
if network == "udp":
    old_listener = router.get("listen_udp", "")
    old_backend = router.get("udp_backend", "")
    owned = (not old_listener and not old_backend) or (
        old_listener == udp_listen and old_backend in (target, previous_udp, marked(udp_marker)))
    if not owned:
        action = "unmanaged"
    elif old_listener != udp_listen or old_backend != target:
        router["listen_udp"] = udp_listen
        router["udp_backend"] = target
        action = "changed"
else:
    old = router.get("default_tcp")
    if not isinstance(routes, list) or routes or (
        old != target and old not in (None, "127.0.0.1:9443", previous_tcp, marked(tcp_marker))):
        action = "unmanaged"
    elif old != target:
        router["default_tcp"] = target
        action = "changed"
    # If we previously enabled UDP for Hysteria, do not leave that public
    # listener pointing to a stale service after switching back to TCP.
    existing_udp = router.get("udp_backend", "")
    if router.get("listen_udp", "") == udp_listen and existing_udp and existing_udp == marked(udp_marker):
        router["listen_udp"] = ""
        router["udp_backend"] = ""
        action = "changed" if action != "unmanaged" else action
if action == "changed":
    mode = os.stat(router_path).st_mode & 0o777
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(router_path), prefix=".xmesh-router.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(router, f, indent=2)
            f.write("\n")
        os.chmod(tmp, mode)
        os.replace(tmp, router_path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
with open(flag_path, "w", encoding="ascii") as f:
    f.write(action)
PY
 then
  rm -f "$flag" "$backup"
  echo "Router config validation/update failed." >&2
  return 1
 fi
 # END ROUTER_PORT_RECONCILER
 action="$(cat "$flag")"
 rm -f "$flag"
 if [[ "$action" == unmanaged ]];then
  rm -f "$backup"
  echo "Custom or unowned $INBOUND_NETWORK router forwarding; refusing port switch to $PORT." >&2
  return 1
 fi
 if [[ "$action" == changed ]];then
  # Atomic JSON rename changes inode: restart alone retains the old file mount.
  if ! (cd "$dir" && docker compose up -d --no-deps --force-recreate xmesh-node) ||
     [[ "$(docker inspect -f '{{.State.Running}}' xmesh-node 2>/dev/null)" != true ]];then
   cp -p "$backup" "$router"
   (cd "$dir" && docker compose up -d --no-deps --force-recreate xmesh-node) || true
   rm -f "$backup"
   echo "Router recreation failed; restored previous route." >&2
   return 1
  fi
  echo "Router remounted for $INBOUND_NETWORK -> 127.0.0.1:$PORT."
 fi
 rm -f "$backup"
 if [[ "$INBOUND_NETWORK" == udp ]];then
  printf '%s\n' "$PORT" > "$STATE/router-managed-udp-port"
  chmod 600 "$STATE/router-managed-udp-port"
 else
  printf '%s\n' "$PORT" > "$STATE/router-managed-port"
  chmod 600 "$STATE/router-managed-port"
 fi
}
TLS_MOUNT_OK=true
if [[ ${#TLS_BIND[@]} -gt 0 ]];then
 if [[ "$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/etc/letsencrypt"}}{{.Source}}{{end}}{{end}}' xmesh-managed-xray 2>/dev/null || true)" != /etc/letsencrypt ]];then
  TLS_MOUNT_OK=false
 fi
fi
if [[ "$NEW_HASH" == "$OLD_HASH" && ! -f "$STATE/geo-changed" && "$TLS_MOUNT_OK" == true ]] && docker inspect -f '{{.State.Running}}' xmesh-managed-xray 2>/dev/null | grep -qx true; then
 if ! reconcile_router_default;then
  echo "Xray is healthy but $INBOUND_NETWORK router remains out of sync." >&2;exit 1
 fi
 if [[ "$POLICY_ENABLED" == true && "$OFFLINE_POLICY" == false ]];then
  python3 "$POLICY_GUARD" commit --state "$STATE" --node-id "$XMESH_NODE_ID"
 fi
 if [[ -r "$GEO_WORKER" ]];then python3 "$GEO_WORKER" commit "$STATE";fi
 echo "Xray configuration unchanged, container healthy, router reconciled."
 exit 0
fi
# Never interrupt unrelated processes on the requested local port.
if ss -l"$([[ "$INBOUND_NETWORK" == udp ]] && printf u || printf t)"nH | awk '{print $4}' | grep -Eq "(^|:)$PORT$" &&
   ! docker inspect xmesh-managed-xray >/dev/null 2>&1; then
 echo "Port $PORT is already occupied; refusing deployment." >&2; exit 1
fi
if [[ -f "$ACTIVE" ]];then cp "$ACTIVE" "$PREVIOUS";fi
install -m 0600 "$CONFIG_FILE" "$ACTIVE"
docker rm -f xmesh-managed-xray >/dev/null 2>&1 || true
if ! docker run -d --name xmesh-managed-xray --restart unless-stopped \
 --network host --user 0:0 --read-only --security-opt no-new-privileges \
 --cap-drop ALL -v "$ACTIVE:/etc/xray/config.json:ro" "${GEO_BIND[@]}" "${TLS_BIND[@]}" \
 "$IMAGE" run -config /etc/xray/config.json;then
 echo "Xray start failed; attempting rollback." >&2
 if [[ -r "$GEO_WORKER" ]];then python3 "$GEO_WORKER" rollback "$STATE";fi
 if [[ -f "$PREVIOUS" ]];then
  cp "$PREVIOUS" "$ACTIVE"
  docker rm -f xmesh-managed-xray >/dev/null 2>&1 || true
  docker run -d --name xmesh-managed-xray --restart unless-stopped --network host \
   --user 0:0 --read-only --security-opt no-new-privileges --cap-drop ALL \
   -v "$ACTIVE:/etc/xray/config.json:ro" "${GEO_BIND[@]}" "${TLS_BIND[@]}" "$IMAGE" run -config /etc/xray/config.json || true
 fi
 exit 1
fi
sleep 2
if [[ "$(docker inspect -f '{{.State.Running}}' xmesh-managed-xray)" != true ]];then
 echo "New Xray instance exited; attempting rollback." >&2
 if [[ -r "$GEO_WORKER" ]];then python3 "$GEO_WORKER" rollback "$STATE";fi
 docker logs --tail 20 xmesh-managed-xray >&2 || true
 docker rm -f xmesh-managed-xray >/dev/null 2>&1 || true
 if [[ -f "$PREVIOUS" ]];then
  cp "$PREVIOUS" "$ACTIVE"
  docker run -d --name xmesh-managed-xray --restart unless-stopped --network host \
   --user 0:0 --read-only --security-opt no-new-privileges --cap-drop ALL \
   -v "$ACTIVE:/etc/xray/config.json:ro" "${GEO_BIND[@]}" "${TLS_BIND[@]}" "$IMAGE" run -config /etc/xray/config.json || true
 fi
 exit 1
fi
# The public router must follow the validated local Xray listener.
if ! reconcile_router_default;then
 echo "CRITICAL: $INBOUND_NETWORK router was not reconciled; rolling Xray back." >&2
 if [[ -f "$PREVIOUS" ]];then
  cp "$PREVIOUS" "$ACTIVE"
  docker rm -f xmesh-managed-xray >/dev/null 2>&1 || true
  docker run -d --name xmesh-managed-xray --restart unless-stopped --network host \
   --user 0:0 --read-only --security-opt no-new-privileges --cap-drop ALL \
   -v "$ACTIVE:/etc/xray/config.json:ro" "${GEO_BIND[@]}" "${TLS_BIND[@]}" "$IMAGE" run -config /etc/xray/config.json || true
 fi
 exit 1
fi
if [[ "$POLICY_ENABLED" == true && "$OFFLINE_POLICY" == false ]];then
 python3 "$POLICY_GUARD" commit --state "$STATE" --node-id "$XMESH_NODE_ID"
fi
if [[ -r "$GEO_WORKER" ]];then python3 "$GEO_WORKER" commit "$STATE";fi
echo "Xray deployed on 127.0.0.1:$PORT ($INBOUND_NETWORK); router reconciled."
