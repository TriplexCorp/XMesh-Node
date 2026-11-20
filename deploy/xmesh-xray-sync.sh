#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
# Signed pull-based reconciliation. Only the explicit XMesh-managed container is touched.
[[ $EUID -eq 0 ]] || { echo "Run as root" >&2; exit 1; }
# Fixed, root-owned managed state. Establish the physical cutoff before reading
# identity, counters or helper files: their failure may otherwise leave an old
# Xray process admitting clients when quotas cannot be enforced.
STATE=/var/lib/xmesh-xray-sync
REVOCATION_MARKER="$STATE/quota-revocation-deny-pending"
DENY_HELPER=/usr/local/libexec/xmesh-quota-revocation-marker.py
REVOCATION_FAIL_CLOSED=false
OFFLINE_POLICY=false
GEO_WORKER=/usr/local/libexec/xmesh-geodata-sync.py
SIGN_FILE=""
RESP_FILE=""
CONFIG_FILE=""
stop_managed_xray_for_revocation() {
 # An interrupted signed revocation must not leave the old admission policy
 # running or allow Docker's restart policy to resurrect its credentials.
 docker info >/dev/null 2>&1 || {
  echo "CRITICAL: cannot verify managed Xray revocation stop (Docker unavailable)" >&2
  return 1
 }
 if docker inspect xmesh-managed-xray >/dev/null 2>&1;then
  docker update --restart=no xmesh-managed-xray >/dev/null || return 1
  if [[ "$(docker inspect -f '{{.State.Running}}' xmesh-managed-xray)" == true ]];then
   docker stop -t 3 xmesh-managed-xray >/dev/null 2>&1 ||
     docker kill xmesh-managed-xray >/dev/null 2>&1 || return 1
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' xmesh-managed-xray)" != false ]];then
   echo "CRITICAL: revoked Xray could not be verified stopped" >&2
   return 1
  fi
 fi
}
# The same physical, restart-disabled stop applies when an offline policy
# cannot be verified. This is NOT signed revocation proof or a terminal byte
# meter, and it never authorizes reservation refunds.
stop_managed_xray_for_invalid_offline_policy() {
 echo "CRITICAL: cannot safely enforce cached quota policy; stopping managed Xray." >&2
 if ! stop_managed_xray_for_revocation;then
  echo "CRITICAL: failed to confirm managed Xray stopped; operator action required." >&2
  return 1
 fi
}
# The exit trap covers ALL reconciliation failures, not just offline paths:
# corrupt durable counters, missing key/helper/guard, unexpected HTTP states,
# invalid signed response or failed Xray/router validation. No old profile may
# continue accepting clients after an unverified transition. It is NOT a final
# Xray byte receipt and never enables quota refunds.
trap 'rc=$?; if [[ "$rc" -ne 0 ]];then stop_managed_xray_for_invalid_offline_policy || echo "CRITICAL: failed to confirm Xray cutoff; operator action required" >&2;fi; if [[ -e "$REVOCATION_MARKER" || -L "$REVOCATION_MARKER" ]];then stop_managed_xray_for_revocation || echo "CRITICAL: revoked Xray stop requires operator action" >&2;fi; if [[ -f "$STATE/geo-changed" && -r "$GEO_WORKER" ]];then python3 "$GEO_WORKER" rollback "$STATE" || true;fi; for temp in "$SIGN_FILE" "$RESP_FILE" "$CONFIG_FILE";do if [[ -n "$temp" ]];then rm -f -- "$temp";fi;done; exit "$rc"' EXIT
mkdir -p "$STATE"; chmod 700 "$STATE"
exec 9>"$STATE/lock"
if flock -n -E 75 9;then
 : # sole reconciler; lock held until exit
else
 rc=$?
 if [[ "$rc" == 75 ]];then exit 0;fi # another reconciler owns the lock
 echo "CRITICAL: cannot acquire reconciliation state lock" >&2
 exit "$rc"
fi
source /etc/xmesh-node-metrics.env
KEY=/etc/xmesh-node-metrics/node.key
[[ -r "$KEY" ]] || { echo "Missing Ed25519 node identity" >&2; exit 1; }
command -v docker >/dev/null
command -v python3 >/dev/null
command -v openssl >/dev/null
[[ -f "$DENY_HELPER" && ! -L "$DENY_HELPER" ]] || {
 echo "Missing production quota-v2 durable denial helper" >&2;exit 1
}
REVOCATION_STATUS="$(python3 "$DENY_HELPER" status "$STATE")" || exit 1
case "$REVOCATION_STATUS" in
 armed)
  REVOCATION_FAIL_CLOSED=true
  stop_managed_xray_for_revocation || exit 1
  ;;
 clear) ;;
 *) echo "Invalid quota-v2 denial status" >&2;exit 1 ;;
esac
# The staged WAL gate qualifies an existing WAL-capable runtime before any
# desired policy is fetched or applied. The EXIT trap enforces physical cutoff.
WAL_RECONCILE="${XMESH_QUOTA_V2_WAL_RECONCILE:-0}"
case "$WAL_RECONCILE" in
 1)
  if [[ "$REVOCATION_FAIL_CLOSED" == true ]];then
   echo "Pending revocation prevents staged WAL reconciliation." >&2;exit 1
  fi
  if ! docker inspect -f '{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}' xmesh-managed-xray |
       grep -qx 'true no';then
   echo "Staged WAL reconciliation requires a running managed Xray with restart disabled." >&2;exit 1
  fi
  timeout 100s /usr/local/sbin/xmesh-quota-wal sync --panel "$XMESH_API_URL" --node-id "$XMESH_NODE_ID" || {
   echo "External WAL continuity could not be verified." >&2;exit 1
  }
  ;;
 0) ;;
 *) echo "Invalid WAL reconciliation mode." >&2;exit 1 ;;
esac
# The signed desired-config request carries the authoritative local guard
# journal. Only the root-owned, already-persisted totals may become quota-v2
# acknowledgements; an absent ledger is valid only for first enrollment.
REQUEST="$(python3 - "$STATE/policy-usage.json" "$XMESH_NODE_ID" <<'PY'
import json,sys
from pathlib import Path
path=Path(sys.argv[1])
if path.exists():
    with path.open(encoding="utf-8") as f: ledger=json.load(f)
    if not isinstance(ledger,dict): raise SystemExit("Invalid durable quota journal")
    users=ledger.get("users",{})
    if not isinstance(users,dict): raise SystemExit("Invalid durable quota users")
else:
    users={}
if len(users)>2048: raise SystemExit("Too many durable quota users")
rows=[]
for key,entry in users.items():
    if not isinstance(key,str) or not key.isdecimal() or not isinstance(entry,dict):
        raise SystemExit("Invalid durable quota entry")
    uid=int(key)
    total=entry.get("total",0)
    if uid<=0 or type(total) is not int or not 0<=total<2**63:
        raise SystemExit("Invalid durable quota counter")
    row={"userId":uid,"usedBytes":total}
    lease=entry.get("quotaReservation")
    if lease is not None:
        if not isinstance(lease,dict): raise SystemExit("Invalid durable lease")
        for field in ("epoch","meterEpoch","reservationId"):
            value=lease.get(field)
            if not isinstance(value,str): raise SystemExit("Missing durable lease identity")
            row[field]=value
    rows.append(row)
rows.sort(key=lambda row:row["userId"])
print(json.dumps({"node_id":int(sys.argv[2]),"quotaProtocolVersion":2,
                  "quotaLocalCounters":rows},separators=(",",":")))
PY
)"
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
if [[ "$REVOCATION_FAIL_CLOSED" == true && "$POLICY_ENABLED" != true ]];then
 echo "Signed quota revocation pending but policy guard unavailable; preserving denial." >&2
 exit 1
fi
# Never admit even an HTTP 200 response when the mandatory signed quota guard
# is missing or explicitly disabled. This also removes the old raw-v1-config
# admission bypass: normal installations must ship the policy guard first.
if [[ "$POLICY_ENABLED" != true ]];then
 echo "CRITICAL: autonomous signed policy guard absent; refusing managed Xray admission." >&2
 exit 1
fi
printf 'XMESH1\nPOST\n%s\n%s\n%s\n%s\n%s\n' "$PATH_API" "$XMESH_NODE_ID" "$STAMP" "$NONCE" "$HASH" > "$SIGN_FILE"
SIG="$(openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$SIGN_FILE" | od -An -tx1 -v | tr -d ' \n')"
HTTP_STATUS="$(curl --proto '=https' --tlsv1.2 -sS --max-time 20 -X POST "$XMESH_API_URL$PATH_API" \
 -H "Content-Type: application/json" -H "X-XMesh-Timestamp: $STAMP" \
 -H "X-XMesh-Nonce: $NONCE" -H "X-XMesh-Signature: $SIG" \
 --data-binary "$REQUEST" -o "$RESP_FILE" -w '%{http_code}')" || HTTP_STATUS=000
# Rolling upgrade: Node v6.0.14 may be installed before Nexus understands
# quotaProtocolVersion. Retry the legacy request ONLY for the old control
# plane's exact unknown-request rejection, and only before any signed quota-v2
# policy/lease has ever been committed locally. Once v2 is active, fail closed.
if [[ "$HTTP_STATUS" == 400 ]] && python3 - "$RESP_FILE" "$STATE/policy-envelope.json" "$STATE/policy-usage.json" <<'PY'
import json,sys
from pathlib import Path
try:
    error_path,policy_path,ledger_path=map(Path,sys.argv[1:])
    response=json.loads(error_path.read_text(encoding="utf-8"))
    if not isinstance(response,dict) or response.get("error")!="Invalid node configuration request.":
        raise ValueError("Not the legacy request schema rejection")
    if policy_path.exists():
        if policy_path.is_symlink() or not policy_path.is_file():
            raise ValueError("Invalid committed policy")
        version=json.loads(policy_path.read_text(encoding="utf-8")).get("policy",{}).get("version")
        if version!=1: raise ValueError("Quota v2 downgrade rejected")
    if ledger_path.exists():
        if ledger_path.is_symlink() or not ledger_path.is_file():
            raise ValueError("Invalid durable quota journal")
        users=json.loads(ledger_path.read_text(encoding="utf-8")).get("users",{})
        if not isinstance(users,dict) or any(
                isinstance(row,dict) and "quotaReservation" in row for row in users.values()):
            raise ValueError("Committed v2 lease prevents downgrade")
except (OSError,ValueError,TypeError,AttributeError):
    sys.exit(1)
PY
then
  echo "Legacy Nexus schema detected before v2 cutover; using signed v1 request." >&2
  REQUEST="$(printf '{"node_id":%s}' "$XMESH_NODE_ID")"
  STAMP="$(date +%s)"
  NONCE="$(openssl rand -hex 16)"
  HASH="$(printf %s "$REQUEST" | openssl dgst -sha256 -r | awk '{print $1}')"
  printf 'XMESH1\nPOST\n%s\n%s\n%s\n%s\n%s\n' "$PATH_API" "$XMESH_NODE_ID" "$STAMP" "$NONCE" "$HASH" > "$SIGN_FILE"
  SIG="$(openssl pkeyutl -sign -rawin -inkey "$KEY" -in "$SIGN_FILE" | od -An -tx1 -v | tr -d ' \n')"
  HTTP_STATUS="$(curl --proto '=https' --tlsv1.2 -sS --max-time 20 -X POST "$XMESH_API_URL$PATH_API" \
    -H "Content-Type: application/json" -H "X-XMesh-Timestamp: $STAMP" \
    -H "X-XMesh-Nonce: $NONCE" -H "X-XMesh-Signature: $SIG" \
    --data-binary "$REQUEST" -o "$RESP_FILE" -w '%{http_code}')" || HTTP_STATUS=000
fi
if [[ "$HTTP_STATUS" == 000 ]];then
 echo "Panel unavailable; checking whether cached signed policy can authorize Xray." >&2
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
# HTTP 202 is a normal, authenticated enrollment state: the operator has
# registered the node but has not yet assigned an XRAY STUDIO profile.
# Never treat it as a signed policy or start a placeholder Xray process.
if [[ "$HTTP_STATUS" == 202 ]];then
 if ! python3 - "$RESP_FILE" "$XMESH_NODE_ID" <<'PY'
import json,sys
try:
 with open(sys.argv[1],encoding="utf-8") as f: response=json.load(f)
 valid=(isinstance(response,dict) and response.get("status")=="awaiting_profile"
        and type(response.get("nodeId")) is int and response["nodeId"]==int(sys.argv[2])
        and "config" not in response and "policy" not in response)
except (OSError,ValueError,TypeError):
 valid=False
sys.exit(0 if valid else 1)
PY
 then
  echo "Unexpected HTTP 202 body; refusing unverified provisioning state." >&2
  # The EXIT trap physically cuts off any existing managed proxy.
  exit 1
 fi
 if ! docker info >/dev/null 2>&1;then
  echo "Docker unavailable; cannot verify Xray state while awaiting a profile." >&2
  exit 1
 fi
 # If a profile is intentionally unassigned after an earlier deployment,
 # stop ONLY the XMesh-managed instance. Leaving an old policy serving
 # clients would contradict the control plane's explicit unassignment.
 if docker inspect xmesh-managed-xray >/dev/null 2>&1;then
  docker update --restart=no xmesh-managed-xray >/dev/null
  if [[ "$(docker inspect -f '{{.State.Running}}' xmesh-managed-xray)" == true ]];then
   docker stop -t 3 xmesh-managed-xray >/dev/null
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' xmesh-managed-xray)" != false ]];then
   echo "CRITICAL: Managed Xray did not stop after profile unassignment." >&2
   exit 1
  fi
 fi
 printf '%s\n' awaiting_profile > "$STATE/awaiting-profile"
 chmod 0600 "$STATE/awaiting-profile"
 echo "Node enrolled and router ready; awaiting XRAY STUDIO profile assignment. Automatic sync will retry." 
 exit 0
fi
# An unrelated 403 (e.g. reverse proxy/WAF) must not disable local
# quota/expiry enforcement. Only the recognized disabled-node response above
# can authoritatively stop the entire Xray instance.
if [[ "$HTTP_STATUS" != 200 && "$HTTP_STATUS" != 000 ]];then
 # Report only known, fixed user-actionable errors; never dump API bodies,
 # keys, profile JSON, or arbitrary server-provided strings into logs.
 python3 - "$RESP_FILE" "$HTTP_STATUS" <<'PY'
import json,sys
try:
 with open(sys.argv[1],encoding="utf-8") as f: response=json.load(f)
 message=response.get("error","") if isinstance(response,dict) else ""
except (OSError,ValueError,TypeError):
 message=""
mapping=(
 ("Assign an XRAY STUDIO profile", "Assign an XRAY STUDIO profile in Nexus."),
 ("Assigned XRAY STUDIO profile was not found", "Reassign the missing XRAY STUDIO profile."),
 ("Set a valid local Xray port", "Set a valid local Xray port in the node editor."),
 ("Automatic local-port mapping", "XRAY STUDIO profile must have exactly one managed inbound."),
 ("TLS node needs managed ACME", "Choose managed TLS or a preinstalled external certificate."),
 ("Managed TLS requires", "Complete TLS domain and ACME settings in Nexus."),
 ("Choose either managed ACME TLS", "Only one TLS certificate mode can be selected."),
 ("Profile has no Xray JSON", "XRAY STUDIO profile needs a valid Xray JSON configuration."),
 ("Invalid profile JSON", "XRAY STUDIO profile JSON is invalid."),
 ("Profile has no inbounds", "XRAY STUDIO profile has no inbounds."),
)
reason=next((safe for prefix,safe in mapping if isinstance(message,str) and message.startswith(prefix)),
            "Check XRAY STUDIO profile and node settings in Nexus.")
print(f"XMesh desired-config HTTP {sys.argv[2]}: {reason}",file=sys.stderr)
PY
fi
if [[ "$HTTP_STATUS" != 200 && "$POLICY_ENABLED" == true ]];then
 if [[ ! -s "$STATE/policy-envelope.json" ]];then
  echo "No previously issued signed offline policy; denying unmanaged traffic." >&2
  stop_managed_xray_for_invalid_offline_policy || exit 1
  exit 1
 fi
 echo "XMesh desired-config returned HTTP $HTTP_STATUS; enforcing last signed offline policy; panel changes NOT applied." >&2
 OFFLINE_POLICY=true
fi
# Missing or disabled autonomous guard is NEVER an authorization to keep
# previously issued users online when Nexus cannot deliver a verified policy.
# In particular HTTP 000 sets OFFLINE_POLICY=true before this check, so testing
# OFFLINE_POLICY=false here silently bypassed the fail-closed stop.
if [[ "$HTTP_STATUS" != 200 && "$POLICY_ENABLED" != true ]];then
 echo "CRITICAL: desired-config unavailable and autonomous policy guard absent; denying managed Xray." >&2
 stop_managed_xray_for_invalid_offline_policy || exit 1
 exit 1
fi
# The control agent owns reactivation. Never bypass its forced-stop marker
# by recreating a container during ordinary profile reconciliation.
if [[ -f /var/lib/xmesh-node-control/forced-stop ]];then
 echo "Xray forced-stop marker present; awaiting signed control-agent reactivation." >&2
 stop_managed_xray_for_invalid_offline_policy || exit 1
 exit 0
fi
if [[ -f "$REVOCATION_MARKER" && "$HTTP_STATUS" != 200 ]];then
 echo "Signed quota revocation pending: cached/offline policy cannot re-enable old Xray." >&2
 exit 1
fi
if [[ "$POLICY_ENABLED" == true ]];then
 if [[ "$OFFLINE_POLICY" == true ]];then
  # If the signed authorization lifetime has already elapsed, deny BEFORE
  # Docker config validation. A failed validation must not preserve active
  # credentials after their finite offline policy has expired. This local
  # metadata check may only DENY; the guard still verifies the signature
  # and counters before allowing any active policy.
  CACHED_LIFETIME="$(python3 - "$STATE/policy-envelope.json" "$STATE/policy-usage.json" <<'PYCACHE'
import json,sys,time
try:
 with open(sys.argv[1],encoding='utf-8') as f: document=json.load(f)
 policy=document['policy']
 issued,expiry=policy['issuedAtMs'],policy['validUntilMs']
 if (type(issued) is not int or type(expiry) is not int or
     expiry<=issued or expiry-issued>7*86400000):
  raise ValueError('invalid signed policy lifetime')
 now_ms=int(time.time()*1000)
 try:
  with open(sys.argv[2],encoding='utf-8') as f: ledger=json.load(f)
  if not isinstance(ledger,dict):raise ValueError('invalid journal')
  high_water=ledger.get('maxSeenMs',0)
  if type(high_water) is not int or high_water<0:raise ValueError('invalid durable clock')
  now_ms=max(now_ms,high_water)
 except FileNotFoundError:
  pass
 print('expired' if now_ms>=expiry else 'live')
except (OSError,ValueError,TypeError,KeyError,IndexError):
 print('invalid')
PYCACHE
)" || CACHED_LIFETIME=invalid
  if [[ "$CACHED_LIFETIME" != live ]];then
   echo "Cached offline policy is expired or invalid; refusing continued proxy admission." >&2
   stop_managed_xray_for_invalid_offline_policy || exit 1
   exit 1
  fi
  python3 "$POLICY_GUARD" offline --state "$STATE" --node-id "$XMESH_NODE_ID" --output "$CONFIG_FILE" || {
   echo "No verifiable cached offline policy or traffic counter." >&2
   stop_managed_xray_for_invalid_offline_policy || exit 1
   exit 1
  }
 else
  python3 "$POLICY_GUARD" prepare --state "$STATE" --node-id "$XMESH_NODE_ID" \
   --response "$RESP_FILE" --output "$CONFIG_FILE" || {
   echo "Invalid signed desired policy; refusing continued proxy admission." >&2
   stop_managed_xray_for_invalid_offline_policy || exit 1
   exit 1
  }
 fi
 # Guard.prepare has verified the pending Ed25519 policy and durable journal.
 # Arm a root-owned marker BEFORE optional TLS/GeoData operations. A failed
 # deploy, crash, offline fallback, or rollback cannot revive old credentials.
 if [[ "$OFFLINE_POLICY" == false ]];then
  PENDING_REVOCATION="$(python3 "$POLICY_GUARD" pending-revocation --state "$STATE" --node-id "$XMESH_NODE_ID")" || exit 1
  case "$PENDING_REVOCATION" in
   true)
    REVOCATION_FAIL_CLOSED=true
    # The file AND parent directory must be fsynced before acknowledging
    # a signed revocation. An incomplete publication refuses reconciliation.
    python3 "$DENY_HELPER" arm "$STATE" || exit 1
    ;;
   false) ;;
   *) echo "Invalid signed revocation state" >&2;exit 1 ;;
  esac
 fi
else
 if [[ "$OFFLINE_POLICY" == true ]];then
  echo "Panel offline and autonomous quota guard unavailable; denying existing Xray." >&2
  stop_managed_xray_for_invalid_offline_policy || exit 1
  exit 1
 fi
python3 - "$RESP_FILE" "$CONFIG_FILE" "$XMESH_NODE_ID" <<'PY'
import json,sys,ipaddress
data=json.load(open(sys.argv[1]))
if data.get("nodeId")!=int(sys.argv[3]): raise SystemExit("Wrong node identity")
cfg=data.get("config")
if not isinstance(cfg,dict):raise SystemExit("Invalid configuration")
ibs=cfg.get("inbounds")
if not isinstance(ibs,list) or not 1<=len(ibs)<=3:raise SystemExit("Invalid managed inbound count")
if len(ibs)>1 and ibs[-1].get("tag")=="xmesh_stats_in":
 api=ibs[-1]
 if (api.get("listen")!="127.0.0.1" or api.get("port")!=10085
     or api.get("protocol")!="dokodemo-door"
     or cfg.get("api",{}).get("tag")!="xmesh_stats_api"):
  raise SystemExit("Unexpected StatsService inbound")
 proxies=ibs[:-1]
else:
 proxies=ibs
if not 1<=len(proxies)<=2:raise SystemExit("Invalid managed proxy count")
if len(proxies)==2 and len(ibs)!=3:raise SystemExit("Missing managed StatsService")
port=data.get("port")
if type(port) is not int or not 1<=port<=65535:raise SystemExit("Invalid port")
for index, ib in enumerate(proxies):
 if ib.get("listen")!="127.0.0.1" or ib.get("port")!=port+index:
  raise SystemExit("Unsafe inbound listen/port")
 if ib.get("port")==10085:raise SystemExit("StatsService port collision")
for entry in ibs:
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
  echo "Managed TLS prerequisites not satisfied; refusing continued Xray admission." >&2;exit 1;
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
# A successfully updated release is bound to its exact local image ID. Never
# resolve the mutable registry tag again during later configuration syncs.
if [[ -f "$STATE/pinned-release.json" ]];then
 IMAGE="$(python3 - "$STATE/pinned-release.json" <<'PYPIN'
import json,re,sys
with open(sys.argv[1],encoding="utf-8") as f:d=json.load(f)
assert set(d)=={"image","imageId"}
assert re.fullmatch(r"ghcr\.io/xtls/xray-core:[0-9]+\.[0-9]+\.[0-9]+([._+-][A-Za-z0-9._+-]+)?",d["image"])
assert re.fullmatch(r"sha256:[0-9a-f]{64}",d["imageId"])
print(d["imageId"])
PYPIN
 )" || { echo "Invalid immutable Xray release pin" >&2;exit 1; }
 docker image inspect "$IMAGE" >/dev/null 2>&1 || { echo "Pinned Xray image missing locally; refusing tag drift" >&2;exit 1; }
fi
if [[ "$WAL_RECONCILE" == 1 || "$OFFLINE_POLICY" == true ]];then
 # A staged WAL runtime or disconnected node requires its current local image.
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
 echo "GeoData/config validation failed; refusing continued Xray admission." >&2
 exit 1
fi
NEW_HASH="$(sha256sum "$CONFIG_FILE" | cut -d' ' -f1)"
ACTIVE="$STATE/config.json"
PREVIOUS="$STATE/previous.json"
OLD_HASH="$(test -f "$ACTIVE" && sha256sum "$ACTIVE" | cut -d' ' -f1 || true)"

# Derive one exclusive TCP backend and one exclusive UDP backend from the
# VERIFIED signed Xray configuration. "-": no listener of that transport.
# Refuse two QUIC backends: the edge router cannot demultiplex UDP by SNI.
PORTS="$(python3 - "$CONFIG_FILE" <<'PYPORTS'
import json,sys
cfg=json.load(open(sys.argv[1],encoding="utf-8"))
inbounds=cfg.get("inbounds")
if not isinstance(inbounds,list) or not inbounds:raise SystemExit("Missing managed inbounds")
stats=inbounds[-1].get("tag")=="xmesh_stats_in"
proxies=inbounds[:-1] if stats else inbounds
if not 1<=len(proxies)<=2 or (len(proxies)==2 and not stats):
 raise SystemExit("Unsupported managed proxy layout")
if stats and (inbounds[-1].get("port")!=10085 or inbounds[-1].get("listen")!="127.0.0.1"):
 raise SystemExit("Unsafe stats listener")
tcp=udp=None
for index,ib in enumerate(proxies):
 port=ib.get("port")
 if (type(port) is not int or not 1<=port<=65535 or port==10085
     or ib.get("listen")!="127.0.0.1"):
  raise SystemExit("Invalid private proxy listener")
 if index and port!=proxies[0]["port"]+1:
  raise SystemExit("Managed port offset mismatch")
 stream=ib.get("streamSettings",{})
 if not isinstance(stream,dict):raise SystemExit("Invalid stream settings")
 network=stream.get("network","raw")
 alpn=stream.get("tlsSettings",{}).get("alpn",[])
 quic=(ib.get("protocol")=="hysteria" or network in ("hysteria","quic")
       or (stream.get("security")=="tls" and network in ("masque","xhttp") and "h3" in alpn))
 mixed=network=="xhttp" and any(p in alpn for p in ("h2","http/1.1")) and "h3" in alpn
 uses_udp=quic
 uses_tcp=(not quic) or mixed
 if uses_tcp:
  if tcp is not None:raise SystemExit("Multiple TCP backends unsupported")
  tcp=port
 if uses_udp:
  if udp is not None:raise SystemExit("Multiple UDP/QUIC backends unsupported")
  udp=port
 if len(proxies)==2:
  kind=("udp" if ib.get("protocol")=="hysteria" and network=="hysteria"
        and stream.get("security")=="tls" else
        "tcp" if ib.get("protocol") in ("vless","vmess","trojan","shadowsocks")
        and network in ("raw","tcp","xhttp","grpc","ws","httpupgrade") and uses_tcp
        and not uses_udp else "other")
  if kind=="other":raise SystemExit("Unsupported TCP/Hysteria2 managed pair")
if len(proxies)==2 and (tcp is None or udp is None):
 raise SystemExit("Expected TCP and Hysteria2 UDP backends")
print(tcp if tcp is not None else "-",udp if udp is not None else "-")
PYPORTS
)" || { echo "Failed to resolve managed transport ports." >&2;exit 1; }
read -r TCP_PORT UDP_PORT <<< "$PORTS"
PORT="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["inbounds"][0]["port"])' "$CONFIG_FILE")"
if [[ "$TCP_PORT" != "-" && "$UDP_PORT" != "-" ]];then
 INBOUND_NETWORK=both
elif [[ "$UDP_PORT" != "-" ]];then
 INBOUND_NETWORK=udp
else
 INBOUND_NETWORK=tcp
fi

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
 if ! python3 - "$router" "$TCP_PORT" "$UDP_PORT" "$PREVIOUS" "$STATE/router-managed-port" "$STATE/router-managed-udp-port" "$flag" <<'PY'
import json, os, sys, tempfile
router_path, tcp_str, udp_str, previous_path, tcp_marker, udp_marker, flag_path = sys.argv[1:]
def endpoint(value):
    if value == "-":
        return None
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid proxy port")
    return f"127.0.0.1:{port}"
tcp_target = endpoint(tcp_str)
udp_target = endpoint(udp_str)
with open(router_path, encoding="utf-8") as f:
    router = json.load(f)
routes = router.get("routes", [])
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
        former = json.load(f)["inbounds"]
    if former[-1].get("tag") == "xmesh_stats_in":
        former = former[:-1]
    for inbound in former:
        port = int(inbound["port"])
        stream = inbound.get("streamSettings", {})
        network = stream.get("network", "raw")
        alpn = stream.get("tlsSettings", {}).get("alpn", [])
        quic = (inbound.get("protocol") == "hysteria" or network in ("hysteria", "quic")
                or (stream.get("security") == "tls"
                    and network in ("masque", "xhttp") and "h3" in alpn))
        mixed = network == "xhttp" and "h3" in alpn and any(
            p in alpn for p in ("h2", "http/1.1"))
        if quic:
            previous_udp = f"127.0.0.1:{port}"
        if not quic or mixed:
            previous_tcp = f"127.0.0.1:{port}"
except (OSError, ValueError, TypeError, KeyError, IndexError):
    pass
action = "aligned"
if tcp_target is not None:
    old = router.get("default_tcp")
    if not isinstance(routes, list) or routes or (
        old != tcp_target and old not in (None, "127.0.0.1:9443", previous_tcp, marked(tcp_marker))):
        action = "unmanaged"
    elif old != tcp_target:
        router["default_tcp"] = tcp_target
        action = "changed"
if udp_target is not None:
    old_listener = router.get("listen_udp", "")
    old_backend = router.get("udp_backend", "")
    owned = (not old_listener and not old_backend) or (
        old_listener == udp_listen and old_backend in (
            udp_target, previous_udp, marked(udp_marker)))
    if not owned:
        action = "unmanaged"
    elif old_listener != udp_listen or old_backend != udp_target:
        router["listen_udp"] = udp_listen
        router["udp_backend"] = udp_target
        action = "changed"
else:
    # Do not interfere with a separately managed UDP listener.
    existing_udp = router.get("udp_backend", "")
    if (router.get("listen_udp", "") == udp_listen and existing_udp
            and existing_udp == marked(udp_marker)):
        router["listen_udp"] = ""
        router["udp_backend"] = ""
        if action != "unmanaged":
            action = "changed"
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
  echo "Custom or unowned router forwarding; refusing TCP:$TCP_PORT UDP:$UDP_PORT." >&2
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
  echo "Router remounted for TCP:$TCP_PORT UDP:$UDP_PORT."
 fi
 rm -f "$backup"
 if [[ "$UDP_PORT" != "-" ]];then
  printf '%s\n' "$UDP_PORT" > "$STATE/router-managed-udp-port"
  chmod 600 "$STATE/router-managed-udp-port"
 fi
 if [[ "$TCP_PORT" != "-" ]];then
  printf '%s\n' "$TCP_PORT" > "$STATE/router-managed-port"
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
 if [[ "$OFFLINE_POLICY" == false ]];then
 rm -f "$STATE/awaiting-profile"
 # Only after the signed deny is committed and the router is verified.
 python3 "$DENY_HELPER" clear "$STATE" || {
  echo "CRITICAL: cannot durably remove verified revocation denial" >&2
  exit 1
 }
fi
 echo "Xray configuration unchanged, container healthy, router reconciled."
 exit 0
fi
if [[ "$WAL_RECONCILE" == 1 ]];then
 echo "Staged WAL reconciliation requires separate qualification of any replacement Xray." >&2
 exit 1
fi
# Never interrupt unrelated processes on the requested local port.
if ! docker inspect xmesh-managed-xray >/dev/null 2>&1; then
 for kind in tcp udp;do
  if [[ "$kind" == tcp ]];then local_port="$TCP_PORT";socket=t;else local_port="$UDP_PORT";socket=u;fi
  if [[ "$local_port" != "-" ]] &&
     ss -l"${socket}"nH | awk '{print $4}' | grep -Eq "(^|:)$local_port$";then
   echo "Managed $kind port $local_port is already occupied." >&2
   exit 1
  fi
 done
fi
# Optional staged quota-v2 preservation of the OLD Xray process's last
# available user counters. The reconciler holds the state flock already.
# Do not call after docker rm/stop: the old in-memory counters are gone.
# THIS DOES NOT MAKE THE READINGS FINAL OR RELEASE ANY HELD QUOTA.
if [[ "${XMESH_QUOTA_V2_PRESTOP_SAMPLE:-0}" == 1 &&
      "$POLICY_ENABLED" == true && "$OFFLINE_POLICY" == false ]] &&
   [[ "$(docker inspect -f '{{.State.Running}}' xmesh-managed-xray 2>/dev/null || true)" == true ]];then
  python3 "$POLICY_GUARD" prestop-sample --state "$STATE" --node-id "$XMESH_NODE_ID" || {
    echo "Old Xray revocation meter capture failed; refusing replacement." >&2
    exit 1
  }
fi
if [[ -f "$ACTIVE" ]];then cp "$ACTIVE" "$PREVIOUS";fi
install -m 0600 "$CONFIG_FILE" "$ACTIVE"
docker rm -f xmesh-managed-xray >/dev/null 2>&1 || true
if ! docker run -d --name xmesh-managed-xray --restart unless-stopped \
 --network host --user 0:0 --read-only --security-opt no-new-privileges \
 --cap-drop ALL -v "$ACTIVE:/etc/xray/config.json:ro" "${GEO_BIND[@]}" "${TLS_BIND[@]}" \
 "$IMAGE" run -config /etc/xray/config.json;then
 echo "Xray start failed; refusing to restore stale admission." >&2
 if [[ -r "$GEO_WORKER" ]];then python3 "$GEO_WORKER" rollback "$STATE";fi
 exit 1
fi
sleep 2
if [[ "$(docker inspect -f '{{.State.Running}}' xmesh-managed-xray)" != true ]];then
 echo "New Xray instance exited; refusing to restore stale admission." >&2
 if [[ -r "$GEO_WORKER" ]];then python3 "$GEO_WORKER" rollback "$STATE";fi
 docker logs --tail 20 xmesh-managed-xray >&2 || true
 docker rm -f xmesh-managed-xray >/dev/null 2>&1 || true
 exit 1
fi
# The public router must follow the validated local Xray listener.
if ! reconcile_router_default;then
 echo "CRITICAL: $INBOUND_NETWORK router was not reconciled; stopping Xray." >&2
 exit 1
fi
if [[ "$POLICY_ENABLED" == true && "$OFFLINE_POLICY" == false ]];then
 python3 "$POLICY_GUARD" commit --state "$STATE" --node-id "$XMESH_NODE_ID"
fi
if [[ -r "$GEO_WORKER" ]];then python3 "$GEO_WORKER" commit "$STATE";fi
if [[ "$OFFLINE_POLICY" == false ]];then
 rm -f "$STATE/awaiting-profile"
 # Only after the signed deny is committed and the router is verified.
 python3 "$DENY_HELPER" clear "$STATE" || {
  echo "CRITICAL: cannot durably remove verified revocation denial" >&2
  exit 1
 }
fi
echo "Xray deployed with TCP:$TCP_PORT UDP:$UDP_PORT; router reconciled."
