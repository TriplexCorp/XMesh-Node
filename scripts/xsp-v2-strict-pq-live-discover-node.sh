#!/usr/bin/env bash
set -Eeuo pipefail
export LC_ALL=C

STATE_ROOT="${XSP_V2_STATE_ROOT:-/var/lib/xmesh-agent/xsp-v2}"
echo '=== XSP-v2 strict-PQ Node live discovery ==='
echo "stateRoot=$STATE_ROOT"

echo
echo '--- state layout ---'
for p in "$STATE_ROOT" "$STATE_ROOT/cutover" "$STATE_ROOT/keys" "$STATE_ROOT/keys/node-request.vault" "$STATE_ROOT/keys/node-request.master"; do
  if [[ -e "$p" || -L "$p" ]]; then
    printf 'FOUND %s type=%s mode=%s owner=%s:%s size=%s\n' "$p" "$(stat -c %F "$p")" "$(stat -c %a "$p")" "$(stat -c %U "$p")" "$(stat -c %G "$p")" "$(stat -c %s "$p")"
  else
    echo "MISS  $p"
  fi
done

echo
echo '--- active public key metadata only (ciphertext/master NOT printed) ---'
python3 - "$STATE_ROOT/keys/node-request.vault" <<'PY'
import json,os,sys
p=sys.argv[1]
try:
    x=json.load(open(p,encoding='utf-8'))
    public=x.get('public')
    if not isinstance(public,dict): raise ValueError('missing public metadata')
    allowed=['nodeId','purpose','keyEpoch','ed25519KeyId','mldsa65KeyId','edKeyId','pqKeyId']
    print(json.dumps({k:public[k] for k in allowed if k in public},sort_keys=True,separators=(',',':')))
except Exception as e:
    print('UNREADABLE',e)
PY

echo
echo '--- cutover journal files (contents suppressed) ---'
if [[ -d "$STATE_ROOT/cutover" ]]; then
  find "$STATE_ROOT/cutover" -maxdepth 1 -type f -printf '%f mode=%m owner=%u:%g size=%s\n' | sort
else
  echo NONE
fi

echo
echo '--- verified permit public binding ---'
python3 - "$STATE_ROOT/cutover/xsp2-verified-permit.json" <<'PY'
import base64,json,sys
p=sys.argv[1]
try:
    row=json.load(open(p,encoding='utf-8'))
    print('journalSchema='+str(row.get('schema')))
    print('envelopeSha256='+str(row.get('envelopeSha256')))
    print('permitDigest='+str(row.get('permitDigest')))
    signed=row.get('signedPermit')
    if not isinstance(signed,str): raise ValueError('signedPermit is not base64 JSON')
    envelope=json.loads(base64.b64decode(signed,validate=True))
    msg=envelope.get('message',{})
    wanted=['nodeId','fromEpoch','toEpoch','requestId','fromEdKeyId','fromPQKeyId','toEdKeyId','toPQKeyId','candidateSha256Hex','candidateSHA256Hex','issuedAtMs','expiresAtMs']
    print('permitMessage='+json.dumps({k:msg[k] for k in wanted if k in msg},sort_keys=True,separators=(',',':')))
except Exception as e:
    print('UNREADABLE',e)
PY

echo
echo '--- candidate TLS/client material (PRIVATE CONTENTS NOT PRINTED) ---'
python3 - <<'PY'
import os,stat
roots=['/root','/etc','/var/lib/xmesh-agent']
interesting=('ca.pem','root-ca.pem','client.pem','client.crt','client.key','node.crt','node.key','fullchain.pem','privkey.pem')
seen=set()
for root in roots:
    if not os.path.isdir(root): continue
    for base,dirs,files in os.walk(root):
        rel=os.path.relpath(base,root); depth=0 if rel=='.' else rel.count(os.sep)+1
        if depth>=5: dirs[:]=[]
        dirs[:]=[d for d in dirs if d not in {'.git','target','node_modules'}]
        for name in files:
            low=name.lower()
            if not (low.endswith(('.pem','.crt','.key')) and any(token in low for token in ('ca','client','node','cert','key','chain'))): continue
            p=os.path.join(base,name)
            if p in seen or os.path.islink(p): continue
            seen.add(p)
            try:
                st=os.stat(p)
                print(f'FOUND {p} mode={oct(stat.S_IMODE(st.st_mode))[2:]} uid={st.st_uid} gid={st.st_gid} size={st.st_size}')
            except OSError as e: print(f'ERR {p}: {e}')
if not seen: print('NONE')
PY

echo
echo '--- parseable X.509 certificates (public metadata only) ---'
if command -v openssl >/dev/null 2>&1; then
  while IFS= read -r -d '' p; do
    if openssl x509 -in "$p" -noout >/dev/null 2>&1; then
      echo "CERT $p"
      openssl x509 -in "$p" -noout -subject -issuer -fingerprint -sha256 2>/dev/null | sed 's/^/  /'
      openssl x509 -in "$p" -noout -ext subjectAltName 2>/dev/null | sed 's/^/  /' || true
      spki="$(openssl x509 -in "$p" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
      [[ -n "$spki" ]] && echo "  spkiSha256=$spki"
    fi
  done < <(find /root /etc /var/lib/xmesh-agent -maxdepth 5 -type f \( -name '*.pem' -o -name '*.crt' \) -print0 2>/dev/null)
else
  echo 'openssl unavailable'
fi

echo
echo '--- production activation binary ---'
for p in /usr/local/bin/xmesh-agent-xspv2-activate /root/xmesh-agent-xspv2-activate; do
  if [[ -f "$p" && -x "$p" ]]; then
    echo "FOUND $p sha256=$(sha256sum "$p"|awk '{print $1}')"
    "$p" --identity 2>&1 || true
  else
    echo "MISS  $p"
  fi
done

echo
echo 'PASS: Node discovery complete (private key/master/ciphertext contents not printed)'
