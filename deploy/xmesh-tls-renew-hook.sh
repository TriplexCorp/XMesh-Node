#!/usr/bin/env bash
set -Eeuo pipefail
# Certbot invokes this hook after a successful renewal. Restart only the
# XMesh-managed Xray when the renewed lineage is used by its ACTIVE TLS config.
[[ -n "${RENEWED_LINEAGE:-}" ]] || exit 0
ACTIVE=/var/lib/xmesh-xray-sync/config.json
[[ -r "$ACTIVE" ]] || exit 0
if python3 - "$ACTIVE" "$RENEWED_LINEAGE" <<'PY'
import json,sys
from pathlib import Path
try:
    config=json.load(open(sys.argv[1],encoding="utf-8"))
    lineage=Path(sys.argv[2])
    if lineage.parent != Path("/etc/letsencrypt/live") or not lineage.name:
        raise ValueError("untrusted renewal lineage")
    expected=str(lineage / "fullchain.pem")
    matched=any(
        cert.get("certificateFile")==expected
        for inbound in config.get("inbounds",[])
        for cert in inbound.get("streamSettings",{}).get("tlsSettings",{}).get("certificates",[])
    )
    sys.exit(0 if matched else 1)
except (OSError,ValueError,TypeError,KeyError):
    sys.exit(1)
PY
then
 if command -v docker >/dev/null && docker inspect -f '{{.State.Running}}' xmesh-managed-xray 2>/dev/null | grep -qx true;then
  echo "XMesh TLS renewed; restarting managed Xray to load new certificate"
  docker restart xmesh-managed-xray >/dev/null
 fi
fi
