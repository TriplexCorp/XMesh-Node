# Read-only local Quota V2 cutover inventory

Run from a trusted SSH session on **each enrolled XMesh Node VPS**, from the existing Node source checkout:

```bash
sudo python3 /opt/xmesh-node/scripts/quota-v2-local-audit.py --json
```

The command is **read-only** and never modifies Xray, Docker, node identity, signed policies, quotas, or PostgreSQL. It reports fixed reason codes only, without user IDs, keys, UUIDs, signed secrets or configs.

The scanner requires root, private root-owned on-disk policy, root-owned control worker with expected release tag, **both** production strict-PQ binaries cross-checked against actual SHA-256, installer manifest and binary `--identity`, a successful `xmesh-profile-attest.py --json` check that the running managed Xray matches the committed signed config and Docker bind mount, and no active or unverifiable native `xray.service` / `v2ray.service`.

A committed version-1 policy ALWAYS blocks positive local v2 status, even when expired or granted zero bytes. `potentialLiveV1OfflineBudget=true` warns of an unexpired signed v1 policy with a nonzero per-node offline budget. A signed old policy can remain valid for **up to seven days**; fifteen minutes without v1 API polling is not sufficient retirement evidence.

A `localV2AppliedVerified=true` report confirms only the inspected local **managed** Xray installation, not other Node processes, cloned keys, alternate containers, offline machines, or the whole fleet. Therefore it ALWAYS reports `allLegacyCopiesRetiredVerified=false`, `fleetActivationAuthorized=false`, `finalMeterVerified=false`, `refundableBytes=0`.

This script is a diagnostic aid, **not an automatic activation gate**. Before flipping `XMESH_QUOTA_V2_ENABLED=1`, independently inventory all physical VPS (including disabled and offline nodes), retire every old v1 Xray/Agent and pre-issued signed offline policy, verify release/policy/actual process on each machine, and rehearse staged update and rollback. Do not upload local signed policy files or private identities to support tickets.

## Additional local process and enforcement checks

The scanner also checks a bounded list of **running** Docker containers. It expects exactly `xmesh-node` (edge router) and `xmesh-managed-xray` (signed managed Xray). Any other running container is **red until independently reviewed** because its image/name cannot prove it has no proxy listeners or stale v1 policy. Unknown/unavailable Docker inventory is red. This may conservatively flag unrelated monitoring containers; review them instead of treating a local green result as mandatory availability.

The three systemd timers `xmesh-node-control.timer`, `xmesh-xray-sync.timer`, and `xmesh-node-metrics.timer` must be both **enabled** and **active**. A timer only installed/enabled but not running means the local quota/expiry revocation loop may not execute, so local readiness is red. The script still never starts/stops any unit or Docker container. It does not scan external hosts, arbitrary native processes or cloned identities and **never** authorizes fleet activation or refunds.
