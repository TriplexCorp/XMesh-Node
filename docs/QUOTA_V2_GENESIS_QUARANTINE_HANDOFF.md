# Quota V2 first-genesis quarantine from an installed strict-XSP/2 Agent

**Experimental, manual/opt-in, NO spending authority. Not a positive
Xray permit and NOT an automated production startup path.**

The exact installed command is
`/usr/local/sbin/xmesh-quota-genesis-quarantine`.
It is installed root-only by the existing
`deploy/install-v6-strict-operational-agents.sh`
alongside `/usr/local/sbin/xmesh-quota-wal`; no separate daemon,
network port or installer step is added. The command does not run at boot
and does not modify the managed Xray configuration or service.
In GitHub it is `experiments/quota-v2-physical-stop/quarantine_policy.py`.

A disposable, newly enrolled Node can exercise this path after an
independently pinned, isolated Docker Xray with WAL has been started
**without any network or public ingress**:

```bash
sudo /usr/local/sbin/xmesh-quota-genesis-quarantine \
  --panel https://YOUR-DISPOSABLE-NEXUS.example \
  --node-id YOUR-DISPOSABLE-NODE-ID \
  --state /var/lib/xmesh-xray-sync
```

Required Nexus experimental gates are
`XMESH_QUOTA_V2_ENABLED=1`,
`XMESH_QUOTA_V2_WAL_TRANSPORT=1`,
`XMESH_QUOTA_V2_XRAY_GENESIS_STAGING=1` and
`XMESH_QUOTA_V2_GENESIS_QUARANTINE_STAGING=1`.
These must **never** be changed on production for this experiment.
No private signing keys may be stored in the repository or command line.

## What happens

1. Require root and the existing root-owned private
   `/var/lib/xmesh-xray-sync` state directory. Acquire the SAME
   `state/lock` flock as `xmesh-xray-sync.sh` so the ordinary reconciler
   cannot replace Xray during staging. An existing Ed25519 policy pin is
   used unchanged and never silently rotated. If this is a newly enrolled
   Node without the original policy key pin, request its public key
   through **the existing owner-enrolled strict-PQ product tunnel** on
   `/api/v1/node/quota-v2/policy-pin`. Nexus first checks original
   activation and pristine Genesis. The already pinned product TLS/XSP
   identity authenticates this response, including its 0-byte/no-start
   status and activation digest. Write the first Ed25519 policy pin
   atomically with root-only permissions and directory `fsync`.
   Plain HTTPS or unauthenticated TOFU is never accepted.
2. Generate an unpredictable 256-bit challenge internally. Inspect the
   isolated Docker Xray's real Linux process, executable, config and WAL
   without believing a caller-supplied runtime ID. Send a
   `prepare_genesis` request using the installed strict-PQ product client;
   verify the Ed25519-signed original Genesis receipt under the pinned
   Nexus key, original strict product activation, expiry and no authority.
3. Send the SAME runtime ID and challenge with
   `quotaGenesisQuarantine=true` via the INSTALLED
   `xmesh-agent-xspv2-product request` on the already registered
   `/api/v1/node/desired-config` path. No curl/legacy Ed25519 fallback.
4. Reject a response unless it explicitly says `status=quarantined`,
   `publicIngressAllowed=false`, `canStart=false`,
   `canResume=false`, `authorizedBytes=0`; every signed user is
   `onHold=true` with `offlineBudgetBytes=0`.
5. Verify the original Nexus Ed25519 policy signature with OpenSSL and
   the pinned public key. Match config SHA256, original policy SHA256,
   Node, Xray measured runtime/challenge, original activation, and
   120-second Genesis window.
6. Reinspect the Xray process after the network operation. Reject PID,
   container, executable, config or isolation changes. Durably save the
   exact signed zero-authority evidence to a **root-only** local file
   using file `fsync`, atomic rename and parent directory `fsync`;
   refuse conflicting writes, symlinked paths or overwritten evidence.
7. Print only non-secret status and policy SHA256. Never connect the
   Docker network, run VLESS, install a cap, invoke Docker restart or
   mutate the existing active policy.

The special installed helper is still opt-in and the lock is
released after saving zero-authority evidence. A later automatic ordinary
reconciliation intentionally refuses to open the staged Node: positive
admission must eventually be integrated into the same supervised
Agent lifecycle/lock interval before VLESS can be opened.

Existing normal `xmesh-xray-sync.sh` intentionally REJECTS any such
HTTP 200 response rather than applying the quarantined profile as an
ordinary policy. Its fail-closed guard is also tested in Node CI.

## Verification

`tests/test_quota_v2_quarantine_handoff.py` exercises **actual OpenSSL
Ed25519 policy signatures** and rejects a changed key, policy, runtime,
challenge, positive budget, permissive ingress flag, invalid TTL,
duplicate JSON keys, oversized reply, tampered profile SHA and
post-network Xray PID substitution. It checks write+fsync evidence
idempotency, conflict rejection and that the installed XSP client
request carries the original measured candidate ID and challenge.

This does **not** validate a production TLS hop (the unit test mocks
product transport), a real Ubuntu/systemd 8 MiB positive-grant E2E,
a complete historic WAL, privileged Linux kernel attestation, or the
installed Agent's positive Xray control socket. This is only the safe
first handoff that the existing ordinary policy path previously
prevented. DO NOT set `XMESH_QUOTA_V2_ENABLED=1` on production.
