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


## Experimental positive-cap local handoff (NOT a release route)

The draft experiment first_cap_handoff.py now exposes callable functions,
not installed commands:

- verify_grant checks canonical Ed25519 first-cap bytes using the existing
  pinned Nexus PolicySigner key, plus the original signed Genesis and
  previously signed quarantined policy. It denies mismatched Node, user,
  activation, policy SHA-256, runtime, old WAL, oversized limits,
  expiry, start/resume permissions and refunds.
- The user must be held with zero offline budget in the original signed
  policy. Every granted MAIN/CDN alias must resolve to exactly one VLESS
  client with the user's original Xray ID and email in the signed profile.
  The local install scope is derived from that verified information; it
  cannot be supplied by the positive grant's caller.
- install_staged_cap acquires the normal root-owned reconciliation lock,
  reads the fsynced evidence with O_NOFOLLOW, rechecks the owner's enrolled
  strict-XSP/2 activation, and measures the actual isolated Linux Xray PID
  before and after admission. An independently release-verified executable
  SHA-256 pin is **required**. The actual config bytes must hash to the
  original Nexus-signed profile. Only then does the verified private Unix
  peer installer receive the original grant and derived scope.
- The real OpenSSL test suite tests signature forgery, changed account,
  user/policy/runtime, expiry, aliases, zero-WAL claims, and a mocked
  root-private locked handoff to the existing local Xray socket.

**Still blocked:** Nexus does not serve the real positive issuer over the
owner-enrolled XSP/2 path, and the installed Agent has not been wired to
obtain a signed permit or release-qualified executable pin. This function
is not exposed as a normal installed command and never opens VLESS itself.
The test fixtures do not prove two installed Nodes and two real Xray servers
with genuine Nexus-issued caps. Keep production Quota V2 OFF.

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


## Draft Agent control-v6.0.27: original strict-PQ SQL reserve/echo

The opt-in `/usr/local/sbin/xmesh-quota-genesis-reservation` command
is installed on the disposable staging Agent; it is **not** run by normal
systemd control, and the main release remains unchanged. It requires
root, a private state directory and the existing reconciliation flock.

On a clean first-Genesis candidate that already has the original
`genesis-quarantine-envelope.json`:

```bash
sudo /usr/local/sbin/xmesh-quota-genesis-reservation --panel https://DISPOSABLE-NEXUS.example --node-id 47 --user-id 101 --state /var/lib/xmesh-xray-sync --operation prepare
sudo /usr/local/sbin/xmesh-quota-genesis-reservation --panel https://DISPOSABLE-NEXUS.example --node-id 47 --user-id 101 --state /var/lib/xmesh-xray-sync --operation confirm
```

No user-provided epoch/reservation is trusted by confirm: the installed
helper reads the **original root-private signed prepare** receipt. It
verifies the original Genesis and signed zero-budget policy, the same
pinned Nexus signing key and original strict-PQ Node activation, the
measured isolated Xray process and valid lease clock; the exact signed
responses are persisted as separate immutable files under the normal
reconciler lock. Both replies have `authorizedBytes=0` and cannot
start/resume Xray or refund traffic.

The later experimental `first_cap_handoff.install_staged_cap` now
requires BOTH the signed prepared and signed confirmed lease evidence,
with identical account/meter/reservation identity. It requires its
positive Ed25519 grant's revision and byte ceiling to match the
confirmed lease, remeasures the independently pinned executable/config,
then delegates to the PID/Unix-peer verified local Xray socket.

**This is NOT live release qualification.** No genuine Nexus positive
XSP/2 cap issuance and independent historical WAL/kernel attestation
is connected yet. A private reservation alone never enables public
VLESS. Only run on isolated disposable guests with explicit opt-in
staging and immutable Nexus commit pin; no production flags or VPS
were changed.


## Draft automatic calendar handoff: signed preparation → irreversible old-Xray fence

The 20-second `control-v6.0.27` staging renewal worker now separates
three **different** states. A signed first/renewed cap is spendable only
until its exact immutable `validUntilMs`. A signed
`calendar-successor-prepared` object is **zero authority** and is
persisted before the Agent attempts to fence the old process. Finally,
`calendar-fence-u<user>-<old-reservation>.json` holds only a **nonfinal**
checkpoint received from the original measured Xray PID over its
UID-checked Unix socket.

After Nexus confirms a real calendar boundary, the Agent authenticates
the original signed quarantined roster and the successor Ed25519 domain,
remeasures the original executable/config/runtime and invokes the
existing `/v1/fence` control endpoint under the existing root flock.
Xray fsyncs the scoped denial intent *before* cancelling all aliases,
waits for its tracked sessions/readers/writers to drain and records the
observed StatsService/WAL checkpoint. The deterministic local fence UUID
is a staging **stop identifier**, not an administrative revocation
authorization. On lost Unix responses the identical Xray scope is retried.
A forged/mismatched marker never grants access; it fails closed.

For signed users who have **never started a VLESS session**, the
instrumented Xray may derive the complete idle MAIN/CDN roster from its
already installed Ed25519 first cap, but only with zero in-memory usage,
no prior WAL inventory births for that user and no unexpected counters.
It still writes only a nonfinal, zero-byte observation, never a positive
permit.

The Node regression covers lost IPC replies, marker tampering, unchanged
Xray PID, idempotency and no positive install. The disposable patched
Xray test additionally opens genuine MAIN and CDN VLESS streams, fences
the old user, checks both streams close, checks the WAL files are
byte-for-byte unchanged on replay, and refuses new old-epoch sessions.

**Not completed:** none of these records is a terminal meter or
refundable balance. The old Xray remains fenced permanently. There is
still **no verified independent successor WAL meter**, newly funded
PostgreSQL lease, signed positive successor cap, or checked installation
against that new meter. A preparation or fence receipt MUST NOT be
accepted as authorization to restart, resume or reset any counter.
Hosted Actions must execute the new tests before claiming PASS. Keep
the production flag disabled and both PRs draft.
