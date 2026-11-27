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

For any user with an actually **installed Ed25519 first or renewed
cap**, the patched Xray now derives the complete original MAIN/CDN alias
roster from that signed permit, not merely the subset observed in session
tracking. An alias which has never carried traffic contributes zero only
when its StatsService counter is absent AND the fsynced WAL audit confirms
that no nonzero journal exists for it. Active MAIN with unused CDN, or
fully dormant users, therefore produce a complete nonfinal old-epoch
observation; foreign or uninstalled aliases and missing WAL fail closed.
This never creates a new positive permit or refund.

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


The Agent verifies the returned nonfinal checkpoint **against every
signed MAIN/CDN alias**, not just whichever session happened to be
active. It requires sorted full-roster inbound meter rows, monotonic
integer byte counts, exact uplink/downlink sums, matching predecessor
epoch/Node/user/runtime and zero refundable bytes. A truncated row,
mismatched total, booleans in byte counters, unexpected same-user
StatsService alias or altered local checkpoint fails closed. This
additional structural verification is a defense against malformed local
IPC/retained evidence and does not prove terminal byte accounting.

## Independent fsynced old-Xray WAL audit before calendar-fence commit

The installed staging Agent no longer accepts the private Unix socket's
`drained=true` response as sufficient to persist an old-epoch handoff.
After the same verified old PID has fenced its user, Agent additionally
re-discovers the managed Xray's real Docker bind mount and reads the
root-private journal through `journal_integrity.verify_poststop_journal`.
This independently verifies the committed fence, canonical observed
checkpoint, complete fsynced birth registry and every indexed meter WAL,
including conservation of actual MAIN/CDN counter rows and rejection of
missing, torn, alien-runtime or mutated files. The resulting SHA-256 is
stored as `independentJournalSha256` alongside the **nonfinal** Xray
checkpoint. The old PID, Docker container and start identity must match
on both sides of this audit. A missing WAL birth, altered counter,
foreign process or changed journal means **no completed Agent marker**.

The real-VLESS disposable regression now cross-checks the old journal
before and after an idempotent fence response, and Agent unit tests
exercise foreign process and missing-WAL failure branches. The verified
source-pinned Xray birth registry permits 4096 journal entries: the older
512-file independent-auditor threshold was inconsistent with its real
multi-user MAIN/CDN capacity, so it now uses the registry's bound.

**This is still not an authoritative final byte count.** A compromised
Node root can tamper with local evidence, and a digest verified only
on the same VPS is not an independently retained off-host witness.
This new SHA-256 **cannot** authorize a new SQL reservation, carryforward,
refund, Xray restart or positive successor grant. Existing migration 0135
requires separately preserved full WAL birth-index bytes; that condition
and a genuinely fresh successor WAL stream must be proven before release.

## Staged remote WAL birth confirmation after the fence

Once the old user's Xray checkpoint matches the independently reread
local WAL, the Agent releases its ordinary root-state flock while it
runs the EXISTING strict-XSP/2 `charge-sync` protocol. This publishes
(or idempotently replays) the complete fsynced WAL birth index to Nexus,
then independently fetches and verifies Nexus's current signed latest
head. The returned result still has `canResume=false`,
`carryforwardApplied=false`, `finalMeterVerified=false` and zero
refundable bytes. A wholly idle old Xray without any birth-index files
is recorded distinctly as **no off-host birth index** and may not be
mistaken for an externally witnessed nonzero meter.

**The network request never holds the reconciler flock.** Once it
completes, the Agent reacquires that same lock, checks the original
signed cap/preparation and enrolled Node identity byte-for-byte,
remeasures the exact old Xray PID and config, and independently rereads
the complete journal. Only if its SHA-256 is unchanged does Agent fsync
`calendar-fence-*.json` with both the local digest and the
non-authorizing off-host registry status. If Nexus committed the index
but its answer was lost, retry authenticates that same head and repeats
the exact already-fenced Xray scope; no additional grant is created.

This permits per-user WAL closure to make progress without holding a
root flock across a slow network request. It does NOT authenticate the
final amount of traffic actually delivered, prove off-host history
before the first WAL-index bootstrap, or validate independent new-period
Xray meter isolation. Those are still necessary before a positive
successor issuance, and neither a local checkpoint nor an off-host
index alone can authorize spending.

## All old WAL stream tails must have Nexus-signed charge receipts

The remote **birth** index only proves that each WAL filename was once
registered. It does not prove that the *last* fsynced old-user byte
intent was conservatively charged in PostgreSQL. Before publishing the
Agent's nonfinal `calendar-fence-*.json`, the final root-locked stage
now independently reopens the old Docker journal, validates every
registered stream, derives the complete signed MAIN/CDN alias roster
and requires a durable **Nexus Ed25519 WAL-charge acknowledgement** for
the exact final sequence/digest/byte count of every old-user WAL file.
It uses the already tested `charge_worker._durable_cursor` verifier,
so one lost SQL COMMIT response can be retried and only its signed
receipt advances the cursor. Remaining unacknowledged WAL keeps the old
user's completion marker absent; normal scheduled `charge_worker.run`
continues submitting that debt without touching other users' leases.

A matching marker records only `allOldStreamTailsNexusAcknowledged=true`,
a digest of the verified stream heads, and explicit **no resume, no final
meter and no refund** flags. These signed receipts are conservative
pretransmit byte-intent charges, which may include bytes not ultimately
delivered by the network. They neither identify safe refunded capacity
nor prove a fresh independent meter epoch. A separately reviewed
positive successor protocol remains necessary.

A root-private regression now rejects a missing final WAL charge ACK,
accepts only the exact last-sequence receipt, and refuses a forged
old-user counter; the existing charge-worker tests verify the actual
Nexus signature/sequence contract. The end-to-end two-Node PostgreSQL
and live-Xray CI workflows still must run to certify the combined chain.

## Isolated successor Xray process discovery — proof-only

The existing process/PID verifier has been extended with an **exact two-name
allowlist**: `xmesh-managed-xray` for the original quarantined incarnation,
and `xmesh-successor-quarantine` for a second independently started
quarantined process. The same independent Docker inspection, Linux pidfd
runtime fingerprint, privilege/capabilities/namespace restrictions, Docker
network=`none`, bounded mount inventory, root-owned WAL directory and
executable/config hash checks remain mandatory for **both** names. No
arbitrary Docker container name can be supplied to weaken those checks.

The root-only disposable Docker test now starts a real original Xray and
a separately named second Xray in parallel. It requires different
container IDs, start times, host PIDs, kernel runtime fingerprints and
private WAL mount inodes; no preexisting Xray meter journal may be present
in the second process. It then stops the second process and requires
fresh measurement to fail, while the original remains independently
measured and in its original namespace. Unit tests also reject network,
namespace, capability and read-only-root violations on the successor.

This is an **independent process feasibility test**, not proof of fresh
zero MAIN/CDN StatsService counters and **not** a new positive cap.
The old instrumented Xray WAL filename still depends on runtime ID,
alias and direction; simply changing `meterEpoch` in an unchanged Xray
would reuse the same filename. The Nexus draft migration
`0160_quota_v2_successor_fresh_meter_staging.sql` therefore stores
a separate zero-authority candidate Xray identity and blocks both
legacy first-cap and renewal outboxes from spending its unfunded
candidate reservation. No Node runtime currently submits an
independently verified zero-counter preflight to that table.

Multiuser calendar handoff may share a freshly started Xray as long
as every user's old WAL remains separately owned, all users' observed
new aliases are independently zero, and the same candidate process
identity is consistent. The new SQL staging check requires all users
claiming the same container to agree on the kernel/process metadata.
None of this authorizes data-plane admission until a future positive
signing and SQL conservation flow passes end-to-end tests.

## Fresh successor measured zero-meter preflight (read-only)

The patched disposable Xray now provides `POST /v1/zero-meter` on its
existing private Unix socket. It is enabled only with the source-pinned
experimental signed-cap startup binding and requires the same-UID
`SO_PEERCRED` control peer. The request is bounded, canonical JSON
containing a Node/user, predecessor-derived nonce, candidate meter and
reservation UUIDs, and the COMPLETE signed MAIN/CDN alias roster.

With both `observed` and `gate` locks held, the new Xray verifies its
current kernel runtime ID, all User StatsService counters equal to **zero**
(including pre-registered idle aliases), no active sessions, no installed
signed caps, no old gate user state or byte intents, an empty private WAL
namespace except its own lifetime lock, and the complete birth registry.
A process already carrying bytes, even for a different user, cannot claim
pristine first-meter status. The result echoes the exact request alias
roster and candidate IDs, plus the observed runtime, SHA-256 of the empty
WAL inventory and explicit `authorizedBytes=0`,
`canSpend=false`, `canStart=false`, `canResume=false`,
`finalMeterVerified=false`, `refundableBytes=0`. It never modifies
the byte-cap map or admits VLESS.

The staged Agent's `successor_meter.py` first verifies the existing
Nexus-signed ZERO-SPEND successor, the OLD fully charged WAL close
marker, and a **different** Docker process/container/pidfd and private
WAL-root device+inode. The Agent then calls the read-only Unix endpoint
and requires the exact same candidate, runtime and signed roster; it
rechecks the new process and empty WAL root afterward. The immutable
`calendar-meter-u<user>-<predecessor-uuid>.json` marker contains only
zero-spend evidence and pinned executable/config SHA-256.

The automatic renewal worker can optionally run this second stage with
`XMESH_QUOTA_V2_FRESH_METER_STAGING=1` and the three explicit
`--successor-socket`, `--successor-executable-sha256` and
`--successor-config-sha256` arguments, **after** the old user's
signed WAL-close marker exists. The default installed service does NOT
enable this stage and never automatically creates an extra Xray.
The signed preparation and meter marker are rechecked under the
existing state lock; a damaged record fails closed. No configured
stage can issue a positive successor permit.

Source-pinned Go regressions test forged/foreign peers, noncanonical
JSON, incorrect aliases, nonzero StatsService, any installed cap, stale
WAL and pure zero-authority response fields. The existing live
MAIN/CDN VLESS acceptance fixture now probes a genuinely pristine Xray
before its FIRST signed grant, and verifies that the same process refuses
another zero-meter observation once provisioned. Node Python tests
exercise changed runtime, altered cap-authority flags, changed aliases,
and shared/unsafe/nonempty WAL directories.

**Release blockers:** this is a private process observation, not an
authenticated off-host attestable measurement. No new
`quota_v2_reservations` row, funded Nexus successor grant, confirmed
positive Unix installation or post-period real-VLESS re-admission exists.
The stage is deliberately disconnected from production quota enabling;
hosted CI must PASS before it can be considered verified.


## Draft positive successor Ed25519 pair, readmission and current blockers

After a signed zero-spend calendar preparation, irreversible old Xray
fence, independently checked original WAL, Nexus off-host registry and
Nexus-signed final charge ACK for every old stream, \`successor_meter.py\`
records a source-pinned distinct kernel/Docker runtime and truly empty
private Xray WAL. With an EXPLICIT staging opt-in,
\`renewal_worker.py\` may then call \`successor_positive.py\` over strict
XSP/2 using one deterministic request nonce derived from the original
reservation and fresh runtime. The new Nexus 0161 issuer returns two
different, separately authenticated Nexus Ed25519 domains:

- \`XMESH_XRAY_GENESIS_PREPARED_V1\0\`: strictly zero spend, bound
  to the fresh process runtime, valid for only 120 seconds.
- \`XMESH_QUOTA_V2_XRAY_CAP_ADMISSION_V1\0\`: positive bounded
  reservation, with a new meter epoch, independent fresh WAL stream
  identity, MAIN/CDN ceilings, signed aliases, a fresh expiration and
  NO start/resume/refund entitlement.

After verifying both domains, exact original user/Node/account/policy,
predecessor WAL state and unchanged new kernel PID, the Agent sends both
envelopes to the existing root-private \`/v1/quota-cap\` Xray socket.
Xray verifies original signed Genesis/permit semantics and fsyncs
\`positive-cap-u<user>.json\` before admitting any VLESS user packet;
Agent independently rechecks the received runtime and exact grant
SHA-256, then writes a root-only \`calendar-positive-u<user>-*.json\`
receipt. After a lost SQL COMMIT/HTTP reply, a repeat uses the same
request challenge and exact saved positive/grant signatures. Historical
receipt replay by itself never creates new spend authority.

The disposable source-pinned real Xray tests now include a
\`calendar-positive\` case with fresh paired signatures and live
MAIN/CDN VLESS traffic. Its WAL filename is derived from the NEW
runtime; a subsequent identical install does not refill counters. Unit
tests use actual OpenSSL Ed25519 signatures to reject changed epoch,
runtime, policy, alias, monetary ceiling, nonce and unauthorizing fields.
Nexus WAL charge selection also distinguishes the original signed
first cap from the separately signed successor cap; old streams still
select their old reservation.

The successor charge worker sends its measured runtime with the existing
XSP/2 birth-index requests. Nexus requires the successor's signed cap
scope and keeps that runtime's append-only index separately from the
first Genesis ledger. The signed head includes the runtime and a fresh
challenge. Xray can check a zero-meter candidate while another user has
an installed, intact WAL in the same successor process.

**Release is still blocked.** The successor Docker Xray remains isolated.
Public VLESS listener handoff and automatic rotation to a third process
are unfinished. The full two-Node SIGKILL and replay scenarios still need
to exercise the running stack.
Do NOT merge/enable production Quota V2 based on the signed install
receipt alone. Keep draft, main/production untouched, feature flag 0.

## Stop-only public TLS watchdog: absolute signed expiry

The SQL-backed strict-PQ TLS revocation endpoint in Nexus #592 signs a
short-lived, nonce-bound **zero-authority** witness. The dormant TLS
monitor must not translate successful checks into an unconditional ten
second extension of public ingress. The Linux pidfd guardian now takes
the earliest of the independently verified TLS authority, every signed
cap in the exact roster, and the most recent verified revocation
witness as absolute monotonic and Unix-wall deadlines. Its independent
watchdog also measures boot time (including suspend), rejects old or
malformed queued heartbeat frames and refuses late renewal even after
the guardian resumes. Losing a proof kills the owned child with SIGKILL
rather than allowing a graceful shutdown interval.

Tests use actual Linux pidfds, OpenSSL Ed25519 revocation signatures,
and a disposable TLS 1.3 loopback listener gated on guardian startup.
They verify closure of both an existing encrypted session and the
listener when the supervisor is SIGSTOPed, earlier signed expiry than
the watchdog gap, loss of the guardian, and malformed or late frames.
The local TLS harness is not a production Xray or off-host WAL proof.

No launcher, service, public binding, positive TLS authority issuer,
or new deployed Agent version is introduced here. Before promotion,
a real installed lifecycle must gate bind until fully verified evidence
and guardian readiness, contain the public child and guardian in a
single fail-closed systemd control group, authenticate the actual
release Xray executable, prove off-host WAL floors and cap ownership,
and qualify installed MAIN/CDN TLS end to end. Production Quota V2
remains OFF.

### Real systemd containment qualification (disposable CI only)

A control-group kill policy alone does not detect a simultaneously frozen
supervisor and frozen guardian while the service main PID still exists.
The dedicated hosted-Linux CI test creates a uniquely named transient
systemd service with `Type=notify`, `NotifyAccess=main`,
`KillMode=control-group`, `WatchdogSec=2s`, `WatchdogSignal=SIGKILL`,
`SendSIGKILL=yes` and `Restart=no`. It verifies that the owner, guardian
and gated TLS 1.3 loopback child really share its PID1-managed cgroup.
The test fixture pings PID1 only after the guardian ACKs a fixed short
artificial stop deadline. It tests guardian SIGKILL and simultaneous
SIGSTOP of both owners; the latter specifically requires PID1 to
report `Result=watchdog`, close the live encrypted connection, refuse a
new connection, and reap all three exact PIDFD identities.

This is a containment experiment, not a production service or proof of
a signed policy's exact stopping deadline under simultaneous failures.
No installer, release runtime, certificate lineage, WAL state, signed
authority or public bind is touched. The test fails rather than skips
when actual hosted PID1 systemd is unavailable. A future installed
service must fit its watchdog interval and proof refresh scheduling
within the shortest real authority/witness expiry and independently
qualify its actual Xray process and metering evidence.

## First-Genesis strict-PQ WAL readback (dormant diagnostic)

The separate `public_tls_wal_watch.py` experiment uses the installed product
request to `/api/v1/node/quota-v2/wal` with operation `public_tls_head`. It
requires the root-private enrolled state, original signed Genesis and full
first-cap roster, independently qualified release executable/configuration,
and the actual isolated Docker/Xray PID, start time and private ledger bind
(including the process mount namespace's device/inode). It rejects later
cap/renewal/fence/unknown ledger files, mismatched or absent persisted cap bytes,
foreign WAL aliases/runtimes, corrupt or missing streams/inventory, oversized
scans, stale/changing local counters, and untrusted responses.

The actual qualified meter always owns a zero-length, root-private
`xray-instance.lock` lifetime flock. The readback requires that exact
single-link inode, and verifies the exclusive whole-file `FLOCK` entry
in the measured Xray PID's kernel `/proc/PID/fdinfo/N` for a descriptor
whose device/inode matches the ledger path. The proof does not acquire
or modify the lock. Replaced, absent, linked, unlocked, nonempty, foreign
or changed lock evidence fails. The descriptor and inode are compared
across both snapshots. Tests use genuine process-owned Linux flock,
including transfer to a foreign live process. Do not confuse this
instance lock with a signed cap or a committed WAL birth.

The exact pinned Nexus Ed25519 signature, domain, fresh challenge, activation,
policy, profile, roster, measured process, seven-second maximum TTL,
and canonical index sequence/hash/tail must all match. HTTP 404, missing
history or a legacy fallback is NOT a signed empty history statement.
The local birth index and complete WAL digests are re-read around the strict-PQ
request, with every alias's nonce/PID-authenticated cumulative MAIN/CDN cap
counters reconciled to local WAL sums. If anything changed or the signed time
window expired, the check fails. For a nonempty index the readback proves
equality of **birth history**, not equality of off-host charge byte counters.
The signature cannot prove pre-bootstrap historical completeness, actual
delivery of every recorded intent, future absence of revocation, or terminal
meter finality. The check returns no permit even on success.

The Node regression suite exercises actual Ed25519 signatures and private
Go-format hash-chained test WAL files, including deletion and concurrent
mutation; PID/Unix-socket and product request boundaries are mocked in these
unit tests. It is not an installed end-to-end qualification. No installer,
launch path, systemd unit, product release version or public listener uses this
module. An installed two-node test, live lease/charge reconciliation and
atomic fail-closed launch/stop integration are still required before public
admission.

## Sealed TLS material before any future public spawn

The dormant certificate verifier now snapshots the root-owned Certbot
archive files and installed CA trust bundle into anonymous Linux memfds.
Every source inode is checked before/open/after copy; the complete chain,
exact non-wildcard SNI, TLS server EKU and matching private key are
verified by OpenSSL against the **sealed files** at the current time and
at the 24-hour renewal margin. A future-dated leaf cannot pass merely
because it would be valid tomorrow. The rewritten configuration differs
from the signed compiler output only in its certificate/key paths, which
identify the explicitly inherited sealed descriptors. The config is
also sealed; the private key is never embedded in it or written into a
temporary filesystem path.

A future launcher must retain the exact snapshot through child exec,
inherit only its listed material descriptors and check the original
lineage, CA, descriptor identities and elapsed lifetime in the
pre-bind and stop-monitor checks. A Certbot rotation requires a fresh
complete proof; it cannot silently substitute different bytes. The
legacy diagnostic returns paths for inspection only, not for launch.
Tests exercise actual kernel seals, independent child reads, real TLS
1.3 over a socketpair, swapped sealed descriptors, future-dated leaves,
CA/source changes and descriptor cleanup on failure.

No issuer, installer, systemd integration or public listener is enabled
by this material snapshot. It is not authorization of traffic.

## First-Genesis private route capsule (dormant)

The ordinary enrolled per-user ingress links are mutable by design during
generation cutover. The future public TLS ingress must not follow that
cutover while its signed authority still names the first Genesis runtime.
The separate root-only route capsule verifies the full original first-cap
roster, exact enrolled link set with no pending route, the original live
PIDFD/runtime identity, root-private meter directory and each required
VLESS Unix listener inode plus SO_PEERCRED. It creates a distinct private
directory containing only the original routes. The child can inherit that
one directory descriptor and use `/proc/self/fd/N/.` with the existing Go
ingress directory/Readlink contract. Replacing a pathname cannot retarget
the inherited descriptor. Any change in the enrolled routes, capsule
contents, meter identity, socket inodes, signed roster or either cap
expiry clock fails the proof. Cleanup never recursively removes substituted
paths or foreign state.

The capsule now uses Linux `open_tree(OPEN_TREE_CLONE|AT_EMPTY_PATH)`
and `mount_setattr` on a **detached** mount of its exact inode. The child
FD is reopened through that mount, checked for a distinct kernel mount ID,
the same device/inode and read-only/nosuid/nodev/noexec flags; the writable
owner descriptor is separate and never part of the child FD list. No mount
is attached to the host namespace. The kernel read-only proof is mandatory;
unsupported APIs and substituted writable descriptors fail closed. A real
capless UID-0 child cannot unlink, create a directory, retarget a link or
clear the read-only mount attribute through the passed FD. The hosted Go
peer test also uses a capless root child and capless original Unix peer.

This is mount write denial, **not** a kernel seal of directory contents.
The future launcher must still prevent the child from obtaining writable
references through other paths or other processes' descriptors, drop mount-
changing capabilities, isolate mutable enrolled state, keep the capsule
live, and stop/reap the child before releasing it. These checks do not
replace signed cap, WAL or revocation verification. Hosted CI requires
genuine Unix listeners and peer PID/UID verification; the structural tests
exercise actual detached Linux mounts and process inheritance. No public bind,
authority issuance, systemd installation or Agent version change occurs.

## Exact pinned local input bundle for pre-spawn and stop-only monitoring

`PinnedTlsInputs` compiles the exact signed TLS authority over the original
Genesis profile and independently verified cap roster, assembles the sealed
certificate/key/config inputs and the original detached read-only route
capsule, and binds them to the exact authority digest, compiled config digest,
roster object/hash and meter PID. Its child FD list contains only the config,
certificate/key memfds and read-only route descriptor, not the verified CA,
writable owner directory, meter pidfd or enrolled Agent state.

The dormant pre-spawn and periodic stop-only checks now require this same
bundle, rather than a fresh diagnostic returning mutable Certbot pathnames.
A missing, foreign, changed, expired or authorizing input witness fails; a
monitor already owning a subprocess must stop that exact child. The bundle
checks immutable descriptor identities and current source lineage/route
state on each invocation. Real signed test inputs, real sealed memfds and
detached mounts are combined in root-only tests, with a genuine kernel Unix
peer mandatory in hosted CI. A fixture signature is NOT a production issuer.

No code here execs or listens publicly. The future launcher must keep the
bundle open until the owned child is stopped and reaped, isolate other
writable paths and capabilities, verify qualified executable identity,
complete installed WAL evidence and independently establish the signed
revocation/systemd deadman stop chain. This assembly does not provide
positive authority or replace the separate WAL proof.

### Immutable qualified executable for the dormant TLS launch boundary

`PinnedTlsExecutable` independently hashes the root-owned installed release
binary and the actual original meter's kernel `/proc/PID/exe` against the
installed qualification digest; a pidfd and runtime identity fence both
observations. A bounded copy is retained as a read-only executable memfd
with write, grow, shrink, future-write, execute-bit and seal seals. No
fallback to a mutable executable pathname is permitted. A later supervisor
must exec this exact FD and verify the owned child's kernel executable inode
and original meter before admission and on every stop-monitor check.
Changing either source inode, release record, meter or sealed FD fails the
proof. This primitive is not itself a launcher or a process sandbox.

The real Linux tests execute only a disposable non-listening compiled fixture:
same bytes executed by pathname fail the inode proof; modifying/truncating
the memfd or changing its execute bits is denied by the kernel. The tests
also reject missing/mismatched source bytes, meter exit, replacement source
inode, descriptor substitution and expired assembly. Actual installed
qualified Xray exec, full isolation, stop/reap, WAL qualification and a
positive Nexus issuer remain mandatory; no public listener is enabled.

The nonauthorizing pre-spawn gate now requires the exact sealed executable
bound to the original metered runtime twice: before other evidence and
after external revocation/cap probes. The stop-only monitor checks the
actual owned child's kernel exec inode before other proofs, before each
deadman pulse and after the guardian ACK. Missing, foreign, replaced or
authorizing proof kills the exact owned child. This is still NOT an exec,
confinement, public authority or installed service.


### Actual post-exec child descriptor proof (dormant)

The local input bundle captures exact supervisor descriptor identities at
assembly, and independently inspects the directly owned live child's
kernel `/proc/PID/fd` and `fdinfo` before/after stop-only checks. Every
original config/certificate/key/route FD must retain its inode, descriptor
number, mount ID and access flags (apart from close-on-exec); the detached
route must still be read-only/nosuid/nodev/noexec. Extra descriptors to the
protected supervisor objects, including the writable route view, CA,
enrolled Agent directory and original meter identity handles, fail the
proof. The owner snapshots are compared again rather than accepting new
objects at a reused FD number. The exact directly owned PID and start time
are checked across a bounded scan.

The stop-only monitor cannot refresh its independent guardian before and
after the current child executable **and inherited input** proof. Wrong,
lost, retargeted or authorizing proof stops the owned child. Real capless
root Linux fixtures use genuine sealed memfds and a detached mount, reject
same-number substitution, the same route inode on a writable mount, leaked
CA/owner FDs, extra protected aliases and changed owner descriptors. The
complete signed input-bundle test also verifies the independent capless
child's actual descriptors while it is alive. No test opens a public
listener. This is not a complete sandbox: unrelated runtime FDs are not
certified safe, and a future launcher must isolate other namespaces and
filesystem access, drop capabilities and obtain full signed/WAL authority
before any public publication.


### Actual capless child thread credentials (dormant)

The post-exec child proof now reads every thread's actual kernel procfs
status, not a launcher-supplied claim or only the main PID. It requires
root UID/GID in all four credential slots, no extra supplementary groups,
no tracer, no-new-privs and zero inherited/permitted/effective/bounding/
ambient capabilities. Any missing, changing or privileged thread fails
before and after the descriptor scan and independently bound PID checks.
The bounded thread scans compare the exact live thread set. Tests use a
real capless multithreaded process and an independently privileged process
inheriting the exact same sealed inputs; only the former passes. This
does not prove a complete mount, PID, seccomp, cgroup or network sandbox,
and does not create a listener or a positive authority.

### Namespace-independent original Unix peer identity (dormant)

A future capless TLS child must not retain host PID/procfs access merely
because the current ingress dialer compares `SO_PEERCRED.Pid` with a
host numeric PID. In a real descendant PID namespace, an ancestor Unix
peer has PID **0** in both credentials and the child's procfs pidfd
metadata. The dormant `public_tls_peer_identity` primitive verifies the
actual connected root stream via Linux `SO_PEERPIDFD`: the returned
private CLOEXEC descriptor must be a live **pidfs** kernel object, with
the exact device/inode token captured by the supervisor on the original
measured PID's still-pinned pidfd. It independently checks the
namespace-relative PID from kernel credentials and fdinfo, root UID/GID
and liveness; it closes the fresh peer pidfd and never passes the
supervisor's pidfd into the child. A missing API, old shared anon-inode
pidfd implementation, different same-UID process, dead process,
inheritable supervisor pidfd or corrupt token fails closed.

Actual nested PID/mount namespace tests run with a new procfs,
no-new-privs and all five capability masks zero. They verify an ancestor
PID is invisible, the actual peer PID is zero, the pidfs object still
matches, and another invisible root peer is refused. They also verify
the detached directory remains read-only and a signal-zero attempt on
the ancestor peer pidfd is denied. Hosted CI additionally requires a
fresh Unix connection through a detached read-only directory descriptor
in that namespace, without inheriting a connected socket, and a
different root process's listener in the same directory must fail.

This is a **kernel feasibility and refusal primitive only**. It does
not change the existing Go dialer or Xray artifact, the pinned route or
input bundle, Agent installation, authority, production flags, or
listeners. A future reviewed dialer must bind this token to exact
immutable inputs, use the isolated readonly meter directory instead of
the host proc PID path, authenticate before forwarding any application
bytes, and demonstrate its actual namespace, FD, seccomp and stop-chain
requirements on the independently qualified executable. Do not weaken
the original dialer's PID check or make unsupported kernels eligible.

### Exact pre-bound TCP identity and capless private-network child (dormant)

The public TLS compiler may eventually require a privileged port such
as 443. Reintroducing CAP_NET_BIND_SERVICE into the serving Xray or
changing the host's privileged-port sysctl is not acceptable.
`public_tls_bound_listener` is a read-only identity primitive: it pins an
already-bound **not listening** exclusive IPv4 TCP descriptor's exact
signed address/port, kernel device/inode, socket cookie and network
namespace cookie. It independently requires an unconnected stream with
no reuse, device override, freebind or transparent socket option.
The future owned child must inherit the same object, never an alternate
endpoint or a connected stream; the same identity and the expected
listen phase can subsequently be rechecked. This module never opens
or binds a socket, listens, accepts, or grants authority itself.

The required hosted test uses a fresh disposable network namespace
containing only loopback, verified distinct from PID1's host network
namespace. It sets the privileged-port floor to 1024 **inside that test
namespace only** and requires a real capless process to receive EACCES
on an independent bind of port 443. The owner then binds loopback 443
but does not listen. A separate capless PID/network namespace inherits
only the exact bound descriptor, proves the socket belongs to the
ancestor's isolated namespace and its own fresh socket does not, and
waits for explicit fixture synchronization. Connection before that
marker must be refused; afterwards the capless child must accept and
echo a real loopback TCP connection over the original descriptor.
The workflow independently checks the host sysctl stays unchanged.
No traffic or listen bind is made on the host's external network.

This is **not** Xray inherited-listener support, a launcher, seccomp
policy, positive signed authority, public listener, or production
qualification. The future executable must use exact signed listener
FDs, prevent independently created public/outbound sockets, and stop
and reap before releasing other pinned identities. The bound socket
owner copy is different: release it before listen, as qualified below. No installed worker,
release version or metered Xray artifact changes here.

### Actual private root and PID namespace topology proof (dormant)

A capability-free UID 0 is not proof that Xray cannot read the Agent's
state by absolute path or an inherited host procfs. The dormant
`public_tls_namespace.py` pins the supervisor's exact retained,
root-owned mode-0700 tmpfs root FD and namespace identities. It verifies
the kernel's actual child mount, PID, network, IPC and UTS namespaces
differ from the supervisor's while user namespace is unchanged; the
exact root inode is mounted read-only/nosuid/nodev/noexec, and mountinfo
has exactly a private tmpfs root and private read-only procfs. Its procfs
PID 1 must identify the same actual child's PID namespace, root and
executable. The actual child is namespace init, and pidfd liveness,
birth, all thread capless credentials and stable mount/namespace
snapshots are checked in a bounded observation window.

The disposable fixture actually pivots into the tmpfs, detaches old
root, mounts its own procfs, execs a static sealed executable with all
capabilities cleared, proves Agent state/host shadow are absent and
root writes fail with EROFS. The single-thread disposable supervisor
creates the new PID namespace for its next child, spawns directly (no
wrapper PID), then restores its original namespace for future children
before starting the actual deadman. The Popen PID is itself the child
namespace init, the guardian remains in the supervisor PID namespace,
and an expired fixture deadline kills that exact init with SIGKILL. It rejects a different root, writable root,
unexpected extra read-only mount, nonisolated child and ordinary
non-mount-root directory. CI requires a fresh private mount namespace
before creating any mount. No installed launcher, association to the
qualified Xray, seccomp/cgroup proof, authority issuance, public bind,
or production flag changes are supplied by this primitive. Those
independent gates are still required.

### Namespace-native immutable meter input bundle (dormant)

The original `FirstGenesisRoutes` is intentionally a supervisor-side
readback of installed route symlinks, including host PID paths. A child
inside its own PID namespace cannot use these paths. The dormant
`public_tls_namespace_route.NamespaceMeterInputs` borrows that exact
live original route capsule, including its still-pinned meter pidfd,
but prepares only two child inputs: a detached read-only/nosuid/nodev/
noexec view of the original meter socket directory, and a sealed
anonymous manifest of the exact authenticated alias roster, runtime,
roster SHA, directory/mount identity, every original listener inode and
kernel pidfs device/inode.
The manifest has neither host PID nor host-proc path and the original
pidfd and writable directory are not passed. Unsigned aliases, an extra
socket/file, changed original evidence, writable view substitution or
an identical-content replacement manifest fail closed. The detached
view's parent resolves to its own root, not an enclosing directory.
The actual capless private PID namespace test connects to the exact
inherited meter directory, verifies the manifest and root peer pidfs
identity, then rejects a replaced same-UID invisible Unix listener.
The original route capsule must remain live until child stop/reap.

This does **not** implement the Go dialer yet, change signed Xray,
integrate the inherited input bundle into a launcher, grant authority
or publish a port. Only an independently qualified future dialer may
consume these inputs, checking the authenticated alias/tag before any
application bytes, and the actual kernel peer for every connection.
No existing installed service or production flag changes.

### Namespace-native Go dialer kernel proof (dormant)

The standalone Go package under
`experiments/quota-v2-physical-stop/namespacepeer` consumes the exact
sealed manifest from the preceding input bundle. It requires separate
expected runtime/roster hashes, canonical JSON (byte-identical Go
re-encoding, rejecting duplicate/foreign fields), exact uint64
identities, in-scope alias and inbound tag, actual readonly detached
meter directory/mount and particular original Unix socket inode.
An actual AF_UNIX connection must expose UID/GID 0 and invisible
PID 0, plus a fresh CLOEXEC live `SO_PEERPIDFD` from pidfs matching
the immutable original token; fdinfo, liveness and identity are
rechecked before returning the stream. It closes the transient peer
pidfd and rechecks the original manifest/socket after dialing. It
never sends a byte, retries another endpoint or uses host procfs.

The hosted capless private-PID fixture runs the compiled Go code
against original live sockets, then exercises wrong alias/tag,
foreign runtime/roster and same-UID different pidfs token, changed
listener inode, whitespace and duplicate manifest fields. This
separate package is NOT injected into Xray, not a launcher or public
authority and not a candidate release. Existing Go production
`DialIngressMeter` remains unchanged until the separately qualified
replacement is integrated and attested.

### Exclusive listener ownership transfer and nonduplicating stop readback (dormant)

A retained supervisor copy would let the kernel keep a TCP listener
alive after SIGKILL of the serving child. The original pre-bound
socket owner must therefore close its actual copy after verifying
exact child inheritance **and before listen**; the guardian must
never inherit it either. The dormant `public_tls_listener_readback`
uses bounded live directly-owned child procfs FD inode/birth proof
and the kernel INET_DIAG IPv4 TCP LISTEN dump for the original
network namespace, exact endpoint, root UID, inode and socket cookie.
It never duplicates or reopens a listener. Missing/overlapping
listener, mismatched cookie/inode, invalid/partial/foreign netlink
response, or retained owner/guardian FD fails closed.

The hosted test is a new disposable loopback-only private network
namespace: direct capless child namespace init receives the original
unlistening 443 FD, parent proves its own retained copy is detected,
closes it, verifies both supervisor and independent guardian FD
inventories, and verifies connection refusal before fixture gate.
After a real guardian ACK, the child listens and serves an echo; the
parent independently reads exact INET_DIAG identity. When heartbeat
expires, actual guardian SIGKILL of PID1 must produce no kernel
listener and ECONNREFUSED while the supervisor itself remains alive.
No host sysctl change, public bind, actual authority, Xray inherited
listener integration, seccomp policy or installed service is supplied.

### Irreversible kernel network fence (dormant candidate)

The socket syscall filter alone would be insufficient: an inherited bound
IPv4 socket or accepted TCP stream still belongs to the original network
namespace, and seccomp cannot inspect the pointed-to sockaddr. The dormant
`public_tls_network_fence` installs a mandatory Linux Landlock ABI >= 4
ruleset handling TCP bind and connect with **no allow rules**. It then
installs a native amd64 classic seccomp filter denying new sockets other
than AF_UNIX SOCK_STREAM (optional CLOEXEC/NONBLOCK, protocol zero),
socketpair, bind, address-based sends, ancillary FD import/export,
io_uring and selected namespace/descriptor entry points. Native architecture
and x32 syscall handling are explicit. This is a network fence, **not**
a complete syscall allowlist, cgroup proof or positive launch authority.
It requires a single-thread capless root no-new-privs pre-exec process.
Failure is terminal for the child; there is no weak-policy fallback.

The required hosted diagnostic uses only an explicitly disposable network
namespace with loopback. A capless nested PID/net namespace process inherits
the exact unlistening TCP socket, plus a deliberately extra unconnected
TCP socket used only for the negative test. It must refuse new internet,
datagram, netlink and ancillary FD operations, deny TCP connect using the
inherited negative socket, successfully echo on the transferred listener and
connect to an original pathname Unix meter fixture, then refuse reuse of an
accepted socket for egress even after an attempted AF_UNSPEC disconnect.
A real independent TCP destination must receive no connection. No production
network, installer, Xray artifact, authority, version or flag is changed.
The subprocess must exit on unsupported/missing Landlock or filter failure;
passing local structural tests without the actual hosted network test is
not qualification. Actual Go/Xray integration and independent complete
sandbox/stop-chain proofs remain required.

### Actual Go transfer adapter behind the irreversible network fence (dormant)

A future Xray TCP transport cannot call its normal bind/listen path in the
isolated child. The separate `namespacepeer.AdoptTransferred` Go adapter
checks the independently measured signed IPv4 endpoint, original socket
device/inode and both kernel cookies, exclusive options and unconnected
phase before listen. It uses `net.FileListener` only on the inherited
descriptor after the caller's exclusive-transfer gate. It checks the
resulting Go pollable TCP listener's exact kernel identity and closes
the input FD before returning. Any failure closes the owned FD and the
new listener. No other endpoint is created or used.

The hosted fixture compiles the real Go package, installs Landlock and
seccomp in the capless direct child before exec into Go, then requires
Go to reject independently created TCP listeners and dials. The
supervisor verifies exact child FD inheritance, drops its own FD and
checks that the endpoint is not listening. The Go adapter must reject
every incorrect token, adopt the precise bound socket, transfer actual
TCP payload to a disposable Unix meter and return its echo. Independent
procfs and INET_DIAG readback prove the new Go FD has the exact kernel
identity, with no remaining owner or guardian copy and only one child
listener FD. Real deadman expiry kills exact namespace PID1; require
physical listener removal and ECONNREFUSED while supervisor lives.

This is a **standalone transport qualification**, not an attested Xray
change, production launcher or permission. The Unix fixture is raw
connectivity; the separately qualified namespace-native manifest and
peer verifier must be integrated into the actual Xray candidate,
alongside the exact sealed listener inputs and full stop chain. No
installer, version, Agent target, public authority or deployment change.
