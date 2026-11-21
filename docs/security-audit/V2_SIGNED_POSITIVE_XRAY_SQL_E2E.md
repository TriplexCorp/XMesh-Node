# Quota V2 — positive signed Xray cap, disposable end-to-end boundary

This branch is stacked on Node #169 → #168 → #165 → #164. It **does not**
enable the production quota or deploy an updated Agent/Xray. All positive
spending demonstrated here is inside pinned, disposable Go test processes.

## Implemented behavior (real instrumented Xray code)

A new **Ed25519-signed, canonical** first-genesis cap binds the exact Nexus
Node, user ID, original activation fingerprint, measured Linux Xray process,
desired-policy SHA, account/meter epoch, reservation ID/revision, nonce,
ordered MAIN/CDN alias set, time limits and three byte ceilings:

- Shared user reservation portion held by this Node.
- Per-Node user limit, independent of the global user budget.
- Per-Node CDN allowance for signed CDN aliases only.

The parser rejects unsigned, wrong-key, duplicate-key, unknown-key,
noncanonical, out-of-scope, expired, replayed or oversized grants. A grant
cannot claim authority to **start/restart Xray** or refund bytes.

For **first-ever zero-WAL Genesis only**, installation checks the independently
supplied first-activation context, current runtime, policy and lease, requires
no old meter-inventory entries or historic user debt, and verifies zero live
StatsService counters for every admitted alias/direction.

The complete signed grant is fsynced to a private `0600` file, with the
directory fsynced, **before** the process exposes the positive spend cap.
Another installation with the same Node/user/lease is refused, including
concurrent retries. The real `Register()` entry point blocks authenticated
user sessions without a valid cap, after expiry, for foreign aliases, and
after shared/Node/CDN exhaustion. Accepted bytes still pass the existing
exact-alias WAL fsync and counter mutation under the same mutex.

This is a *test-only installer called directly by CI*, not a production
XSP/2 or private Xray admission endpoint.

## PostgreSQL ↔ Ed25519 ↔ Xray proof

The dedicated workflow boots **PostgreSQL 17**, checks out a pinned Nexus
revision, applies the **actual** migrations 0125, 0126, 0127, 0128, 0137
and 0138, and uses the **real** PostgreSQL `quota_v2_reserve` and runtime
preflight functions (not a mock allocator). It then builds the pinned
instrumented Xray Go code with the race detector and launches two
independent OS test processes.

A scaled-byte example models the requested 1000 / 700 / 500 / 150 layout:

| Item | Offered | PostgreSQL held | Verified Xray WAL |
|---|---:|---:|---:|
| Global shared cap | 1000 bytes | 1000 bytes total | 1000 bytes total |
| Node 47 MAIN + CDN | 700 bytes | 700 bytes | 700 bytes |
| Node 48 MAIN + CDN | 500 bytes | **300 bytes** | 300 bytes |
| CDN (per Node) | 150 bytes maximum | Signed per Node | 150 bytes per Node |

Both processes must match their own StatsService values, user alias
scope and durable WAL exactly. Additional byte writes are denied before
the raw counter changes.

The workflow then exits the first two processes and starts two **new**
OS processes against the same persisted grant files and fsynced WAL
directories. A new process has a new Linux runtime fingerprint, sees old
unresolved WAL debt, cannot reuse the signed first grant, cannot create
a new grant by changing inbound, and cannot insert a second first-genesis
record in real PostgreSQL. After these replay attempts the server account
still has 1000 held, 0 settled, and no refunded capacity.

Tests also cover signing-key substitution, exact canonical JSON, wrong
Node/PID/runtime/policy/epoch, foreign alias, CDN classification,
overdraft, clock expiry, and many concurrent duplicate installs.

## What this does NOT prove

The signing script is an **ephemeral test key**, not Nexus's persistent
`PolicySigner`. It directly simulates the authenticated Node echo and
independent live process/scope attestation, which the real strict XSP/2
Agent has not yet wired into this path. The two OS processes are compiled
test binaries exercising actual Xray metering modules, **not two installed
systemd Agent services, real VLESS clients or public TCP listeners**.

The signed first-genesis cap is not an authorization to install a new
cap against existing WAL history or old process debt. No observed
checkpoint here is final accounting; nothing unlocks refund, plan reset
or a new epoch.

### Required before shipping

1. Implement Nexus-side positive Ed25519 issuer with a serializable,
   authenticated transaction, using its persistent policy key and
   independently enrolled strict XSP/2 identity.
2. Bind Node's *actual* installed Xray kernel/process, Docker profile,
   signed user policy, full MAIN/CDN inbound membership, off-host WAL
   witness and already acknowledged spent floor to the issuer.
3. Implement a root-private installed-agent → Xray control channel
   that verifies this issuer, with cap installation/fsync before opening
   any public dataplane connection.
4. Prove restart/upgrade/rollback, delayed/duplicate ACKs, real VLESS
   uplink/downlink and MAIN/CDN traffic under both installed Agent and
   real Xray, including the actual 1000/700/500/150 MiB-scale test.
5. Retain `XMESH_QUOTA_V2_ENABLED=0`, draft PRs and no production
   migration until the full signed chain passes CI and operator review.
