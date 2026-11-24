# CI-only Xray shared/Node/CDN byte ceilings

This experimental module demonstrates **one required physical enforcement
primitive** for Quota V2. It is injected only into the exact pinned disposable
Xray source under a GitHub Actions test. It is not a shipping control-plane
feature and does not turn an existing WAL birth receipt into traffic authority.

The existing experimental Xray has a trusted counted-byte path:

authenticated user alias → metered StatsService method → exact inbound/
direction provenance → WAL fsync → StatsService byte increment → deliver.

The new cap check runs under the **same gate mutex**, immediately before the
WAL fsync. After a successful durable byte-intent WAL append (and first-birth
inventory fsync), it charges three independent ceilings:

- shared Node reservation for this user (the preallocated portion of an
  eventual global budget);
- this Node's own user quota;
- the CDN quota, only for exact separately configured CDN aliases.

All directions and aliases of the same user share the first two counters.
Switching from `main` to `cdn`, from uplink to downlink, or between
multiple inbound tags must not mint extra bytes. Absent/unknown aliases and
unknown user grants fail closed when strict cap testing is armed. Exact ceiling
writes may commit, whereas the next byte is denied *before* WAL mutation.
The local cap is tied to one observed runtime fingerprint.

The unit suite asserts the actual StatsService counter equals the fsynced
per-alias WAL for all accepted bytes, no WAL exists for a denied first write,
concurrent writers cannot overspend a shared grant, an injected WAL fsync failure cannot advance either raw byte counters or an in-memory grant, unrelated Xray/WAL panics are never silently counted as quota-denial successes, CDN exhaustion doesn't
reduce a separate main bucket beyond its shared portion, and a stale runtime
cannot reuse an old cap. The pinned Xray test job runs with `-race` and
then runs the earlier complete `xmeshdrain` suite.

## Still missing for positive production admission

An independently authenticated, signed Nexus admission must durably bind
Node ID, user, **every alias and direction**, actual Xray PID/runtime,
policy revision/digest, account epoch, meter epoch, reservation ID/revision,
absolute previous charged bytes, expiry, and a serializable held ceiling.
The summed grants of both Nodes must be proven not to exceed the global
account limit, and CDN/node-specific constraints must be tracked in that
same transaction.

After crash, a new runtime must **not** reinitialize these in-memory counters
from zero. It must prove complete prior WAL byte history and old-writer
shutdown or conservatively hold all uncertain bytes before a new signed
cap may be installed. None of those admissions, carryforwards, refunds or
releases is implemented by this CI-only code. There is intentionally no
operator-facing function to install positive caps, no Docker bridge change,
no Xray start permission, and no production flag change.

`XMESH_QUOTA_V2_ENABLED=0` remains unchanged. Do not merge this experiment
as proof of end-to-end quota correctness.

## Same-Xray-runtime recovery experiment

A second CI-only function can recover a control component's cap counters
without resetting already fsynced byte intents, **provided Xray itself is
still the same process**. It must be given a separately authenticated,
exact off-host inventory-head digest and independently read live per-alias
StatsService counters. It checks the entire local WAL directory against
its inventory, refuses every prior-runtime or unlisted alias for the same
billing identity, verifies the inventory head equals the pinned witness,
and compares each raw user direction against its WAL tail. Only then can
the in-memory remaining ceilings be reconstructed by summing durable WAL
entries across MAIN and CDN aliases and both directions. Duplicate
installations are refused, even if they claim a larger cap.

The new negative matrix exercises deleted/modified WALs, deleted
inventories, stale/mismatched witnesses, changed Xray identity,
unknown aliases, reduced grants, erroneous or missing live counters,
and old runtime history. Exact same-runtime residual bytes are tested.

**Trust boundary:** the Go helper is not allowed to trust a digest just
because its caller provides one; the CI fixture merely simulates the
independently authenticated off-host anchor. Nexus must sign and
persist a specific inventory checkpoint, and the production Node must
verify that signature and the exact registered Agent/Xray process before
this operation could ever authorize traffic. It cannot restart Xray,
reconstruct deleted WAL contents from their birth index, or erase
unresolved old-runtime debt. There is still **no positive production
admission** and no V2 rollout authorization.

## Raw StatsService mutation bypass in the bounded experiment

The precharge check is the only trusted positive counted-write path. A direct
`Counter.Add`/`Counter.Set`, a wrong inbound or a post-fence mutation is
not evidence of a delivered byte and must never be allowed to mutate the
billable StatsService counter when strict byte limits are active. Previously
the observed-only drain test path marked the meter tainted but still called
the mutation callback, which would bypass the new cap check.

When the CI-only experimental cap is armed, the same gate mutex now persists
a durable taint and **panics before raw mutation** on every untrusted,
unattributed or revoked billable user counter. A previously tainted meter
cannot resume positive writes even through the trusted path. The old
observed-only behavior is retained when the CI-only cap is not armed so
existing continuity tests still measure historical taint semantics.

The new regression verifies direct `Add`, direct `Set`, a different
inbound during a valid in-flight write, unchanged raw counters, zero cap
debit, fsynced forensic taint and refusal to recover positive spending
from the tainted runtime. This remains a disposable Xray test, not
production activation.

## Signed-reservation expiry boundary in the test-only cap

Even when bytes remain in a granted ceiling, an expiry is an independent
reason to deny the **next** metered write. The test-only cap now requires a
positive absolute `validUntilMs`; the check runs while the byte/WAL mutex
is held, before every fsync attempt. The precise boundary
`now >= validUntilMs` is denied. A backwards local clock transition is
also treated as loss of time continuity and latches denial for that cap:
returning the clock to the former valid window does not restore authority.

Same-process WAL recovery requires a still-valid expiry and cannot mint
another grant from an already expired receipt. CI exercises exact expiry,
backwards-clock refusal and unsuccessful expired WAL restoration.

**Not a substitute for signed time verification:** these are Go-side,
test-only invariants. The current cap fixture supplies its own expiry; no
production Nexus receipt is verified or installed by this patch. On actual
rollout, signed Nexus reservation validity and clock continuity must both
be checked at issuance, installation, restart and in the dataplane.
