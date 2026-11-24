# Quota V2 — signed, nonauthorizing reservation candidate

This is **not** a shipping positive Xray admission. The new Node-side
CI-only validator establishes the strict serialization and Ed25519
signature contract that a future Nexus issuer must satisfy before a
measured Xray runtime could receive paid byte authority.

The candidate is signed with a dedicated domain
`XMESH_QUOTA_V2_RESERVATION_CANDIDATE_V1\0`. It is a canonical
UTF-8 JSON envelope ending in exactly one newline. The verifier
requires an independently pinned Nexus policy public key, exact
schema (no unknown or duplicate JSON keys), and a fresh short-lived
validity interval (max 120 seconds).

Each candidate binds:

- Node ID, **first XSP/2 activation receipt fingerprint**, Docker
  container ID, measured process runtime fingerprint and PID;
- Nexus policy digest, billable user ID, account epoch, meter epoch,
  reservation ID and monotonic reservation revision;
- acknowledged bytes, an independently verified conservative WAL
  byte floor, per-Node and CDN spent floors, and finite shared/Node/CDN
  ceilings;
- complete sorted MAIN/CDN inbound alias classification, not only a
  user UUID; a changed class is a different signed policy scope;
- current externally authenticated WAL birth-index sequence and tail
  digest, which alone are **not** a final byte meter.

The caller must present independently measured Node/runtime/policy
and lease bindings. The parser refuses any signed field which differs
from those bindings. Signed but stale or expired candidates,
a swapped scope, foreign key, different Node/PID/container, and
lowered spent floors are refused.

When a prior authenticated candidate exists, the verifier requires
the same immutable Node/runtime/lease identity, monotonic revisions,
nondecreasing acknowledged totals, WAL totals, issuance timestamps and byte-floor continuity. A repeated
revision must be **byte-for-byte identical**; a new revision may
advance signed conservative floors without resurrecting previously
reported capacity.

**Critical deliberate hold:** every accepted candidate has the fixed
fields `authorizedBytes=0`, `canStart=false`,
`canResume=false`, `finalMeterVerified=false`,
`refundableBytes=0`. Any correctly signed attempt to turn one of
these flags on is rejected. The return value repeats the nonauthorizing
status, so a downstream caller cannot accidentally mistake candidate
signature verification for permission to bind Xray ingress.

## Remaining implementation required for real traffic

1. Nexus needs a PostgreSQL-serialized positive reservation/transfer
   issuer which verifies that *all outstanding Node grants plus
   irreversible settled bytes* fit the shared account limit.
2. Node must independently prove real Docker/kernel process identity,
   the entire previously fsynced byte WAL, externally witnessed history,
   old-writer stop/fence, policy scope and exact private statistics.
3. The actual Xray process must accept a **single use**, signed,
   time-bounded process-bound admission via its private socket and
   persist cap installation before opening the public listener.
4. Replacements, offline expiry, lost responses, duplicate signed
   packets, delayed telemetry, plan upgrades, CDN grants and process
   crashes must retain already spent absolute bytes.
5. Repeat a two-Node/two-Xray production-equivalent full XSP/2 +
   PostgreSQL test and update release pinning before enabling V2.

Until then, this validator is reachable only from offline tests and
cannot open a network listener, install a cap, refund bytes or change
`XMESH_QUOTA_V2_ENABLED=0`.
