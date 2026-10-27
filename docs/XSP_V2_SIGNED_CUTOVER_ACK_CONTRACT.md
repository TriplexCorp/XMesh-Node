# XSP-v2 — signed rotation cutover / applied-ACK contract candidate v1

> **Design + cross-language test fixtures only (27 October 2026).**
> Neither repository implements these network endpoints, trusted panel signing, a persisted Node transition, or production key rotation as part of this contract.
> Production `XMESH1` and Ed25519 remain unchanged. `strict-pq` MUST remain OFF.
> This contract must pass security review and implementation tests before any activation.
> Related: [staging prepare/prove](XSP_V2_STAGING_ROTATION_PREPARE.md) (Nexus) and [candidate base wire](XSP_V2_WIRE_SPEC.md).

## 1. Trust model and proof boundaries

- **Permit (`panel_response` / Nexus → Node):** BOTH Ed25519 **AND** ML-DSA-65 signatures from a previously pinned, independent, purpose-restricted panel keypair over the exact `permit` signing input. A certificate-valid HTTPS channel, authenticated owner UI, unsigned HTTP 200, `preparedProofVerified`, or raw keys supplied inside the response cannot authorize activation. Pin panel *public* keys from an independently authenticated channel; the `issuerId` and signer IDs are selectors, not self-proving trust anchors.
- **Applied ACK (`node_request` / Node → Nexus):** BOTH signatures by the owner-approved **pending NEW public keypair**, looked up under `(nodeId, toEpoch, both key IDs)`, over the exact `ack` input. Checking only the old active key or only one algorithm must fail. Node must explicitly persist and fsync the prepared → applied transition and monotonically protected floor **before signing**; a signature alone is a claim about disk durability, *not* cryptographic proof of persistence.
- **Owner-approved prepare:** migration `0102` has at most one pending public proposal and a one-use proved challenge; the proof does not grant cutover permission. `candidateSha256Hex` must be independently recomputed from the exact, owner-approved public keyset, epochs, purpose and key IDs using a reviewed candidate-digest serializer before a real signer is enabled; the fixture uses an opaque deterministic TEST digest to exercise bindings, not production serialization.
- The permit MUST be bound to one recipient Node, one `fromEpoch → toEpoch=fromEpoch+1` step, the previously active and pending key IDs, request ID, approval digest, TTL, and a 16-byte permit nonce. The Node rejects unknown issuer, revoked signer, absent prepared vault, wrong prepared pair, changed trust floor, stale/expired permit, nonce reuse or unauthorized `strict` suite changes.
- The ACK includes SHA-256 of the exact *signed-input bytes* of the authenticated permit, plus a fresh ACK nonce and the expected applied-state digest. Nexus checks equality to its saved permit, not a permit supplied by the untrusted ACK sender. The ACK keypair must match the pending next keypair.

## 2. Canonical signing input (`xsp2-cutover-contract-1`)

These are NEW domain-separated message classes; do **not** reinterpret `XSP2-KEY-ROTATE-PREPARE-V1`, initial enrollment signatures, generic unsigned JSON, or `XSP2-SIGNED-MESSAGE\0` as cutover consent.

Encode all of the following in the listed order, without trailing bytes:

| Field | Permit | Applied ACK |
| --- | --- | --- |
| Domain with ONE `0x00` | ASCII `XSP2-CUTOVER-PERMIT-V1\0` | ASCII `XSP2-CUTOVER-APPLIED-ACK-V1\0` |
| Version / signed direction | `0x01,0x02` (panel → Node) | `0x01,0x01` (Node → panel) |
| Integers | `u64_be(nodeId), u64_be(fromEpoch), u64_be(toEpoch)` | identical values |
| Strings | Ten `u32_be(byteLen) || ASCII(0x21..0x7e)` values, in the order below | same encoding/order |
| Time | `i64_be(issuedAtMs), i64_be(expiresAtMs)`, Unix milliseconds | same |
| Nonces | raw `permitNonce[16]`, raw `nonce[16]` | same (ACK nonce MUST be distinct) |
| Digests | raw `candidateSha256[32]`, `permitSha256[32]`, `appliedStateSha256[32]` | same |

The ten strings, **in order**, are: `requestId` (max 64), `issuerId` (64), `signerEdKeyId` (64), `signerPQKeyId` (64), `fromEdKeyId` (64), `fromPQKeyId` (64), `toEdKeyId` (64), `toPQKeyId` (64), `method` (8), `path` (256). All must be nonempty and printable ASCII without spaces. Identifiers should be restricted further to a reviewed registry at implementation time.

- Method is precisely `POST`. Candidate transport path for permit: `/api/v2/node/keys/rotation/permit`; for ACK: `/api/v2/node/keys/rotation/ack`. These paths are **reserved contract bindings only**, not live routes.
- Require `nodeId>0`, `fromEpoch>0`, checked `toEpoch=fromEpoch+1`, `issuedAtMs>0`, `issuedAtMs<expiresAtMs<=issuedAtMs+60,000`. At runtime also check bounded clock skew, rejection after expiry and durable nonce uniqueness.
- Require exactly 32 lowercase hex characters for each 16-byte nonce, and exactly 64 lowercase hex characters for each 32-byte digest. Reject all-zero nonces and candidate digest.
- The `permit` requires `nonce == permitNonce`; `permitSha256` and `appliedStateSha256` are exactly **32 zero bytes**, preventing confusion with ACK. Permit signer IDs refer to independently pinned `panel_response` keys, not pending Node keys.
- The `ack` requires `nonce != permitNonce`, `issuerId == "node-" + decimal(nodeId)`, and both signing key IDs equal the pending `toEdKeyId` and `toPQKeyId`. `permitSha256 = SHA256(exact permit signing input)`.
- `appliedStateSha256 = SHA256(ASCII("XSP2-APPLIED-STATE-V1") || 0x00 || u64_be(nodeId) || u64_be(toEpoch) || candidateSha256[32])`. Its public-digest semantics attest *which state the node claims to have durably committed*; real Node implementation must separately enforce write/fsync/atomic rename ordering, sealed-key consistency and no floor rollback.
- The outer wire envelope and actual dual-signature encoding/verification are **not implemented** by this test-only PR. The future server must verify public key purpose, expected role, both signatures, signed metadata, permit-to-ACK matching, bounded lifetimes, and storage state BEFORE any side effect.

Shared fixture in both repositories: [XSP_V2_CUTOVER_CONTRACT_VECTORS.json](XSP_V2_CUTOVER_CONTRACT_VECTORS.json). The Rust and Go test-only encoders each reconstruct both hashes independently and reject tampered role, type, nonce, path, epoch, request binding, digest and TTL. Fixtures contain **no real keys, no signature, and no proof of activation**.

## 3. Transaction / crash-safe staged state machine (implementation gates, not implemented here)

1. **`prepared_proved` (Nexus):** owner-approved, unexpired dual-PoP completed, pending public pair frozen; old pair remains trusted and suite floor unchanged. Verify panel_response key pinning is provisioned independently first.
2. **`permit_issued` (Nexus):** atomically persist the exact signed permit bytes/hash, owner approval reference, request ID, nonce, expiration and idempotency key; issue a dual-signed permit only if the proposal and current epoch still match. Multiple polls for the same request return the same decision, not new consent.
3. **`applied_ack_pending` (Node):** verify BOTH independent panel signatures, issuer/purpose, request binding and old/new candidates; atomically seal/fsync the new active vault and protected nondecreasing floor while retaining previous ciphertext and a durable pending ACK record. Stop/fail closed on mismatched local state or interrupted writes; never silently revert floor or switch back to unsigned permit.
4. **`ack_verified_committed` (Nexus):** verify the ACK signed by both **pending** new keys, compare every invariant against DB-stored permit, reject unknown/replayed ACK. In one PostgreSQL transaction, record ACK digest + irreversible epoch advancement, require expected current suite/epoch and matching proposal, keep old public keys unrevoked for separate retirement. If the same ACK/request repeats, respond idempotently with the stored result; conflicting ACKs fail.
5. **`commit_receipt_seen` (Node):** signed Nexus commit receipt / read-back needed before considering server trust switched. Retain a recovery path and previous sealed keyset until independently authorized retirement. A missing receipt MUST NOT induce Node to lower its suite floor or discard signed/retry state.
6. **`retired` (separate later workflow):** owner-approved, time-bounded retirement after confirmed convergence; no immediate deletion of old keys upon ACK, and never use legacy `/api/v2/node/keys/claim` for rotation.

**Safety under failures:** A lost permit or ACK may be retried with the same request binding. Node crash after local commit but before sending ACK must regenerate the *same logically bound* ACK from persisted state (or report a recoverable fail-closed state); it must not generate conflicting cutovers. Nexus crash after commit but before reply must return the committed result upon valid idempotent retry. Concurrent proposals, altered digests, replay, stale epoch, network partition and previous vault restore must not revoke old public keys or reduce either floor.

## 4. Explicit out-of-scope and review gates

- No new production API path or signing key. No `activate-rotation` orchestration or modifications to production Go 1.23 agent, Docker router, PostgreSQL key epoch, Nginx, active keypair, Xray profiles, `strict-pq` or TLS listeners.
- Before implementation: threat-model review, freeze public keyset candidate digest layout, trust-anchor distribution and rollover, failure/rollback matrix, exact persistence & fsync story, role-separated DB permissions, independent negative **dual-signature** verification with OpenSSL 3.5+ and Go 1.27, nonce storage and signed commit receipts.
- Before any canary: KAT/fuzz/security review, real dedicated hybrid TLS ingress, preplanned backup/recovery and explicit operator approval.
