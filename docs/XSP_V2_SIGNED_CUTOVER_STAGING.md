# XSP-v2 signed permit / applied ACK — staging crypto gate

**Status (27 October 2026): cryptographic primitives implemented, full P0 cutover NOT implemented.**

This change is deliberately isolated:

- Nexus: `backend/src/xsp_v2_signed_cutover.rs` compiles **only with `xsp-v2-experimental`** and exercises actual Ed25519 AND ML-DSA-65 verification/signing in OpenSSL 3.5 crypto CI. Issuer signing requires externally supplied protected private material and independently pinned `panel_response` public keys; the normal server has no new route or signer.
- Node: `security/xspv2/poc-go/cutover` is a separate Go **1.27.3 research module**, not imported by the production Go 1.23 node/router. It verifies signed Nexus permits and signed Node applied ACKs against independently provided pinned public keys with role, request ID, epoch, key ID, candidate digest, nonce, and time bindings. Both algorithms are mandatory.
- Both sides use the already reviewed *candidate* canonical domain separators and shared `XSP_V2_CUTOVER_CONTRACT_VECTORS.json`; fixture digests and signer IDs are TEST ONLY. Rust and Go tests each generate genuine dual signatures, reject substitution and missing signatures, and check metadata mutations.

**Non-goals and hard blockers (the current PRs do not solve these):**

1. A frozen real `candidateSha256` serializer over the owner-approved `0102` public bytes/key IDs/current+next epochs; the existing shared candidate fixture uses a test digest, not a database authorization. Production verifier must independently rederive it.
2. Independent, protected `panel_response` signer provisioning (KMS/process isolation), **authenticated public key pin distribution/rollover**, and explicit owner approval of the exact active/pending keysets. The signing helper does not itself prove approval.
3. Durable PostgreSQL permit issuance, one-use nonce and idempotency registry; bounded TTL and per-node locks. An authenticated signed permit is **not** replay-safe unless consumed transactionally.
4. On Node: verify the pinned signer + pending vault/floor, record cutover intent with fsync, advance protected floor, atomically install new sealed vault, then record **exact logical ACK identity persistently** and dual-sign using the *new active* keypair. Crash between steps requires fail-closed recovery; raw signature does not itself prove disk durability.
5. On Nexus: verify ACK under the *pending* **new** public keypair plus DB-stored original signed permit, then atomically advance `key_epoch` while keeping old public keys until separate authorized retirement. Lost permit/ACK/restart/duplicate/rollback/network partition must be idempotently recoverable. Signed server commit receipt is required before Node considers the server converged.
6. Independent Rust ↔ Go cross-verification of signed **permit and ACK artifacts**, database fault injection, restored-vault rollback/floor tests, dedicated hybrid TLS canary, independent KAT/fuzz/security review. No live XSP-v2 activation until these gates are completed.

**Safety invariant:** a `200 preparedProofVerified`, old-key signature, HTTPS success, unsigned reply or merely matching claimed applied-state digest NEVER authorize activation or retirement. This PR does not call `ActivatePreparedRotation`, change a database epoch, touch old keys, create publicly reachable APIs, switch `strict-pq`, or deploy to Poland-2.

CI scope:

- Go research: `cd security/xspv2/poc-go && go test -race -count=1 ./...`
- Rust experimental: `cargo test --manifest-path backend/Cargo.toml --features xsp-v2-experimental --bin xmesh-api -- xsp_v2_signed_cutover::signed_tests`
- Production backend uses default features; new cryptographic module is absent.
