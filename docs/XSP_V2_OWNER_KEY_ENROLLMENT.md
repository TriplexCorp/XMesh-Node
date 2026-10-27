# XSP-v2 P0 — Owner-approved dual-key enrollment and staged rotation

**Date: 2026-10-27 · Status: experimental/staging ONLY, not a production Node API.**

This follows [the staging dual-signature heartbeat](XSP_V2_EXPERIMENTAL_GATEWAY.md). Neither the default Nexus Docker image nor the production Node (Go 1.23) enables these handlers. No agent is migrated, no `strict-pq` suite-floor is activated, and the public Nginx still serves legacy traffic.

## What was implemented

- **Nexus migration `0100_node_xsp_owner_key_approval.sql`:** one outstanding owner-approved key proposal per node and purpose. Stores **public keys only**, their algorithm-labeled IDs, expected next epoch, the SHA-256 of a random 32-byte challenge, owner ID, creation/expiry (max **10 minutes**) and consumption time. No raw challenge, signing secrets, bearer token or private key is stored.
- **Owner-only approval route** `POST /api/v2/admin/nodes/{id}/key-approval`: requires an authenticated **owner** session plus special build/runtime opt-in, and that the node already has a trusted legacy `node_metric_keys` identity. The request names exact **next** key epoch and public Ed25519 (32 B) / ML-DSA-65 (1952 B) keys. Their `ed-`/`pq-` IDs must match SHA-256 fingerprints. The endpoint refuses `strict` or elevated minimum suite, and an epoch other than previous+1. Approving a replacement invalidates the previous outstanding challenge. This route is not linked to the normal owner dashboard.
- **Claim route** `POST /api/v2/node/keys/claim`: accepts no caller-chosen keys. It locks the suite-state and preapproved challenge rows, checks a fresh unconsumed approval and the exact epoch, then verifies **both** Ed25519 AND ML-DSA-65 signatures on a binary domain-separated proof binding the node ID, purpose, epoch, challenge, both public keys and key IDs. **Only after both signatures pass** does one transaction insert the new public keyset, revoke older node-request keys, increment the epoch, set phase to **`dual_enrolled`**, and consume the approval. A repeated claim, invalid signature or stale epoch leaves the existing state unchanged. No strict activation occurs, and the JSON response is **not signed**.
- **Node Go 1.27.3 research module** `keyring/enrollment.go` and `keytool prove`: signs the same binary challenge with **both** protected keys stored in its AES-256-GCM vault; emits a JSON claim containing signatures and public metadata **without exporting private seeds**. This command is **not installed** into production agents.
- **CI regression gates:** independent Rust/Go canonical proof input SHA-256 golden vector, mutated node/epoch/challenge/key tests and two-signature requirement. The isolated Crypto workflow creates a fresh encrypted Go key vault and signatures, then Rust/OpenSSL verifies both in a **direct** cross-language test. Nexus PostgreSQL integration also checks 10-minute expiration, public-key length, one approval per node/purpose, suite-floor monotonicity and nonce uniqueness.

## Precise signed enrollment input (`XSP2-KEY-ENROLL-V1`)

Both implementations must sign **identical bytes**. Integers use big-endian; text is 4-byte big-endian length + graphic ASCII.

1. ASCII `XSP2-KEY-ENROLL-V1` followed by one `0x00` byte.
2. `i64_be(nodeId)`, then `i64_be(keyEpoch)` (both positive).
3. `len32_be("node_request") || ASCII("node_request")`.
4. Exactly **32 raw challenge bytes**.
5. Exact Ed25519 **32-byte** public key then ML-DSA-65 **1952-byte** public key.
6. `len32_be(edKeyId) || ASCII(edKeyId)`, then `len32_be(pqKeyId) || ASCII(pqKeyId)`.

The independent Rust and Go tests pin SHA-256 of the public dummy-key example (Node 42, epoch 1, challenge `09` repeated 32 times, Ed key `01` repeated 32 times, ML-DSA key `02` repeated 1952 times): `902160cf06cde566b7150667d0cbbdd2971e7507d5f640925602b6fc703035a0`. These **dummy public bytes are not usable enrolled keys**.

## Staging workflow — never run against the live panel

The currently supported *manual research flow* (not a one-click provisioning UI):

1. On a disposable Linux host with Go 1.27.3, initialize a dedicated mode-0700 directory, generate the external wrapping key once using `keytool init-master`, and create a `node_request` encrypted keypair using `keytool create -node NODE_ID`. To rotate, use `keytool rotate -expected-epoch OLD_EPOCH` only after an authorized owner has scheduled that epoch. **Protect and back up the old encrypted key and wrapping key before attempting rotation; the current staging vault replaces keys and is not a production two-phase key store.**
2. Run `keytool public`. An authenticated **owner** must supply its `nodeId`, next `keyEpoch`, `ed25519KeyId`, `mldsa65KeyId`, and Base64 `ed25519Public` / `mldsa65Public` fields to the owner approval endpoint. The endpoint's request field names are `ed25519PublicB64` and `mldsa65PublicB64`. Only specifically approved candidate keys can enroll. Keep the 32-byte `challengeHex` out of public logs even though the challenge alone cannot prove private-key possession.
3. Pass the 10-minute `challengeHex` to `keytool prove -challenge CHALLENGE_HEX` locally. It prints only the `nodeId`, `purpose`, `keyEpoch`, `challengeHex` and the two Base64 signatures. Submit this JSON claim to `/api/v2/node/keys/claim` **only on the disposable feature-compiled staging backend**. The HTTP claim result is unsigned and not a trusted policy ACK.
4. After success, verify public key epoch and the `dual_enrolled` phase in PostgreSQL. The existing shadow heartbeat accepts **only** the separately approved `shadow` phase. Claim does *not* activate it, change `minimum_suite` or touch the Xray data plane.

Both new routes are absent unless the backend is built with **`--features xsp-v2-experimental`**; they additionally return 404 unless `XSP_V2_EXPERIMENTAL_HEARTBEAT=staging-only`. Existing public Nginx is **not** configured to forward them. The current loopback-only node ingress template still returns **404 for every HTTP request** by design; it is a TLS test, not an enabled v2 reverse proxy.

## Open security gates

- [ ] Owner-facing UI/UX and secure staging enrollment channel behind actual inspected X25519MLKEM768 TLS. The route is available to local staging only, not real VPS.
- [ ] Independent vetted FIPS 204 known-answer suite, fuzz/malformed key tests, formal review of proof-domain and message registry.
- [ ] Server-signed responses, request correlation and applied-policy ACKs (the JSON enrollment reply and heartbeat 204 are not signatures).
- [ ] Two-phase key rotation retaining previously trusted key material until safe cutover, identity-bound recovery, externally protected floor, secure encrypted backup/KMS or HSM, separation of signing duties and auditable revocation. **Root/DB-admin rollback resistance is not proven.**
- [ ] Trusted transport on *each* CDN/LB/ingress → backend hop, certificate lifecycle, offline-policy/canary tests, owner-approved activation, rollback with no suite downgrade.
- [ ] Verified green current CI and disposable VPS proof before any live rollout.

**Production strict-PQ remains OFF.** Existing automatic Docker/Nginx installation, v1 Ed25519 node enrollment and VPN service are unchanged.
