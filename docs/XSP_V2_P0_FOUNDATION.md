# XSP-v2 P0 foundation — strict decoder, public key registry and isolated ingress

**27 October 2026 · State: committed as pre-production infrastructure only. NOT production XSP-v2.**

This stage follows [wire candidate](XSP_V2_WIRE_SPEC.md), [crypto PoC](XSP_V2_CRYPTO_POC.md), and [hybrid TLS PoC](XSP_V2_TLS_PROBE.md). The Node's existing Go 1.23/router/heartbeat, Xray, public Nginx :443 and `XMESH1` policy are unchanged.

## Deliverables

| Area | Artifact | Proven boundary |
| --- | --- | --- |
| Strict XSP-v2 decoder | [XMesh-Node `security/xspv2/poc-go/envelope/strict.go`](https://github.com/TriplexCorp/XMesh-Node/blob/main/security/xspv2/poc-go/envelope/strict.go) | **Test-only Go 1.27.3**; refuses unknown/duplicate (including nested) JSON keys, trailing data, oversized envelope/payload, malformed/short signatures, noncanonical Base64, wrong suite/direction/path, invalid nonce/epoch/lifetime and non-ASCII metadata. Re-encodes both shared signed-byte golden vectors. Only two candidate message classes are allowlisted. A parsed result is explicitly **Untrusted**. |
| Ephemeral dual-key generation | [XMesh-Node `security/xspv2/poc-go/keyring/volatile.go`](https://github.com/TriplexCorp/XMesh-Node/blob/main/security/xspv2/poc-go/keyring/volatile.go) | **Test-only, in memory**; independent cryptographic randomness for Ed25519 and ML-DSA-65, separated purpose (`node_request` / `panel_response`) and epoch, public key IDs, two signatures required. Does not write, back up or recover private signing keys. |
| Public state and anti-replay schema | [Nexus `0029_node_xsp_v2_public_state.sql`](https://github.com/TriplexCorp/XMesh-Nexus/blob/main/backend/migrations/0029_node_xsp_v2_public_state.sql) | Additive PostgreSQL tables for public verification keys, per-node minimum suite/epoch, and a unique nonce store. Private keys are **never** stored in these tables. DB trigger prevents **UPDATE** from reducing the suite floor/epoch or leaving strict phase. No rows are enrolled/activated by the migration, and no live endpoint writes to these tables. |
| Loopback ingress skeleton | [Nexus `deploy/xsp-v2-node-ingress.nginx.conf.example`](https://github.com/TriplexCorp/XMesh-Nexus/blob/main/deploy/xsp-v2-node-ingress.nginx.conf.example) | Deliberately **not installed**. Sample dedicated loopback `127.0.0.1:8444`, TLS 1.3 with only `X25519MLKEM768`, tickets/cache disabled, placeholder CA paths, and `404` for **all** HTTP requests. There is no `proxy_pass`, no TLS exposure on a public port, and no live v2 API. |

### Tests and CI

- Node standalone research module: `cd security/xspv2/poc-go && go test -race -count=1 ./... && go vet ./...`; tests verify golden vectors, nested/top-level duplicate keys, unknown fields, wrong suite/endpoint/direction, corrupted signatures, keypair generation, public-key uniqueness and lack of accidental JSON secret export.
- Nexus: `node scripts/check-xsp-v2-foundation.js` checks the additive public-only DB schema and the **non-deployed** fail-closed Nginx template. Existing backend CI and integration start disposable PostgreSQL/API and exercise schema migrations.
- Evidence is **revision-bound**, not a claim about the deployed infrastructure. See current [Node CI](https://github.com/TriplexCorp/XMesh-Node/actions/workflows/ci.yml), [Node Crypto CI](https://github.com/TriplexCorp/XMesh-Node/actions/workflows/xsp-crypto-poc.yml), and [Nexus Backend CI](https://github.com/TriplexCorp/XMesh-Nexus/actions/workflows/backend-ci.yml).

## Security limitations blocking any activation

1. **Parsing is not authentication.** `DecodeUntrustedEnvelope` never verifies either Ed25519 or ML-DSA-65 signature, peer identity, recipient, key binding, freshness against trusted time or stored nonce. No production handler may dispatch from this result.
2. **Metadata is not a full key vault.** Node private keys need an audited owner-controlled **encrypted / protected at-rest** storage model (or KMS/HSM), least privilege, atomic rollover, recovery and independent identity anchoring. Public keys in PostgreSQL do not establish trust automatically. The volatile test keypair must NEVER be used for production enrollment.
3. **SQL floor protection is partial.** The trigger prevents normal UPDATE rollback, but a sufficiently privileged DB actor can DELETE/TRUNCATE state or alter the schema; this is **not** durable, mutually pinned downgrade resistance. Production requires role-separated permissions, protected migration/backup processes, authenticated activation and a **persisted Node-side floor**, plus explicit recovery semantics. No traffic currently consumes the replay nonce table.
4. **Replay defense is not wired.** Once verification is implemented, nonce uniqueness, policy revision and side effect MUST be consumed atomically in the same transaction, checking clock skew, direction, issuer and expired data before applying commands. Never prune replay data before expiry/skew.
5. **The ingress is not deployed.** Loopback:8444 with dummy `.invalid` name and nonexistent certificate paths is only a reviewing template. Its 404 rule is intentional: it must not forward unverified requests to legacy HTTP APIs. An actual separate node-only endpoint and TLS termination topology will require a distinct reviewed deployment, certificate lifecycle, explicit routing and controls, `nginx -t`, independent observed `CurveID`/SNI, tested CDN/LB → origin hops and rollback.
6. **No unconditional TLS encryption guarantee behind a proxy.** Nginx → Nexus is currently HTTP; requiring a hybrid Node → terminator handshake alone does **not** make the whole path hybrid confidential.
7. External FIPS 204 KATs/fuzzing, formal security review, tested rotation/backup/restore, real canary nodes and owner-approved strict activation **remain open**.

## Proposed next sequence (no automatic switch)

- **PR03 continuation:** choose protected private-key storage and audited public-key enrollment, role-based database rights, append-only security auditing and two-phase epoch transitions, including deliberately authorized recovery.
- **PR04/05:** Rust and Go strict candidate decoders behind explicit opt-in v2 handlers; verify **both** signatures against pinned public keys, real request metadata and replay DB in one transaction; sign responses/configuration/commands and refuse unverified side effects.
- **PR07 actual ingress:** create a separately reviewed node-only HTTPS endpoint with verified group and real CA/SNI (without weakening the public panel); test *each* TLS hop on an isolated VPS.
- **PR08:** shadow verify, per-node dual enrollment, persisted suite floor on both sides, canary with rollback restricted to v2-capable verifier, offline-policy regression tests and owner-approved activation.

**This stage is not permission to turn on `strict-pq`, alter a running Nginx vhost or replace current Node control keys.**
