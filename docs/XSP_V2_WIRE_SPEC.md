# XSP-v2 — wire format and security review candidate (PR01)

> **Status: draft for architecture/security review, NOT an active protocol.**
> Both repositories intentionally retain their existing `XMESH1` and Ed25519 behaviour.
> Neither hybrid signatures nor PQ TLS, enrolment, minimum-suite pinning or strict mode is implemented by this document and its test-only encoders.
> Source of architectural scope: [XMesh Nexus full XSP-v2 plan](https://github.com/TriplexCorp/XMesh-Nexus/blob/main/docs/HYBRID_POST_QUANTUM_SECURITY_IMPLEMENTATION_PLAN.md).
>
> Schema identifier: `xsp2-wire-candidate-1`. Any incompatible decision must advance the schema/protocol version and regenerate all three independent vector checks. Do not use the candidate for a production signing key until reviewed.

## 1. Scope, trust boundaries and observed v1 facts

| Message / component | Observed today | v2 security requirement |
| --- | --- | --- |
| Agent request ingestion | Nexus `backend/src/node_auth.rs`: `XMESH1\nPOST\n{path}\n{nodeId}\n{timestamp}\n{nonce}\n{sha256(body)}\n`; Ed25519; nonce persisted in PostgreSQL | Separate v2 authentication with BOTH signatures, endpoint binding, max sizes, no replays |
| Node registration | Nexus `backend/src/node_enrollment.rs`: owner-issued short-lived token and Ed25519 possession proof | Independent ML-DSA proof, bound node identity and explicit owner approval |
| Desired configuration | Nexus `backend/src/node_policy.rs`: Ed25519 signature of `serde_json::to_vec(policy)`; `node_runtime.rs` publishes `policySignature` and public key | Sign complete critical response metadata and digest of applied Xray config, pin trust anchors |
| Command polling | Nexus `node_runtime.rs` can return commands or `enforceStop`; signed agent request is NOT equivalent to a signed response | Sign command, ACK and no-command/stop response with replay and revision binding |
| Router heartbeat | Node `heartbeat.go`: independently constructs `XMESH1` with Ed25519 (Go module currently declares Go 1.23) | Shared v2 encoder/verifier and audited key separation |
| Metric/control scripts | Nexus ships shell/Python agents executed on nodes with offline policy guard | Shared least-privilege secure client; never give metric collector a control-signing key |
| Transport | Nexus app is HTTP behind an Nginx TLS terminator; agents require server certificate validation | **Actual** negotiated TLS 1.3 X25519MLKEM768 on each required channel hop, without disabled hostname/cert verification |

**Separate properties:** Ed25519 AND ML-DSA-65 (FIPS 204) protect origin and integrity; X25519MLKEM768 hybrid TLS key exchange protects in-transit confidentiality against harvest-now/decrypt-later. Neither substitutes for the other. The user-facing Xray data plane remains out of scope.

## 2. Candidate transport envelope

The network representation will be a strict JSON object, not yet accepted by either live API. The envelope carries:

- `protocol: "XSP/2"`, `suite: "Ed25519+ML-DSA-65"`, `direction`, `messageType`, `issuerId`, `nodeId`, `method`, `path`, `ed25519KeyId`, `mldsa65KeyId`, `keyEpoch`, `issuedAtMs`, `expiresAtMs`, `nonceHex`, `requestId`, `revision`.
- `payloadB64`: strict padded RFC 4648 Base64 of **exact payload bytes** (not a reconstructed JSON object).
- `signatures.ed25519`: exactly 64 decoded bytes; `signatures.mldsa65`: exactly 3309 decoded bytes, encoded as strict padded Base64.

No private keys or keys-derived secrets are transported. Key IDs select separately enrolled, purpose-authorized verification keys and have to be pinned to the expected node/panel identity and epoch. Do not trust key material merely because it is present in a response. Duplicate keys, unknown critical fields, unknown suite/version, noncanonical Base64 and malformed JSON are errors. The receiver verifies the byte digest and **both signatures over the same exact signing input** before dispatching any payload or command.

### Direction and allowable message types

Direction ID `0x01`: Node → Nexus. Direction ID `0x02`: Nexus → Node. Unsupported IDs must fail.

| Node → Nexus | Nexus → Node | Bidirectional, separate explicitly authenticated transitions |
| --- | --- | --- |
| `node.enroll`, `node.desired-config.request`, `node.heartbeat`, `metrics.ingest`, `node.command.poll`, `node.command.ack` | `node.desired-config.response`, `node.command.response` | `node.security.activate`, `node.keys.rotate`, `node.security.recover` |

For the current wire candidate **all methods are POST**, and the path must be under `/api/v2/node/`. V1 paths are disallowed. The HTTP method/path included in the signed bytes must match the actual observed request/response endpoint. Response `requestId` must match the outstanding authenticated request. `revision` may be empty for message classes without policy revision, never for policy apply (enforced by higher-level semantic validation in a future PR).

## 3. Exact signing_input bytes: candidate version 2 / suite 1

All integer encodings are big-endian, without separators, extra whitespace or a final newline. String bytes must be ASCII `0x21..0x7e` (no space/control/Unicode). `ascii(s, max, optional)` means `u32_be(byte_length) || ASCII_bytes`, with the upper bounds below. An optional empty value uses exactly four zero length bytes; the field is never omitted.

| Order | Field | Encoding and bounds |
| --- | --- | --- |
| 1 | Domain separator | Literal ASCII `XSP2-SIGNED-MESSAGE` followed by **one 0x00 byte** |
| 2 | Protocol and suite | `0x02, 0x01` (version 2; Ed25519+ML-DSA-65 suite 1) |
| 3 | Direction | `u8` equal to `0x01` or `0x02` |
| 4 | Message type | `ascii(messageType,64,false)`, checked against the table above |
| 5 | Issuer identity | `ascii(issuerId,64,false)`, resolved against enrolled/pinned trust |
| 6 | Node identity | `u64_be(nodeId)`, positive and bounded by the backend's signed BIGINT range |
| 7 | HTTP method | `ascii("POST",8,false)` |
| 8 | Endpoint | `ascii(path,256,false)`; absolute API path beginning `/api/v2/node/`, no query, fragment, backslash or traversal |
| 9 | Classical key ID | `ascii(ed25519KeyId,64,false)` |
| 10 | PQ key ID | `ascii(mldsa65KeyId,64,false)` |
| 11 | Key epoch | `u64_be(keyEpoch)`, strictly positive and monotonic for the enrolled node |
| 12 | Issued time | `i64_be(issuedAtMs)` Unix milliseconds, positive |
| 13 | Expiry | `i64_be(expiresAtMs)`, strictly later than issuance and at most **300,000 ms** after issuance |
| 14 | Nonce | Exactly **16 random bytes** decoded from 32 **lowercase** hex characters |
| 15 | Request correlation | `ascii(requestId,64,false)` |
| 16 | Revision | `ascii(revision,128,true)`; typed per message, never inferred from JSON order |
| 17 | Payload digest | Exactly 32 raw bytes: `SHA-256(payload_bytes)` |

The envelope may be Base64-encoded JSON; these transport bytes are **not** the signed input. The sender encodes `payload_bytes` once, exactly; the verifier hashes the decoded bytes without parsing and re-serializing. Digest fields already in policy/config must bind the actual configuration to be applied. Unknown extra fields in the signing input, reordering, integer-as-float, alternate UTF-8, overlong lengths, duplicate envelope JSON keys or inconsistent canonical fields are errors, not tolerant fallbacks.

**Preliminary bounds:** raw payload ≤512 KiB, wire metadata within the per-field limits, JSON request body ≤1 MiB, nonce uniqueness per node/purpose and timestamp clock skew at most ±120,000 ms. The implementation must check bounds **before allocating** and must persist nonce/revision anti-replay state atomically before the side effect. These are design constraints; PR01 vector encoders only test a subset and do not yet implement production parsing or durable replay protection.

## 4. Shared golden vectors and negative cases

Both repositories contain the **same fixture bytes** in `docs/XSP_V2_VECTORS.json`:

- Node heartbeat `node.heartbeat` (direction 1, node 42).
- Signed desired-config *response* metadata (direction 2, node 42).
- Raw payload SHA-256 and complete `signing_input_hex`.

Rust's test-only module `backend/src/xsp_v2_wire_tests.rs`, Go's test-only `security/xspv2/wire_test.go` and Nexus's independent `scripts/check-xsp-v2-wire.js` must reproduce exact bytes. Mutating payload, path, epoch, direction, expiry or nonce must change the digest/binding or be rejected. **These vectors do not contain or verify Ed25519/ML-DSA signatures**: real cross-language signature interoperability and FIPS-204 KATs are PR02 acceptance gates.

## 5. Threats, controls and remaining architecture decisions

Threats: MITM substitution of signed response/command, impersonation with a substituted PQ key, captured HTTPS traffic, replay, old-policy revision restore, reflection between request/response types, downgrade to v1, compromised node metrics process, truncated Base64/JSON and maliciously oversized envelopes.

Necessary controls before any v2 API is enabled:

1. Independent CSPRNG-generated Ed25519 and ML-DSA keys; separate key purposes, protected file modes, rotation, key epochs, backups, revocation and recovery; never transmit private keys through Nexus.
2. **AND semantics:** verify both algorithm signatures on identical bytes with vetted libraries; fail closed for any missing/invalid signature; strict message type, endpoint, recipient and key purpose. No "Ed25519 OR ML-DSA" acceptance.
3. Durable `minimumSuite` and epoch both at Nexus and Node, authenticated owner-mediated two-phase activation, no automatic fallback to v1 after strict activation; rollback only to a verifier that supports the locked suite.
4. Retain last verified offline policy under connectivity failures; reject stale/forged policies and do not resurrect disabled Xray users. ACK must attest actual applied revision, not merely a command accepted.
5. A trusted, actually negotiated TLS 1.3 **X25519MLKEM768** group at the real terminator. Do not interpret app HTTP, an advertised cipher suite or an upstream CDN handshake as proof of end-to-end hybrid confidentiality.
6. Redacted audit logs, atomic rotation and crash recovery, bounded parsing, fuzzing, Rust↔Go cross-sign/verify, TLS fault tests and a disposable-canary deployment.

**Pending design review:** how keys are split by metric/control agent; approved Rust ML-DSA provider and runtime/OpenSSL version; source of authenticated trust on initial enrollment; exact endpoint registry, response request-correlation and HTTP authentication; TLS terminator/negotiation evidence; persistent suite-floor and recovery workflow; performance/size budgets. None is marked approved by these files.

## 6. Activation gate / migration boundaries

`Legacy → capability-discovered → dual keys enrolled → shadow-verified → strict activated` is a **per-node state machine**, with a separate owner-approved recovery path. Before activation, existing v1 remains valid for explicitly legacy nodes. After activation, **only v2 hybrid signed messages and verified hybrid TLS** are acceptable. Loss of panel/network access means fail closed to previous verified offline policy, not permissive Xray reconfiguration.

**PR01 exit condition:** security review explicitly approves this wire candidate, fixtures, error model and key purposes. The new files deliberately do **not** create `/api/v2` routes, generate credentials, flip `minimumSuite`, change Xray/agent execution or advertise PQ protection. Next step PR02: vetted Ed25519+ML-DSA signing/verifying in Rust↔Go, negative KATs, then a hybrid TLS terminator spike. Production enablement and canary acceptance remain later milestones.
