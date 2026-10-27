# XSP-v2 candidate public-keyset binding — test-only serializer v1

**Status:** canonical candidate hashing contract + independent Rust/Go tests. This document does **not** authorize migration, enrollment, or cutover.

Before issuing a dual-signed cutover permit, both Nexus and Node must derive the same SHA-256 from **trusted, separately obtained** old/current and new/pending **public** keyset material, not from an `expectedDigest` value supplied in a permit. For Nexus, the current `node_xsp_public_keysets` row and the owner-approved, dual-PoP-verified `node_xsp_rotation_preparations` row are the intended sources, read within one locked database transaction. For Node, compare against the independently pinned active and sealed pending local keyset. This is a proposed input-binding contract, *not* a DB connection or enforced check today.

## Canonical bytes

Append **exactly in order**, no whitespace, delimiters or trailing bytes:

1. ASCII `XSP2-CUTOVER-CANDIDATE-V1`, then exactly one NUL byte `0x00`.
2. Version byte `0x01`.
3. `nodeId`, `fromEpoch`, `toEpoch`: three unsigned 64-bit **big-endian** integers. Each strictly positive; `toEpoch == fromEpoch + 1` checked for overflow.
4. Five strings in order: `purpose`, `fromEdKeyId`, `fromPQKeyId`, `toEdKeyId`, `toPQKeyId`. Every string uses `u32_be(length in bytes) || printable ASCII bytes (0x21..0x7e)`. `purpose` is **exactly** `node_request`; IDs are nonempty, max 64 bytes.
5. Four fixed-length raw public keys, in order: `activeEd25519Public[32]`, `activeMLDSA65Public[1952]`, `pendingEd25519Public[32]`, `pendingMLDSA65Public[1952]`. Reject wrong lengths and all-zero key blobs; verify actual key validity, key IDs/fingerprints, purpose and owner approval in the enclosing trust layer. A digest alone **cannot** establish that a public key is valid or authorized.

`candidateSha256Hex` is lowercase hex of `SHA256(canonicalBytes)`. Any change of node, epoch, purpose, either key ID or any public-key byte must change the hash. This digest is fixed to the new public/private rotation candidate *and* old active material. Old and pending public keys must be read from **different trusted sources** than the signed permit field and compared before any state change.

## Security and integration boundaries

- **Never** use this serializer as owner approval: explicit authenticated approval, approved expiry, dual PoP of pending private keys, independently pinned panel signer and protected nonce ledger are separate hard gates.
- Confirm `nodeId > 0`, active/current `fromEpoch`, frozen `toEpoch`, lock the per-node DB state, and use the public bytes approved under migration 0102. A prepared proposal may be unproved, revoked, expired or raced; reject it before permit issuance.
- Neither Rust nor Go function introduced here is called by a live API or production Go agent. A subsequent review must bind this serializer to Nexus's actual two database key rows and Node's active/pending sealed vault.
- This serializer hashes raw bytes, not untrusted JSON. The shared test fixture uses **synthetic repeated-byte patterns**, deliberately not deployable cryptographic public keys. It verifies only deterministic encoding across languages, not signature validity.
- No new production routes, DB migrations, keys, Xray configuration, TLS changes, cutover or `strict-pq` activation.

The paired implementation is validated with `docs/XSP_V2_CUTOVER_CANDIDATE_VECTORS.json`, independent Rust and Go canonical implementations and adversarial field/byte mutation cases. It does not replace real signing, crash recovery, backup/restore tests or security review.
