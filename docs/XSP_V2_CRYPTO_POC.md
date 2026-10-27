# XSP-v2 PR02 — isolated crypto interoperability PoC (2026-10-27)

> **Research/test environment only. NOT integrated with the production Nexus API or Node agents; NOT a security certification.**
> The [candidate wire specification](XSP_V2_WIRE_SPEC.md) has not completed security review. Do not enable strict v2, migrate production keys or advertise quantum-safe connections from these tests.

## Algorithms and pinned research tooling

| Component | Implementation | Boundary |
| --- | --- | --- |
| Go | Go **1.27.3**, standard `crypto/mldsa`, `MLDSA65()`, `NewPrivateKey`, `SignDeterministic` (test only), `Verify`, plus standard `crypto/ed25519` | Nested `security/xspv2/poc-go/go.mod` in **XMesh-Node**; production Go 1.23 module and its Docker image intentionally unchanged |
| Rust | Rust 1.99 isolated crate, pinned `openssl = 0.10.81`, system OpenSSL **3.5+** EVP signing/verification, `KeyType::ML_DSA_65` and Ed25519 | `security/xspv2/poc-rust/` in **Nexus**, tested in an isolated Debian Trixie container; no new dependencies in production `backend/Cargo.toml` |
| OpenSSL CLI | OpenSSL 3.5+ `genpkey` seeded *public demo fixture*, `pkeyutl` deterministic sign/verify | Independently reproduces the same SHA-256 digest of test signatures as Go for both request and response |

Go 1.27.3 includes security fixes published on October 19, 2026, including `crypto/x509`. A real future Node toolchain migration needs separate compatibility/build/release/rollback testing. The present `crypto/mldsa` standard library differs from OpenSSL's EVP API: exercise identical **raw message bytes** with an **empty ML-DSA context** and *pure* ML-DSA (not external-μ / prehash mode).

## Shared fixtures

`XSP_V2_CRYPTO_POC.json` is identical in both repositories and contains two public **test-only** 32-byte seeds, and SHA-256 digests of public keys and deterministic Ed25519 / ML-DSA-65 signatures for each direction of the `XSP_V2_VECTORS.json` messages. These seeds are PUBLIC TEST CREDENTIALS. Never enroll them, store them as operational keys, sign production traffic with them or use them in an agent.

- **Node Go** independently derives ML-DSA-65 keys from 32-byte seed, signs deterministically (ONLY for tests), compares public/signature SHA-256 with independently generated OpenSSL fixtures, verifies both algorithms, and denies Ed-only, ML-DSA-only, substituted-key, modified-payload and damaged-signature cases.
- **Nexus Rust** independently derives the same keys from seed using OpenSSL EVP, compares public digests, tests signing and both verifications with **AND semantics**, rejects missing/broken/altered signatures, and validates provider availability.
- **Nexus Python/OpenSSL CLI** independently reproduces deterministic ML-DSA-65 signature digests from shared seeds and verifies them with OpenSSL; a tampered message must fail.
- **Direct CI exchange:** the Go test CLI emits Ed25519+ML-DSA-65 signatures over the shared wire bytes and the Rust CLI verifies both; then Rust signs (hedged ML-DSA) and Go verifies both. Invalid one-signature, modified-byte and key-substitution cases must be rejected.
- Each repository has an **isolated CI workflow**; Go uses Go 1.27.3, Rust uses OpenSSL 3.5+ in a dedicated toolchain image. No stage runs against production node credentials.

A common signature SHA-256, common seed-derived public-key SHA-256, and identical wire input prove deterministic output compatibility for this pair of **test messages**; they are not a substitute for live cross-language exchange and adversarial parsing under production conditions.

## Remaining PR02 acceptance gates

- [ ] Record latest **green CI in both repos**, including isolated Go, Rust and OpenSSL digest checks, and existing production CI without regressions.
- [x] Implement **direct, bidirectional Go signs → Rust verifies AND Rust signs → Go verifies** over the same canonical wire bytes in the isolated Nexus Crypto CI workflow. Public test seeds only; a failing/missing Ed25519 or ML-DSA-65 signature, substituted PQ key and tampered signed payload are rejected. Source: `scripts/check-xsp-cross-language.py`, `security/xspv2/poc-rust/src/bin/interop.rs` (Nexus), `security/xspv2/poc-go/cmd/interop/main.go` (Node). This is a test exchange, not a production verifier.
- [ ] Run an external ML-DSA-65 FIPS 204 **known-answer-test suite**, fuzz parser/decoder/overlong lengths/duplicate JSON keys and malformed public keys; review OpenSSL provider patch level and dependency supply chain.
- [ ] Choose actual key-purpose separation, authenticated enrollment/rotation and hardware-independent recovery, versioned error model and bounded parser. No silent Ed25519-only fallback after strict activation.
- [ ] Test TLS 1.3 with a **measured negotiated X25519MLKEM768** key exchange on the intended HTTPS termination hop, certificate/hostname validation and downgrade rejection.
- [ ] Review/approve the XSP-v2 wire specification, threat model and interop harness before merging crypto into production services.

**Strict mode stays disabled.** Existing `XMESH1` requests, Ed25519 policy, offline guard, Xray configuration, node control and legacy TLS remain unchanged.

## Reproduction

**XMesh-Node PoC** (separate Go 1.27.3 toolchain):

```bash
cd security/xspv2/poc-go
go test -race -count=1 ./...
go vet ./...
```

**Nexus PoC** (Debian Trixie / OpenSSL 3.5+, isolated Rust toolchain):

```bash
python3 scripts/check-xsp-crypto-openssl.py
cargo test --manifest-path security/xspv2/poc-rust/Cargo.toml --all-targets
cargo fmt --manifest-path security/xspv2/poc-rust/Cargo.toml --all -- --check
```

See each repository's `.github/workflows/xsp-crypto-poc.yml` for the exact CI environment and SHA.
