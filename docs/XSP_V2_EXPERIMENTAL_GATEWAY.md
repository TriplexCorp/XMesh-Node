# XSP-v2 staging integration — dual verification, encrypted Node keys and Nginx

**27 October 2026 · Experimental only. Production XMESH1/Ed25519 remains unchanged; strict-PQ remains OFF.**

## 1. Experimental Nexus heartbeat endpoint

The optional Rust module `backend/src/xsp_v2_api.rs` implements `POST /api/v2/node/heartbeat`. It is compiled **only** with `cargo --features xsp-v2-experimental`, requiring OpenSSL **3.5+**. Standard Docker builds omit that feature, so **the current production binary has no v2 route**. Even a custom build returns **404** unless `XSP_V2_EXPERIMENTAL_HEARTBEAT=staging-only` is explicitly set. Never enable it on the current public panel Nginx ingress.

Accepted diagnostic messages must be strict `XSP/2` / `Ed25519+ML-DSA-65`, direction Node→Nexus, `node.heartbeat`, HTTP `POST` on the exact signed endpoint, matching `issuerId=node-{nodeId}`, known IDs and epoch, bounded times, lowercase nonce and canonical Base64. Duplicate/unknown JSON fields, including nested signatures, are errors.

The handler builds the canonical signing bytes and verifies **both** Ed25519 **AND** ML-DSA-65 with the *non-revoked enrolled* node-request public keyset from PostgreSQL. It locks the suite-state row, requires `activation_phase=shadow`, `minimum_suite=1`, the same epoch, and inserts a unique nonce in the same transaction. **The only side effect is the nonce record**; it never applies an Xray policy or dispatches commands. The successful result is unsigned HTTP **204** and is **NOT** a verified response, desired-config ACK, or authorization to activate strict mode.

No enrollment/activation operation is added. Public keys must be reviewed and explicitly enrolled in a separate future owner-approved process. A key inserted into a database does not establish authenticated ownership. Cryptographic unit tests use **public demo seeds only**, never real credentials.

## 2. Node research-only encrypted key vault

`security/xspv2/poc-go/keyring/sealed.go` stores independent Ed25519 and ML-DSA-65 32-byte private seeds encrypted by **AES-256-GCM** with identity, purpose, epoch and public key IDs authenticated as AAD. A separate random 32-byte wrapping key is required. Key files must be regular, mode **0600**, owned by the current user; their directory must be mode **0700**. Rotation is guarded by an advisory file lock and exact expected epoch, uses fresh CSPRNG keypairs, atomically replaces ciphertext, and advances the independent on-disk epoch floor **before** swapping ciphertext to fail closed after interruption.

The standalone Go 1.27.3 command `security/xspv2/poc-go/cmd/keytool` implements `init-master`, `create`, `rotate`, and `public`. Only **public** key bundles are written to standard output; never copy private keys or the AES wrapping key into Git, PostgreSQL, logs or the Nexus web UI. This module is **NOT** compiled into the production Go 1.23 router, metrics agent or systemd control worker.

Local test-host commands (disposable host only):

```bash
sudo install -d -m 0700 /etc/xmesh-xsp2-test
cd security/xspv2/poc-go
sudo go run ./cmd/keytool init-master -key /etc/xmesh-xsp2-test/master.key
sudo go run ./cmd/keytool create -key /etc/xmesh-xsp2-test/master.key -vault /etc/xmesh-xsp2-test/node.json -node 42 -purpose node_request
sudo go run ./cmd/keytool public -key /etc/xmesh-xsp2-test/master.key -vault /etc/xmesh-xsp2-test/node.json
sudo go run ./cmd/keytool rotate -key /etc/xmesh-xsp2-test/master.key -vault /etc/xmesh-xsp2-test/node.json -expected-epoch 1
```

**Not an HSM/KMS.** Back up the AES key separately and securely; losing it makes encrypted seeds unusable. A privileged host operator can roll back both the encrypted file *and* its separate floor. Root compromise, accidental backups, restore policy and agent privilege separation require a further security review. An interrupted rotation may intentionally leave the old bundle unusable until authorized recovery.

## 3. Actual test-only Nginx / TLS handshake

`deploy/xsp-v2-node-ingress.nginx.conf.example` is **not installed** and binds only `127.0.0.1:8444`. It requires TLS 1.3 and `X25519MLKEM768`, has disabled TLS session tickets/cache, and returns **404 on every HTTP path**, without any `proxy_pass`. An isolated CI test launches real Nginx with ephemeral test certificates, checks `nginx -t`, measures the negotiated TLS group via OpenSSL, verifies CA/hostname, and checks failures for TLS 1.2, X25519-only and wrong hostname. It also checks that a TLS-connected request receives HTTP 404 and cannot enter v1 routes. [Nginx CI](https://github.com/TriplexCorp/XMesh-Nexus/actions/workflows/xsp-hybrid-tls.yml).

**CI is not the user's VPS.** No DNS, ACME, firewall, CDN/LB→origin or live Node/Panel TLS segment on a real VPS has been measured. For a production design, use a separately approved dedicated node-only ingress and capture authenticated negotiation evidence on every required hop. Do not alter the current public panel Nginx or enable v2 on live Node traffic based on these laboratory tests.

## Still-open gates before production

1. Full XSP-v2 security review, FIPS 204 known-answer vectors and parser fuzzing; explicit per-message key purpose/recipient binding.
2. Authenticated owner-approved **dual-key enrollment**, revocation and rotation, protected private key storage/KMS backup, ACLs, audit logs and recovery.
3. Production **signed** v2 desired-config and command responses, explicit request correlation, verified payload/revision and applied-state ACK.
4. Persisted and protected `minimumSuite` **at both Node and Nexus**, atomic nonce+state change, power-loss/replay tests, rollback-resistant recovery.
5. Separate real TLS1.3/X25519MLKEM768 node-only gateway with valid CA/SNI and end-to-end hop inventory, disposable VPS canary, outage/ACME renewal and staged rollout.
6. Green CI for exact release revisions and independent security approval. **Never switch active nodes automatically.**

**Status:** experimental dual-signature heartbeat verifier and encrypted key vault exist only as opt-in staging components. No production v2 control plane or PQ transport is deployed.
