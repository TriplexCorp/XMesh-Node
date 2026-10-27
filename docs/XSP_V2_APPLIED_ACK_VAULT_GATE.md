# XSP-v2 applied ACK: committed-vault gate (staging only)

This Go 1.27 research module is NOT imported by the production Node/router and does not enable `strict-pq` or invoke rotation.

Before accepting a dual-signed `applied-ACK` for durable retry, `cutover.PersistACKForCommittedVault`:

1. Requires an already authenticated, independently pinned Nexus `VerifiedPermit`. Signed permit fields are **not** permitted to become their own owner-approved expectation.
2. Holds the vault's **shared wrapping-key flock** through vault attestation and the ACK journal write/fsync. Cooperating rotation writers use the exclusive lock; this removes a check/write race between properly locked processes.
3. Verifies the persisted floor equals the requested `toEpoch`, and the active encrypted vault file equals the original sealed `.next` bytes.
4. Cryptographically decrypts/authenticates the active, pending `.next`, and preserved prior `.previous` vaults using the wrapping key. The previous epoch and both previous key IDs, and the next epoch and both new key IDs must match the permit. The new active public key bytes must also match the pinned ACK verifier's key bytes.
5. Checks BOTH Ed25519 AND ML-DSA-65 signatures of the Node applied ACK and its binding to the original signed permit and state digest, then writes the **exact signed envelope** to an exclusive-lock, mode-0600 retry journal, with file fsync, atomic rename and parent directory fsync.
6. Revalidates all those requirements upon journal reload; a restoration of only the old vault when the floor remains new is rejected. Forward-only `RecoverRotation` can be used separately to repair an interrupted local activation.

The low-level unguarded journal helpers were made **unexported**. Only the vault-attested entrypoints are exported to external staging callers.

## Remaining blockers for a real trustworthy XSP-v2 cutover

- Local `ActivatePreparedRotation` still requires a separate operator-mediated step; this module neither initiates nor authorizes it. No end-to-end owner permit → durable vault commit → ACK workflow is deployed.
- The protected epoch floor here is **software-managed**. Restoring the entire vault, wrapping key, snapshots and floor can roll back history. Out-of-band privileged writers can bypass the cooperative file lock. Hardware/remote anti-rollback and recovery consistency with Nexus are still required.
- A signed ACK is a claim about a durable state; the protocol also requires Nexus to validate the stored permit and pending public keys, atomically advance the remote epoch, issue a **signed commit receipt**, preserve old keys until separately authorized retirement, and safely handle lost ACKs, replay and split-brain.
- Do not use these Go research operations in production or migrate existing Node 13 keys; staging-only fault-injection and independent security review remain required.

CI: `cd security/xspv2/poc-go && go test -race -count=1 ./... && go vet ./...`.
