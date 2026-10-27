# XSP-v2 staging — crash-recoverable two-phase key vault

> 27 October 2026. **Laboratory only.** This is an operator-mediated local
> key-vault workflow, **not** an authenticated Nexus/Node rotation protocol.
> `strict-pq`, Node Go 1.23, the running Xray agent, and production enrollment
> remain unchanged.

## Invariants and on-disk state

The encrypted key vault and external AES-256-GCM wrapping key keep the existing
mode-0600 and mode-0700 owner-only checks. The following files are local to a
disposable staging host:

| File | Meaning |
| --- | --- |
| `node.json` | Active encrypted Ed25519 + ML-DSA-65 keyset |
| `node.json.next` | Prepared candidate; never activated by merely creating it |
| `node.json.previous` | Retained encrypted previous keyset, never used automatically as active |
| `node.json.min-epoch` | Monotonic local floor; written durably **before** changing the active file |
| `master.key` | Separate external wrapping key; back it up independently |

The writer takes an exclusive lock on the master file. Each vault file is
atomically renamed after `fsync`, and directory updates are synchronised.
If the process crashes after writing `.previous` but **before** advancing the
floor, an explicit `recover-rotation` clears only the redundant saved copy and
leaves the original active keys in place. If it crashes **after** the floor is
advanced but before replacing `node.json`, normal vault reads fail closed;
`recover-rotation` decrypts and authenticates both saved bundles and completes
the **forward** transition. It never restores the older epoch as active.
Repeated recovery after the swap is idempotent.

## Experimental operator sequence

1. Prepare on a disposable host with Go 1.27.3: `keytool prepare-rotation -key MASTER -vault VAULT -expected-epoch EPOCH`. Existing active key material is unaffected.
2. Review the two returned candidate public-key IDs through a **separately trusted owner channel**. For the **separate staging Nexus rotation-prepare proposal**, when that channel provides a 32-byte owner challenge, `keytool prove-prepared -key MASTER -vault VAULT -expected-epoch EPOCH -challenge LOWERCASE_64_HEX` signs the challenge using **both prepared private keys without activating them**. The original one-shot Nexus enrollment `claim` revoked old public keys; [Nexus PR #24](https://github.com/TriplexCorp/XMesh-Nexus/pull/24) restricts it to **initial enrollment only**. Do **not** submit this prepared proof to that old claim route as a rotation handshake.
3. Only after manual approval of the exact candidate, run `keytool activate-rotation -key MASTER -vault VAULT -expected-epoch EPOCH -expected-ed-key-id APPROVED_ED -expected-pq-key-id APPROVED_PQ`. This is a **local manual authorization**, not a signed Nexus ACK.
4. After an interrupted activation, run `keytool recover-rotation -key MASTER -vault VAULT` on that staging host. Inspect active public metadata and verify that the node and epoch match expectations before any further tests.
5. While still only prepared, `keytool abort-rotation -key MASTER -vault VAULT -expected-epoch EPOCH` safely discards the candidate. An activated rotation cannot be aborted.

**Domain separation:** `prove-prepared` now signs `XSP2-KEY-ROTATE-PREPARE-V1\0` with both prepared keys, binding `nodeId`, `fromEpoch`, `keyEpoch`, `node_request`, challenge, both public keys and key IDs. Its output is for staging `POST /api/v2/node/keys/rotation/prove` only, **not** for initial `/keys/claim`. A successful prepared proof records *no* active cutover and must never authorize local `activate-rotation`; a separate signed, accepted Node cutover protocol remains required.

The old one-step `keytool rotate` subcommand now **refuses execution**. The
research-only `keyring.Rotate` helper remains for existing legacy vault unit
tests and MUST NOT be used to rotate managed nodes.

**No automatic retirement** is provided. After activation, the old encrypted
keyset is intentionally retained, and further preparation is rejected while
`.previous` exists. A future separately reviewed Nexus→Node signed transition
acknowledgement, proof that the new keys are accepted, safe previous-key
revocation, and full identity-bound disaster recovery are required before
introducing a retirement command.

## Security limits / open production gates

- The local floor is NOT protected against privileged rollback of the vault,
  floor **and** wrapping key together. Hardware-backed or independently
  persisted monotonic state and off-host backup/recovery need review.
- The Node→Nexus owner-approved proof and server-side keyset cutover protocol
  are NOT integrated with these local operations.
- No pinned Nexus rotation-approval signature, atomic server ACK, durable
  network replay prevention, policy applied-ACK, or strict-PQ migration exists.
- Tests cover wrong epoch/key IDs, pre-cutover abort, tampered ciphertext,
  old-key retention, rollback rejection, and interruption at both persistence
  boundaries. Passing isolated CI does NOT prove reliability under actual
  VPS power loss or filesystem failure.
