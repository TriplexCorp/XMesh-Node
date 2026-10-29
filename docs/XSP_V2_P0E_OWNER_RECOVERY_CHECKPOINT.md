# XSP-v2 P0-E3a owner/off-host monotonic recovery checkpoint

Status: **implementation candidate — staging/recovery proof only. Production strict-PQ remains OFF.**

## Problem

P0-E2a proves a rolled-back Agent fails closed when Nexus remains current. P0-E2b proves a rolled-back PostgreSQL state cannot silently replace the state already witnessed by a current Agent. Neither side can detect a coordinated rollback when both local failure domains are restored to mutually consistent old snapshots.

P0-E3a introduces a third trust domain: an owner-held/off-host signed checkpoint that is not stored inside the Agent state root or Nexus/PostgreSQL backup domain.

## Checkpoint contract

`agent/xspv2/recovery` defines `XSP2-OWNER-RECOVERY-CHECKPOINT-V1`. Every checkpoint binds:

- a strictly positive monotonic generation and the SHA-256 of the previous canonical checkpoint payload;
- exact Node ID and authenticated Nexus server authority;
- exact committed key epoch and active Node Ed25519 / ML-DSA-65 key IDs;
- exact commit request ID and SHA-256 of the authoritative dual-signed commit receipt bytes;
- `XSP2-NEXUS-RECOVERY-STATE-V1`, binding the PostgreSQL-visible committed epoch, request, `ack_verified` permit state, receipt digest, outbox count and replay-nonce count;
- an explicit owner-recovery signer identity and key IDs;
- an issue timestamp for audit correlation.

The checkpoint itself requires **both Ed25519 AND ML-DSA-65 owner-recovery signatures**. The recovery verifier accepts only a separately pinned `owner_recovery` public identity whose key IDs match algorithm-labelled SHA-256 fingerprints.

## Monotonicity and trust-domain boundary

The code deliberately does **not** persist the owner generation floor in the Agent root or Nexus database. Doing that would place the anti-rollback witness inside the rollback domains it is supposed to detect.

The off-host operator/store must retain the current signed checkpoint and its generation floor independently. `VerifySuccessor` requires exact `generation + 1`, exact previous-checkpoint digest, the same Node/server/owner identity and a non-decreasing key epoch. `VerifyLocal` requires a non-zero independently supplied generation floor and refuses checkpoints below it.

Rollback resistance therefore depends on the owner/off-host copy remaining outside the coordinated snapshot/restore set. Rolling back that third trust domain too is outside this gate.

## Real Agent binding

`EvidenceFromAgent` accepts the existing durable `state.SecuritySnapshot`; it does not create a second key/epoch state machine. Recovery evidence requires the authenticated previous and candidate key snapshots already retained by the applied-rotation design plus the exact authoritative receipt bytes and a Nexus-state observation.

The verifier checks Agent and Nexus evidence agree on Node, epoch, request and receipt before comparing them with the owner checkpoint.

## Fail-closed properties

The primitive rejects:

- missing or invalid Ed25519 or ML-DSA-65 owner signatures;
- wrong owner-recovery key purpose/fingerprint;
- duplicate/unknown JSON fields or noncanonical signatures/digests;
- stale owner checkpoint generation below the independent floor;
- broken checkpoint-chain predecessor/generation;
- Node, server authority, epoch, key-ID, request, receipt or Nexus-state mismatch;
- disagreement between the Agent receipt and PostgreSQL receipt witness.

Verification is read-only. It does not reset epoch/replay state, regenerate keys, replace enrollment, change the authenticated server authority, rewrite receipts, invoke recovery automatically or provide a legacy/weaker fallback.

## What this gate does not yet prove

This source gate establishes the signed checkpoint format, successor rules and local fail-closed comparison primitive. The Nexus integration proof must still store the current checkpoint outside both disposable restore domains, restore both Agent and PostgreSQL to an older mutually consistent snapshot, and show the newer owner/off-host checkpoint rejects that coordinated restore before any security operation.

It also does not prove physical power-loss/controller-cache durability, complete backup inventory, owner-authorized destructive recovery, old-key retirement, KMS/HSM custody, fuzz/KAT review, production canary or rollout.

`strict-pq` remains **OFF** and production XSP-v2 rollout remains **NOT AUTHORIZED**.
