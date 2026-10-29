# XSP-v2 P0-E snapshot / anti-rollback sub-gate

Status: **P0-E2a one-sided Agent snapshot rollback proof; not a coordinated Node+Nexus rollback solution and not production activation**.

This gate addresses a specific snapshot failure mode that cannot be solved by adding another file under the same Agent state root.

A complete VM/filesystem snapshot can restore the encrypted active vault, monotonic epoch-floor file and local journals together. Such a snapshot can therefore be internally self-consistent: local state alone cannot prove that the host moved backward in time.

The anti-rollback witness for this sub-gate is the **current dual-signed Nexus permit from a trust domain that did not roll back**.

## Proven boundary

The dedicated test captures the entire real-Agent state root before an authorized key rotation, then:

1. completes the real two-phase rotation and persists the current verified permit;
2. restores the complete pre-rotation Agent state root, including keys, epoch floor and cutover journal;
3. proves the restored local state is internally self-consistent at the old epoch;
4. re-delivers the current verified Nexus permit without modifying its signed bytes;
5. proves the real Agent applied-state attestation rejects the rolled-back state;
6. calls both `runtime.Exchange` and `runtime.Recover` against a listening TCP endpoint and proves rejection occurs before any TCP connection is accepted.

This uses the production-capable `state.AttestAppliedRotation` / `keyring.AttestAppliedRotation` path. There is no parallel test-only epoch state machine.

The runtime source contract also requires durable applied-state attestation to remain before both network operations.

## Security meaning

This proves a **one-sided Agent snapshot rollback** fails closed when Nexus remains current. Restoring a locally self-consistent old snapshot is not enough to authorize an ACK exchange or historical receipt recovery against the current signed epoch/candidate witness.

It intentionally does not create a local anti-rollback marker under `/var/lib/xmesh-agent/xsp-v2`: such a marker would roll back with the same VM/filesystem snapshot and would not constitute an independent trust domain.

## Explicitly not proven here

This sub-gate does not prove:

- coordinated rollback of both the Agent state and Nexus/PostgreSQL to mutually consistent old snapshots;
- detection when every independent authority/witness is rolled back together;
- PostgreSQL snapshot/restore behavior;
- off-host backup generation/restore authorization;
- physical storage/controller power-loss properties;
- old-key retirement;
- production rollout safety.

A coordinated rollback requires an independent non-rolled-back authority, such as an owner-held/off-host monotonic recovery checkpoint, and belongs to the later backup/restore and owner-authorized recovery gates.

`strict-pq` remains **OFF**. Production XSP-v2 rollout remains **NOT AUTHORIZED**.
