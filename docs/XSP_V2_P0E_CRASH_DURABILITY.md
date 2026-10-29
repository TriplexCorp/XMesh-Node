# XSP-v2 P0-E crash durability sub-gate

Status: **P0-E1a process-crash proof; not a full hardware power-cut claim and not production activation**.

This gate exercises the real two-phase Node key-rotation implementation at the exact durable filesystem boundaries used by `ActivatePreparedRotation` and `RecoverRotation`.

The normal build compiles a no-op durability checkpoint. A separate `xspv2_crash_test` build tag replaces only that checkpoint with a hard process exit used by CI. The normal Agent artifact has no environment-controlled crash switch.

## Durable activation order

The authorized rotation remains:

1. fsync and rename the authenticated old identity to `.previous`, then fsync the parent directory;
2. atomically persist and fsync the monotonic new epoch floor;
3. atomically replace the active vault with the authenticated `.next` candidate and fsync the parent directory.

The dedicated crash matrix kills the test process immediately after each completed durable step and reopens the state from a fresh process boundary.

Expected outcomes:

- after `.previous`: the old identity and old floor remain active; explicit recovery returns to the prepared state and never auto-cuts over;
- after the new floor: the old active vault is rejected fail-closed until explicit recovery moves forward to the already-approved candidate;
- after the active swap: the new identity is readable and recovery is idempotent while both old/new authenticated snapshots remain retained;
- a crash after recovery removes the pre-floor `.previous` entry leaves the old identity active and the candidate explicitly abortable;
- a crash after recovery performs the post-floor active swap leaves the new identity active and a subsequent recovery converges to the same epoch.

CI also builds the normal Agent and rejects it if the tagged crash environment marker is present.

## What this does not prove

This is a real process-crash / durable-write-order proof on the CI filesystem. It does **not** by itself prove physical power removal, controller/write-cache behavior, filesystem snapshot anti-rollback, PostgreSQL backup/restore, key retirement, or production rollout safety.

Those remain separate P0-E gates. `strict-pq` remains OFF and no production cutover is authorized by this sub-gate.
