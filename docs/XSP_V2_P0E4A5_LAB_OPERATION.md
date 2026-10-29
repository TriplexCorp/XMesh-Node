# XSP-v2 P0-E4a5 real-operation power-cut lab runner

Status: **lab-operation reachability proof only**. This does not prove physical power-loss durability, does not power a host off, does not activate `strict-pq`, and does not authorize production rollout.

## Purpose

P0-E4a2 made the five existing rotation durability checkpoints observable through an inherited file descriptor. P0-E4a3 and P0-E4a4 define the strict single-run evidence bundle and complete five-run review matrix. P0-E4a5 closes the remaining software-preparation gap: prove that the exact lab arm marker is reached by the real keyring `ActivatePreparedRotation` and `RecoverRotation` operations, not only by a direct unit call to the checkpoint hook.

The physical experiment still requires an independent BMC/PDU/controller to observe the arm marker and remove power externally.

## Five real-operation paths

The test-only runner exercises the existing keyring implementation at exactly these points:

- `after-previous` during `ActivatePreparedRotation`;
- `after-floor` during `ActivatePreparedRotation`;
- `after-active` during `ActivatePreparedRotation`;
- `after-recovery-abort` during `RecoverRotation`;
- `after-recovery-active` during `RecoverRotation`.

For each run the child process receives the existing bounded lab configuration and signal FD. The marker remains exactly:

```text
XSP2-POWERCUT-ARMED-V1 run=<run-id> point=<checkpoint>
```

The runner confirms that the marker occurs only after the corresponding real durable mutation has reached the expected on-disk state.

## Expected state at the arm marker

- `after-previous`: `.previous` and `.next` exist as private regular files; the old epoch floor and old active identity remain current.
- `after-floor`: the new epoch floor is durable; the old active vault must already fail closed against that floor; `.previous` and `.next` remain retained.
- `after-active`: the candidate identity is the readable active identity and the old/new encrypted snapshots remain retained.
- `after-recovery-abort`: pre-floor recovery has durably removed `.previous`, retained the old active identity and kept the prepared candidate.
- `after-recovery-active`: forward recovery has made the candidate active while retaining authenticated old/new snapshots.

These are the same recovery semantics already established by the process-crash proof. P0-E4a5 only proves that an external physical controller can be armed at those real operation boundaries.

## CI boundary

The runner is a `_test.go` file compiled only with:

```text
xspv2_powercut_qualification
```

CI starts the real operation in a child process, waits for the inherited-FD marker and then terminates the blocked child so the test can finish. That termination is **process control for source-contract testing only** and must never be recorded as physical power-loss evidence.

Normal Agent artifacts do not contain this runner or the power-cut hook. The existing `xspv2_crash_test` and `xspv2_powercut_qualification` tags remain mutually exclusive.

## Real lab use

A valid physical run must still use the independently reviewed E4a3/E4a4 evidence procedure:

1. pin the exact reviewed Node source revision and lab binary digest;
2. run storage preflight on the representative storage/controller/cache/PLP profile;
3. start one real rotation/recovery operation for the selected checkpoint with the inherited signal FD;
4. let the independent BMC/PDU/controller observe the exact arm marker and perform abrupt power removal;
5. after reboot collect Agent, PostgreSQL, boot-ID, controller-event and off-host E3a witness evidence;
6. validate the strict E4a3 bundle;
7. repeat for all five checkpoints and validate the E4a4 matrix;
8. obtain independent review before any physical-power qualification checkpoint is recorded.

No shell-command input, URL, network power-control API, reboot path, epoch reset, replay reset, key regeneration, enrollment replacement or legacy fallback is introduced by P0-E4a5.

P0-E4a remains **OPEN** until the five real abrupt-power experiments on representative reviewed hardware/storage are executed and independently reviewed. `strict-pq` remains **OFF** and production rollout remains **NOT AUTHORIZED**.
