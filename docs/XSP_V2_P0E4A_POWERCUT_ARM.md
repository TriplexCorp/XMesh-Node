# XSP-v2 P0-E4a external power-cut arm

Status: **lab qualification primitive only**. This does not prove physical power-loss durability, activate strict-PQ, change production routing, authorize key retirement, or authorize production rollout.

## Purpose

P0-E1a proved process-crash/fsync ordering. Nexus P0-E4a1 adds a read-only storage preflight and explicitly keeps `physicalPowerLossQualified=false`. The remaining E4a evidence requires an abrupt loss of power on a representative storage stack, not a process exit, VM stop, graceful reboot, or GitHub-hosted runner.

This Node slice makes the already-proven Agent rotation durability checkpoints externally observable without adding a production control path.

## Build boundary

Normal builds compile `durability_checkpoint.go`, where `rotationDurabilityCheckpoint` is a no-op. The lab hook is compiled only with:

```text
xspv2_powercut_qualification
```

The existing process-crash injector remains separately compiled only with:

```text
xspv2_crash_test
```

The tags are intentionally mutually exclusive. A build selecting both must fail instead of silently choosing one evidence model.

The lab-only file does not execute shell commands, open network connections, reboot the machine, issue storage-cache commands, or call a power controller. Production Agent artifacts must not contain the arming environment variables or the lab arm token.

## External-controller handshake

The qualification process is configured with four bounded environment values:

- `XMESH_XSPV2_POWERCUT_POINT`
- `XMESH_XSPV2_POWERCUT_ARM=EXTERNAL_POWER_CUT_LAB_ONLY`
- `XMESH_XSPV2_POWERCUT_RUN_ID`
- `XMESH_XSPV2_POWERCUT_SIGNAL_FD`

The signal FD must be an inherited descriptor opened by the lab supervisor. It is not a path, URL, socket address, or command supplied to the Agent.

At the selected durability boundary the Agent writes exactly one marker of this form:

```text
XSP2-POWERCUT-ARMED-V1 run=<run-id> point=<checkpoint>
```

and then stops making security-state progress. A physically independent BMC/PDU/controller/hypervisor test fixture must observe that marker and remove host/device power externally. The Agent itself never claims the cut occurred.

Allowed Agent checkpoints are the existing P0-E1a boundaries:

- `after-previous`
- `after-floor`
- `after-active`
- `after-recovery-abort`
- `after-recovery-active`

## Qualification evidence

A real P0-E4a run must retain, outside the tested host rollback/power domain:

1. the exact Nexus P0-E4a1 storage-preflight report and reviewed storage/controller identity;
2. the exact Node/Nexus source revisions and qualification binary digest;
3. run ID and selected durability checkpoint;
4. independent controller/PDU/BMC evidence that abrupt power removal followed the `XSP2-POWERCUT-ARMED-V1` marker;
5. post-boot filesystem/storage diagnostics and kernel evidence;
6. post-boot Agent identity, epoch floor, retained old/new key evidence and recovery result;
7. the current owner/off-host E3a checkpoint and independent public pins;
8. for PostgreSQL qualification, matching WAL/database recovery evidence and the unchanged XSP-v2 monotonic tuple.

A run is invalid if the tested host performs a graceful shutdown, if the power controller shares the rollback domain, if write-back cache/PLP semantics are unknown, or if the evidence cannot bind the observed power cut to the exact armed checkpoint.

## Expected post-boot invariant

After a real abrupt cut, recovery may converge only to a state permitted by the established monotonic floor and preserved authenticated material. It must never:

- lower the epoch/replay floor;
- fabricate or replace a signed ACK/receipt;
- silently regenerate or re-enroll keys;
- select the prior key after the floor has advanced;
- accept torn/substituted encrypted identity material;
- fall back to XMESH1, Ed25519-only, classical-only transport, TLS 1.2, or insecure certificate validation.

The existing `RecoverRotation` semantics remain authoritative; this lab hook only creates the moment at which an external controller can remove power.

## What CI proves

GitHub CI proves only that:

- normal builds exclude the lab hook;
- the process-crash and physical-power lab tags remain separate;
- invalid arming configuration fails closed;
- the lab build emits the exact bounded marker on an inherited FD and then remains blocked;
- no command/network/reboot/poweroff path exists in the lab hook;
- existing process-crash tests still pass.

**GitHub CI is not physical power-loss evidence and cannot close P0-E4a.** P0-E4a remains open until the external abrupt-power matrix is executed on reviewed representative hardware/storage and its post-boot evidence is accepted.

`strict-pq` remains OFF and production rollout remains NOT AUTHORIZED.
