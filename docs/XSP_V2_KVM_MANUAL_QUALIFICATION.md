# XSP-v2 manual KVM VPS qualification runner

Status: **operator-facing qualification tooling only**. This runner does not enable production `strict-pq`, does not modify the normal Agent binary, and does not itself satisfy issue #138 without five real VPS stop/start runs and the remaining Nexus-side evidence.

## Purpose

The runner exercises the real XSP-v2 PQ keyring rotation/recovery implementation in an isolated persistent lab directory. It reaches one selected durability checkpoint, prints the existing `XSP2-POWERCUT-ARMED-V1` marker, and then stops making security-state progress until the VPS is stopped externally by the operator/provider.

The normal production Agent is not used for arming and contains no qualification controls.

## Build

From the exact XMesh-Node source selected for qualification:

```bash
cd security/xspv2/poc-go
go build -trimpath -tags xspv2_powercut_qualification \
  -o ./xspv2-kvm-qualify ./cmd/xspv2-kvm-qualify
```

Run the binary as the same privileged operator for both `arm` and `inspect`. The default persistent run root is:

`/var/lib/xmesh/xspv2-kvm-qualification`

Each run uses a fresh subdirectory named by `--run-id` and never touches the normal Agent vault.

## One real run

Example first checkpoint:

```bash
sudo ./xspv2-kvm-qualify arm \
  --run-id kvm-after-previous-01 \
  --checkpoint after-previous \
  --node-id <REAL_NODE_ID>
```

Do **not** stop the VPS when only `PREPARED` is visible. Wait for the exact marker:

```text
XSP2-POWERCUT-ARMED-V1 run=kvm-after-previous-01 point=after-previous
```

Once that marker is visible, use the VPS provider control panel to perform the documented hard **Power Off / Stop** operation. Do not type `shutdown`, `reboot`, kill the process, close SSH as a substitute, or use a snapshot rollback.

After the VPS is fully off, power it on again. Once SSH is available, run:

```bash
sudo ./xspv2-kvm-qualify inspect --run-id kvm-after-previous-01
```

`inspect` requires a different Linux boot ID, validates the persisted keyring, performs only the recovery operation appropriate for that checkpoint, rejects torn/inconsistent state, writes `postboot.json`, and prints `PASS` only for the expected complete identity.

## Five required checkpoints

Use a unique run ID and a fresh directory for every run:

```text
after-previous        -> previous-complete
after-floor           -> next-complete
after-active          -> next-complete
after-recovery-abort  -> previous-complete
after-recovery-active -> next-complete
```

Example run IDs:

```text
kvm-after-previous-01
kvm-after-floor-01
kvm-after-active-01
kvm-after-recovery-abort-01
kvm-after-recovery-active-01
```

## What this proves and what it does not

The runner proves guest-visible crash/recovery behavior of the PQ keyring state machine at the exact durability boundaries. It does not claim physical host power-loss qualification and never sets `physicalPowerLossQualified=true`.

The per-run `postboot.json` records:

- run ID and checkpoint;
- pre/post Linux boot IDs;
- Node ID;
- from/to epoch and Ed25519/ML-DSA-65 key IDs;
- expected complete post-boot classification;
- recovered key epoch and active key IDs;
- SHA-256 of persisted lab security state;
- `networkAttemptedBeforeValidation=false` for the isolated runner.

Issue #138 still additionally requires provider hard-stop evidence plus the Nexus-side PostgreSQL/off-host witness fields and one final five-run result accepted by `verify-xsp-v2-kvm-vps-durability.py`.

## Safety boundary

This executable must be built only with `xspv2_powercut_qualification`. The qualification and process-crash build tags are mutually exclusive. Never install this binary as the production Agent service.

Production remains unchanged during these runs:

```text
strictPQEnabled=false
productionActivation=false
physicalPowerLossQualified=false
```
