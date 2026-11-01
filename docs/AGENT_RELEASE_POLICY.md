# XMesh Agent release/version policy

`AGENT_VERSION` is the canonical production Agent version for the XMesh Node runtime. It uses `control-vMAJOR.MINOR.PATCH` SemVer-style numbering.

## Mandatory version bump

Any pull request that changes deployed Agent or Node runtime behavior **must increase `AGENT_VERSION` in the same pull request**. This includes changes under `agent/`, deployed files under `deploy/`, and bootstrap/install behavior. Test-only and documentation-only changes do not require a bump.

Version intent:

- **PATCH** — backwards-compatible bug fixes, reliability/security hardening, or runtime behavior corrections that do not introduce an incompatible wire contract.
- **MINOR** — backwards-compatible Agent capabilities or protocol/runtime features that operators must be able to distinguish during rollout.
- **MAJOR** — incompatible Agent/wire/security architecture changes or a migration that requires an explicit major cutover.

A runtime change must never be merged while continuing to advertise the previous Agent version merely because the Node product `VERSION` is unchanged. Node release version and Agent release version are independent.

## Release identity consistency

For a production Agent release, the advertised heartbeat version, Nexus target `CONTROL_AGENT_VERSION`, update command target, strict-PQ binary release identity, installers, validators and CI expectations must refer to the same target Agent version. During rolling upgrades, the control plane may explicitly accept the immediately previous version, but it must continue advertising the new target version.

`sourceRevision` and `artifactSha256` remain part of the immutable Agent release identity and do not replace the version bump requirement.

## CI enforcement

`Node CI` runs `scripts/check-agent-version-policy.py`. On pull requests it compares the runtime diff with the base branch and fails when deployed runtime files changed without a strictly newer `AGENT_VERSION`. It also verifies that the strict-PQ production installer consumes the canonical version file.

Current target: **`control-v6.0.1`**.
