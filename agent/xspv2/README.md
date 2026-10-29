# XSP-v2 P0-D Agent artifact

This top-level Go 1.27.3 module is the first production-capable Agent integration boundary for XSP-v2. It is **not installed or activated by default** and does not replace the current root Go 1.23 Agent/router workflow.

P0-D intentionally provides a narrow, reusable Agent artifact boundary:

1. a Linux Agent artifact with a production-style private state root (`/var/lib/xmesh-agent/xsp-v2`, mode `0700`, no symlink components, owned by the Agent UID);
2. reuse of the already-proven `security/xspv2/poc-go/cutover` exchange/recovery implementation through a thin integration bridge instead of copying the protocol/state machine;
3. a machine-readable build identity for staged release verification.

## Exact build identity

A release artifact must embed both the approved release version and the exact 40-hex XMesh-Node source revision at link time:

```bash
go build -trimpath \
  -ldflags "-X main.version=<approved-version> -X main.sourceRevision=<exact-source-sha>" \
  -o xmesh-agent-xspv2 ./cmd/xmesh-agent-xspv2
```

`xmesh-agent-xspv2 --identity` returns exactly:

```json
{"version":"<approved-version>","sourceRevision":"<exact-source-sha>"}
```

The command fails closed unless the embedded version matches the release-version grammar and `sourceRevision` is canonical lowercase 40-hex. A normal developer build deliberately leaves `sourceRevision=development`, so it cannot claim an approved release identity. The later Nexus staged-apply gate must compare this embedded identity with the immutable manifest **and** independently verify the artifact SHA-256 before activation.

The direct TCP `Address` remains separate from the authenticated `ServerName`. The reused cutover transport binds TLS SNI, certificate hostname verification and HTTP authority to `ServerName` and provides no redirect, TLS downgrade or XMESH1 fallback.

The staging command supports only `--version`, `--identity`, and `--check-state <absolute-path>`. Exactly one action is allowed. There is no remote command interpreter, installer hook, systemd unit, Compose service or production activation in this gate.
