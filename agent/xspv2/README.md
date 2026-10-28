# XSP-v2 P0-D Agent artifact

This top-level Go 1.27.3 module is the first production-capable Agent integration boundary for XSP-v2. It is **not installed or activated by default** and does not replace the current root Go 1.23 Agent/router workflow.

P0-D1 intentionally does only two things:

1. exposes a Linux Agent artifact with a production-style private state root (`/var/lib/xmesh-agent/xsp-v2`, mode `0700`, no symlink components, owned by the Agent UID);
2. reuses the already-proven `security/xspv2/poc-go/cutover` exchange/recovery implementation through a thin integration bridge instead of copying the protocol/state machine.

The direct TCP `Address` remains separate from the authenticated `ServerName`. The reused cutover transport binds TLS SNI, certificate hostname verification and HTTP authority to `ServerName` and provides no redirect, TLS downgrade or XMESH1 fallback.

The staging command currently supports only `--version` and `--check-state <absolute-path>`. There is no remote command interpreter, installer hook, systemd unit, Compose service or production activation in this gate.
