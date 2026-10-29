# XSP-v2 P0-D Agent artifact

This top-level Go 1.27.3 module is the production-capable Agent integration boundary for XSP-v2. It is **not installed or activated by default** and does not replace the current root Go 1.23 Agent/router workflow.

P0-D intentionally keeps one narrow Agent boundary:

1. a Linux Agent artifact with a production-style private state root (`/var/lib/xmesh-agent/xsp-v2`, mode `0700`, no symlink components, owned by the Agent UID);
2. reuse of the already-proven `security/xspv2/poc-go/cutover` and `keyring` implementations through thin integration wrappers instead of copying protocol, crypto, epoch or replay state machines;
3. a machine-readable build identity for staged release verification;
4. durable real-Agent state directories that keep cutover journals separate from encrypted Node identity material.

## Durable security-state layout

`state.Prepare` creates only private directory boundaries and never creates, replaces or regenerates enrollment identities:

```text
/var/lib/xmesh-agent/xsp-v2/
├── cutover/                  # exact permit / ACK / commit-receipt journals
└── keys/                     # encrypted Node identity + monotonic epoch floor
    ├── node-request.master
    ├── node-request.vault
    ├── node-request.vault.min-epoch
    ├── node-request.vault.next
    └── node-request.vault.previous
```

The key files are created and authenticated only by the reused `keyring` implementation. A migrated operation must pass `keyring.AttestAppliedRotation` before the Agent transport may send or recover its signed ACK. That attestation requires the exact persisted epoch floor, the active encrypted candidate, the authenticated `.next` snapshot and the retained authenticated `.previous` identity. Restoring an old active vault below the floor, lowering/corrupting the floor or deleting the retained old identity fails closed.

Re-running `state.Prepare` after an Agent/host restart must preserve all existing master/vault/floor/snapshot bytes. Package rollback is outside this state root and therefore cannot reinterpret an older package as permission to lower the security floor or regenerate enrolled identities. Old key material remains retained until a separately authorized retirement workflow exists.

The exact permit/ACK/receipt durability remains owned by the reused cutover journals: private files, exact bindings, atomic rename, file `fsync`, parent-directory `fsync`, immutable retry and corruption/conflict rejection. The Agent wrapper does not introduce a second journal format for those signed objects.

## Authenticated transport authority

The direct TCP `Address` remains separate from the authenticated `ServerName`. Before network I/O the Agent verifies its durable applied identity and epoch. The reused cutover transport then binds TLS SNI, certificate hostname verification **and HTTP authority** to `ServerName`, while `Address` is only the direct connect target. Proxy use and redirects are disabled, unexpected targets are rejected, and there is no TLS downgrade or XMESH1 fallback.

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

The command fails closed unless the embedded version matches the release-version grammar and `sourceRevision` is canonical lowercase 40-hex. A normal developer build deliberately leaves `sourceRevision=development`, so it cannot claim an approved release identity. Nexus staged apply compares this embedded identity with the immutable manifest and independently verifies the artifact SHA-256 before activation.

The staging command supports only `--version`, `--identity`, and `--check-state <absolute-path>`. Exactly one action is allowed. There is no remote command interpreter, installer hook, systemd unit, Compose service or production activation in this module. `strict-pq` remains off unless a later explicit production gate authorizes it.
