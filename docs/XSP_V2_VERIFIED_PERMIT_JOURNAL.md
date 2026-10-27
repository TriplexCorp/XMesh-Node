# XSP-v2 verified-permit Linux journal — isolated staging PoC

A file-backed **verified-permit retry journal** exists only in `security/xspv2/poc-go/cutover` (Go 1.27 research module). It is **not imported by the production Node** and cannot switch keys or alter Xray/router state.

### What it guarantees in a private, trusted Linux directory

- Requires a real, currently valid permit verified by **both Ed25519 and ML-DSA-65** with an independently pinned `panel_response` public pair and a separately approved `ExpectedPermit`.
- Stores the **exact signed envelope bytes**, SHA-256 over that envelope, and the distinct canonical signing-input digest. `ReloadVerifiedPermit` always verifies the original signatures and approval again (journal contents alone are not trusted).
- A Linux flock serializes in-process and cross-process attempts using the same trusted private directory. Identical retries are idempotent; a changed signed envelope, conflicting request or corrupt existing journal fails closed.
- Writes a mode `0600` temporary file, fsyncs it, atomically renames it and fsyncs the containing directory. An unsafe path or non-private directory is rejected.

### Explicit safety limits (not a final cutover implementation)

1. Journal does not durably apply the new encrypted vault, advance a protected monotonic suite floor, generate an ACK, accept an authenticated receipt, or manage key retirement.
2. A local file, even after fsync, is **not tamper-proof or rollback-proof** against a disk snapshot restore or privileged local attacker. The protected floor/rollback counter must be independent of this file; don't interpret the record as authority.
3. Trusted pin distribution, owner approval, current/pending public keyset derivation, nonce consumption on Nexus, expiration and durable PostgreSQL transactions are separate gates. The caller MUST NOT populate `ExpectedPermit` by copying fields out of an untrusted permit.
4. Same-host user and directory must be trusted; symlink races and administrator/root compromise are not prevented by this research PoC. The Linux PoC must not be installed in the production agent as-is.
5. Do not enable `strict-pq` or update working nodes based on this PoC. Continue with a crash-tested vault transition plus server commit receipt in separate PRs.

### Test entry

`cd security/xspv2/poc-go && go test -race -count=1 ./cutover`

Tests cover exact-envelope idempotency, after-restart reload, expiry, corrupt-file rejection, directory permissions, symlinks, and concurrent same-permit retries.
