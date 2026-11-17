# Quota v2: Xray terminal-meter barrier design (prototype only)

**Status:** Experimental reference code in `internal/terminalmeter`. Not
connected to production Xray or Node Guard; no new signed telemetry fields.
`finalMeterVerified` must remain false; **refunds remain forbidden**.

## Observed behavior of the pinned official Xray 26.10.31

- Node PR #92: an established user session generated **16,384 bytes** on the
  first StatsService sample, then **81,920** after more traffic; the RPC
  disappeared when Xray stopped.
- Node PR #93: `HandlerService rmu` denied newly authenticated VLESS sessions
  but the original TCP stream kept transferring (**90,112 bytes** sampled).
  `rmi` removed the inbound listener but the same authenticated TCP stream
  STILL transferred (**98,304 bytes**). StatsService remained accessible
  while the process lived. Neither operation is a drain barrier.

These values are reproducible on disposable GitHub Actions workers; **none**
constitutes a final-meter proof.

## Prototype contract (not a production API)

`internal/terminalmeter` is a Go reference implementation, tested with
`go test -race ./...`. It models an important control-plane property without
claiming Xray's physical dataplane has been modified:

1. `Admit` associates an authenticated session with the exact user,
   account epoch, meter epoch, reservation and runtime incarnation, refusing
   a nil termination callback or a different lease identity.
2. `FenceAndWait` closes admission *under the same lock* used by `Admit`.
   It signals cancellation of every already-registered stream and waits for
   explicit accounting-completion from **all** registered streams.
3. `Account` only adds actual attributed bytes. Overflow permanently
   invalidates this local observation. `Finish` follows the last successful
   transport write/accounting callback, not merely user removal or socket
   close request. Duplicate completion cannot advance counters.
4. Deadline, crash, lost session or mismatched runtime **never** reopens
   admission or creates a refundable observation.
5. The observation sets `Refundable=false` **always**. This deliberate
   type-level limitation prevents a demo registry from pretending to be a
   durable, independently validated final Xray meter.

## Xray integration required before a REAL final meter

Review the **pinned upstream release**, not only upstream `main`:

- `app/dispatcher/default.go`: per-user `getLink` / `WrapLink` create
  user traffic counters; `Dispatch` and `DispatchLink` dispatch sessions.
  Registration must happen **before** any billable stream can transfer.
- `app/proxyman/inbound/worker.go`: TCP, UDP, Unix sockets and additional
  transports must all have accounted, unforgeable completion boundaries.
  UDP, MUX, xHTTP, Hysteria and other concurrent transports need specific
  admission/close guarantees; this prototype covers none of them.
- `app/proxyman/command/command.go`: the existing `RemoveUserOperation`
  and `RemoveInbound` do not terminate old authenticated streams. A new
  privileged local **fence-and-drain** command must be implemented and
  isolated from public/untrusted callers.
- `app/stats/counter.go` and `app/stats/command/command.go`: ordinary
  `statsquery` reads atomic counters but supplies no durable checkpoint,
  revocation identity, exclusive admission barrier or process-finality proof.

The new Xray code must instrument every successfully transferred user byte
once (no duplicate counting from both pipe wrappers), then complete/flush
every affected stream **before** acquiring its final scoped counters.
Draining a single user must NOT tear down unrelated users sharing an inbound.

The privileged command must carry exact `nodeId / userId / accountEpoch /
meterEpoch / reservationId / revision / revocationId / runtimeId`, and
support idempotent retry. The result must be written to a root-owned,
fsynced journal on the Node **before** signing/publishing evidence; the
control-plane must verify the signature and lease identity before an atomic
PostgreSQL settlement. A snapshot taken before quiescence is never eligible.

## Mandatory failure tests before enabling a refund feature

- Two users sharing an inbound, active VLESS TCP sessions, concurrent
  admission racing fence, repeated revoke/timeout, and wrong credential.
- UDP + MUX + xHTTP and all deployed transports; retries must not duplicate
  a session nor double-account a byte.
- Meter persistence across abrupt Xray SIGKILL, Node reboot before fsync,
  failed Guard commit, offline panel, lost signed acknowledgement and
  mismatched runtime/lease/revision. **Each must keep the hold**.
- Coexistence with the conservative full-burn path in Nexus #513, including
  late receipts and irrevocable no-refund decisions.
- Real clean VPS Agent upgrade/rollback rehearsal. No unsigned "terminal"
  flag or local user-supplied byte total may release a reserve.

## Release rule

No v2 fleet switch or early refunds from this prototype. Current Nexus
`XMESH_QUOTA_V2_ENABLED` defaults to 0 and issue Nexus #509 stays open.
