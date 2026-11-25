"""Fail-closed STOP-ONLY primitive for a future Quota V2 TLS supervisor.

THIS FILE CANNOT START A LISTENER OR AUTHORIZE BYTES. It operates only on
an already-owned subprocess.Popen child and an independently verified, short-
lived Nexus Ed25519 public TLS configuration. A real installed supervisor
must keep the child in its systemd control group, supply authenticated live
revocation/installed-cap proof and run checks continuously. Constructing the monitor verifies the signed policy, live meter and TLS
certificate and live signed-cap roster; failed startup kills the owned child. This is
still NOT a pre-spawn gate: a future supervisor must independently preflight
before starting a public process, and continuously check after startup. An
uncalled monitor is NOT a security boundary; this file is not installed.
"""
import hashlib
import subprocess
import time

import public_tls_cap_watch
import public_tls_deadman
import public_tls_certificates
import public_tls_frontend
import public_tls_revocation_watch
import wal_transport

MAX_CHECK_GAP_NS = 10_000_000_000
MAX_DIVERGENCE_NS = 5_000_000_000


class StopOnlyTlsMonitor:
    def __init__(self, *, child, profile, authority, node, activation,
                 genesis_sha, runtime_id, pinned, runtime_pid, cap_watch,
                 revocation_watch):
        if not isinstance(child, subprocess.Popen):
            raise ValueError("only a directly-owned child process is monitorable")
        # A caller may already have started the child. Never leave that
        # process running when the initial signature, runtime, certificate,
        # or lifetime preflight fails before the first monitor tick.
        self._child = child
        self.stopped = False
        self._deadman = None
        try:
            # A separate Linux process pins the already-owned child with a
            # pidfd BEFORE any potentially blocking TLS/Xray preflight. A
            # frozen or dead Python monitor cannot leave this child alive
            # indefinitely waiting for the next explicit stop-only check.
            self._deadman = public_tls_deadman.StopOnlyDeadman(
                child=child, timeout_ms=10_000)
            if type(runtime_pid) is not int or runtime_pid <= 0:
                raise ValueError("metered runtime PID not established")
            # A TLS listener without a complete LIVE cap witness must never
            # survive even the monitor's first successful constructor. The
            # signed authority alone says nothing about installed per-user
            # byte ceilings or the full MAIN/CDN roster.
            if (not isinstance(cap_watch, public_tls_cap_watch.SignedCapRosterWatch)
                    or cap_watch.profile_sha256 != hashlib.sha256(
                        wal_transport.observed.canonical(profile)).hexdigest()
                    or cap_watch.node != node
                    or cap_watch.activation != activation
                    or cap_watch.runtime_id != runtime_id
                    or cap_watch.genesis_sha != genesis_sha
                    or cap_watch.pinned != pinned):
                raise ValueError("missing or foreign complete signed-cap roster watcher")
            if (not isinstance(
                    revocation_watch,
                    public_tls_revocation_watch.SignedTlsRevocationWatch)
                    or revocation_watch.node != node
                    or revocation_watch.activation != activation
                    or revocation_watch.genesis_sha != genesis_sha
                    or revocation_watch.runtime_id != runtime_id
                    or revocation_watch.profile_sha256 != cap_watch.profile_sha256
                    or revocation_watch.roster_sha256 != cap_watch.roster_sha256
                    or revocation_watch.authority_sha256 != hashlib.sha256(
                        authority).hexdigest()
                    or revocation_watch.pinned != pinned):
                raise ValueError("missing or foreign signed Nexus revocation witness")
            self._cap_watch = cap_watch
            self._revocation_watch = revocation_watch
            self._config = public_tls_frontend.compile_signed_public_tls(
                profile, authority, node=node, activation=activation,
                genesis_sha=genesis_sha, runtime_id=runtime_id, pinned=pinned)
            self._runtime_pid = runtime_pid
            self._runtime_id = runtime_id
            self._wall_ms = time.time_ns() // 1_000_000
            self._mono_ns = time.monotonic_ns()
            # Duplicate strict decoding only to read a timestamp ALREADY
            # cryptographically verified by the compiler above.
            payload = wal_transport.observed.strict_json(authority)["payload"]
            self._expires_ms = payload["validUntilMs"]
            if type(self._expires_ms) is not int or self._expires_ms <= self._wall_ms:
                raise ValueError("signed TLS authority already expired")
            self._deadline_ns = (
                self._mono_ns + (self._expires_ms - self._wall_ms) * 1_000_000
            )
            if self._child.poll() is not None:
                raise ValueError("public TLS child exited before supervision")
            # A valid signature alone does not verify this host's actual
            # metered Xray or trusted certificate. Do both at initialization
            # instead of leaving a gap until the first periodic poll.
            measured = wal_transport.runtime_identity.trusted_runtime_identity(
                self._runtime_pid)
            if measured != self._runtime_id:
                raise ValueError("metered Xray changed before TLS supervision")
            public_tls_certificates.verify_certificate_lineage(self._config)
            # The check is read-only, nonce/PID-bound and intentionally returns
            # no positive public-TLS authorization. Missing *any* user dies.
            if self._cap_watch.check() is not None:
                raise ValueError("cap watcher attempted to issue authorization")
            if self._revocation_watch.check() is not None:
                raise ValueError("revocation watcher attempted to issue authorization")
            if self._revocation_watch.ensure_fresh() is not None:
                raise ValueError("revocation watcher attempted to issue authorization")
            # The startup checks themselves consume time. Never signal the
            # independent guardian after expiry, a missed 10s deadline or
            # a wall/monotonic divergence, even if each individual witness
            # returned successfully. Re-anchor the first periodic tick only
            # after this complete check; a failed preflight kills the child.
            checked_wall_ms = time.time_ns() // 1_000_000
            checked_mono_ns = time.monotonic_ns()
            if (checked_wall_ms < self._wall_ms
                    or checked_mono_ns < self._mono_ns
                    or checked_wall_ms >= self._expires_ms
                    or checked_mono_ns >= self._deadline_ns
                    or checked_mono_ns - self._mono_ns >= MAX_CHECK_GAP_NS
                    or abs((checked_wall_ms - self._wall_ms) * 1_000_000
                           - (checked_mono_ns - self._mono_ns))
                    > MAX_DIVERGENCE_NS):
                raise ValueError("TLS startup evidence expired or clock changed")
            self._wall_ms, self._mono_ns = checked_wall_ms, checked_mono_ns
            # A heartbeat is a report that every independent cryptographic
            # and measured Xray check just succeeded. It is NEVER permission
            # for the guardian to open or continue traffic on its own.
            if self._deadman.pulse() is not None:
                raise ValueError("deadman attempted to issue traffic permission")
            if self._child.poll() is not None:
                raise ValueError("TLS child died during startup supervision")
        except Exception:
            self._stop("initial TLS supervision preflight failed")

    def _stop(self, reason):
        self.stopped = True  # latch before any potentially failing I/O
        if self._child.poll() is None:
            self._child.terminate()
            try:
                self._child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._child.kill()
                self._child.wait(timeout=2)
        if self._deadman is not None:
            self._deadman.close()
        raise ValueError("public TLS process stopped: " + reason)

    def check_stop_only(self):
        """Never return traffic permission. Terminate child on ANY loss.

        This check is NOT sufficient to run an ingress. Signed spending-cap
        ownership, verified WAL floors, process isolation, current node
        identity and network authorization must be imposed by its caller.
        """
        if self.stopped:
            raise ValueError("public TLS stop latch is permanent")
        # Never accept a caller-supplied 'revoked=False'. Require a fresh
        # nonce-bound Nexus Ed25519 witness on EVERY explicit monitor tick.
        # This still needs an installed trusted polling supervisor and a
        # database-backed issuer; no public ingress is enabled by this API.
        try:
            if self._revocation_watch.check() is not None:
                raise ValueError("revocation witness cannot grant public TLS")
        except Exception:
            self._stop("signed Nexus revocation witness lost or revoked")
        wall = time.time_ns() // 1_000_000
        mono = time.monotonic_ns()
        if (wall < self._wall_ms or mono < self._mono_ns
                or mono >= self._deadline_ns
                or wall >= self._expires_ms):
            self._stop("expired TLS authority or clock rollback")
        elapsed_ns = mono - self._mono_ns
        wall_elapsed_ns = (wall - self._wall_ms) * 1_000_000
        if (elapsed_ns > MAX_CHECK_GAP_NS
                or abs(wall_elapsed_ns - elapsed_ns) > MAX_DIVERGENCE_NS):
            self._stop("TLS monitor missed deadline or wall clock jumped")
        if self._child.poll() is not None:
            self._stop("TLS ingress subprocess has exited")
        try:
            observed_runtime = wal_transport.runtime_identity.trusted_runtime_identity(
                self._runtime_pid)
        except Exception:
            # Missing /proc, malformed PID ancestry or an unexpected probe
            # failure must never leave an existing TLS subprocess online.
            self._stop("metered Xray runtime unavailable")
        if observed_runtime != self._runtime_id:
            self._stop("metered Xray runtime replaced")
        try:
            public_tls_certificates.verify_certificate_lineage(self._config)
        except Exception:
            self._stop("trusted TLS certificate unavailable")
        try:
            if self._cap_watch.check() is not None:
                raise ValueError("cap witness cannot authorize public TLS")
        except Exception:
            self._stop("live signed-cap roster unavailable or exhausted")
        # A slow cap/procfs/certificate probe cannot silently refresh an
        # already expired, rolled-back or overdue monitor interval.
        end_wall = time.time_ns() // 1_000_000
        end_mono = time.monotonic_ns()
        if (end_wall < wall or end_mono < mono
                or end_wall >= self._expires_ms
                or end_mono >= self._deadline_ns
                or end_mono - mono > MAX_CHECK_GAP_NS
                or abs((end_wall - wall) * 1_000_000 - (end_mono - mono))
                > MAX_DIVERGENCE_NS):
            self._stop("TLS cap check exceeded signed time or clock bounds")
        try:
            if self._revocation_watch.ensure_fresh() is not None:
                raise ValueError("revocation witness cannot grant public TLS")
        except Exception:
            self._stop("signed revocation witness expired during cap probe")
        try:
            if self._deadman.pulse() is not None:
                raise ValueError("deadman attempted to issue traffic permission")
        except Exception:
            self._stop("independent TLS deadman unavailable or unresponsive")
        if self._child.poll() is not None:
            self._stop("independent TLS deadman stopped the owned child")
        self._wall_ms, self._mono_ns = end_wall, end_mono
        # Deliberately no boolean "allowed" return. A successful stop-only
        # poll cannot issue permits, refresh caps or open an ingress.
        return None
