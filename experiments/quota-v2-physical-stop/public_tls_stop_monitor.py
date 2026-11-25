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
import public_tls_certificates
import public_tls_frontend
import wal_transport

MAX_CHECK_GAP_NS = 10_000_000_000
MAX_DIVERGENCE_NS = 5_000_000_000


class StopOnlyTlsMonitor:
    def __init__(self, *, child, profile, authority, node, activation,
                 genesis_sha, runtime_id, pinned, runtime_pid, cap_watch):
        if not isinstance(child, subprocess.Popen):
            raise ValueError("only a directly-owned child process is monitorable")
        # A caller may already have started the child. Never leave that
        # process running when the initial signature, runtime, certificate,
        # or lifetime preflight fails before the first monitor tick.
        self._child = child
        self.stopped = False
        try:
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
            self._cap_watch = cap_watch
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
        raise ValueError("public TLS process stopped: " + reason)

    def check_stop_only(self, *, revoked):
        """Never return traffic permission. Terminate child on ANY loss.

        This check is NOT sufficient to run an ingress. Signed spending-cap
        ownership, verified WAL floors, process isolation, current node
        identity and network authorization must be imposed by its caller.
        """
        if self.stopped:
            raise ValueError("public TLS stop latch is permanent")
        if type(revoked) is not bool or revoked:
            self._stop("revoked or unverified revocation state")
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
        self._wall_ms, self._mono_ns = end_wall, end_mono
        # Deliberately no boolean "allowed" return. A successful stop-only
        # poll cannot issue permits, refresh caps or open an ingress.
        return None
