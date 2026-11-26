"""Bind the dormant TLS compiler to its actual sealed local child inputs.

A future launcher must still obtain positive signed authority, complete
installed WAL qualification and systemd/pidfd containment BEFORE any exec.
This object never executes a child or starts a listener.
"""
import hashlib
import os
import time

import public_tls_cap_watch
import public_tls_certificates
import public_tls_child_inputs
import public_tls_frontend
import public_tls_routes
import wal_transport

MAX_ASSEMBLY_NS = 8_000_000_000
MAX_CLOCK_DIVERGENCE_MS = 2_000


def _sha(value):
    return hashlib.sha256(wal_transport.observed.canonical(value)).hexdigest()


class PinnedTlsInputs:
    """Only the exact signed compiled config, original roster and meter.

    The public child would inherit only the sealed config/certificate/key
    FDs and the detached read-only route FD in `child_fds`. No CA, writable
    owner route FD, lock, pidfd or enclosed Agent state is inherited. This
    is input integrity, not a launch permission or complete sandbox.
    """

    def __init__(self, *, profile, authority, cap_watch, enrolled_fd, node,
                 activation, genesis_sha, runtime_id, runtime_pid, pinned):
        if (os.geteuid() != 0 or type(runtime_pid) is not int or runtime_pid <= 1
                or not isinstance(authority, bytes)
                or not isinstance(cap_watch, public_tls_cap_watch.SignedCapRosterWatch)
                or cap_watch.node != node or cap_watch.activation != activation
                or cap_watch.genesis_sha != genesis_sha or cap_watch.runtime_id != runtime_id
                or cap_watch._pid != runtime_pid or cap_watch.pinned != pinned
                or cap_watch.profile_sha256 != _sha(profile)):
            raise ValueError("foreign or incomplete signed local TLS inputs")
        self._closed = False
        self._certificates = self._routes = None
        self._wall = time.time_ns() // 1_000_000
        self._mono = time.monotonic_ns()
        self._authority_sha = hashlib.sha256(authority).hexdigest()
        self._roster = cap_watch
        self._roster_sha = cap_watch.roster_sha256
        self._runtime_pid = runtime_pid
        try:
            config = public_tls_frontend.compile_signed_public_tls(
                profile, authority, node=node, activation=activation,
                genesis_sha=genesis_sha, runtime_id=runtime_id, pinned=pinned)
            self._config_sha = _sha(config)
            payload = wal_transport.observed.strict_json(authority)["payload"]
            # Compiler already verified authority and cap watcher verified
            # each signed envelope; never accept caller-supplied deadlines.
            self._expires = min(
                [payload["validUntilMs"]] +
                [wal_transport.observed.strict_json(raw)["payload"]["validUntilMs"]
                 for raw, _, _ in cap_watch._grants.values()])
            self._check_clock()
            self._certificates = public_tls_certificates.freeze_certificate_lineage(config)
            self._routes = public_tls_routes.FirstGenesisRoutes(cap_watch, enrolled_fd)
            self._fds = (self._certificates.config_fd, *self._certificates.material_fds,
                         self._routes.directory_fd)
            self._protected_fds = tuple(fd for fd in (
                *self._certificates._fds, *self._routes._fds) if fd not in self._fds)
            self._child_identity = public_tls_child_inputs.capture(
                expected=self._fds, forbidden=self._protected_fds,
                route_fd=self._routes.directory_fd)
            self.ensure_current(config=config, authority=authority,
                                cap_watch=cap_watch, runtime_pid=runtime_pid)
            if time.monotonic_ns() - self._mono >= MAX_ASSEMBLY_NS:
                raise ValueError("pinned TLS input assembly missed watchdog budget")
        except BaseException:
            self.close()
            raise

    def _check_clock(self):
        wall = time.time_ns() // 1_000_000
        elapsed = (time.monotonic_ns() - self._mono) // 1_000_000
        if (elapsed < 0 or wall < self._wall
                or abs(wall - self._wall - elapsed) > MAX_CLOCK_DIVERGENCE_MS
                or wall >= self._expires or self._wall + elapsed >= self._expires):
            raise ValueError("pinned TLS input lifetime expired or clock changed")

    def ensure_current(self, *, config, authority, cap_watch, runtime_pid):
        if (self._closed or not isinstance(authority, bytes)
                or hashlib.sha256(authority).hexdigest() != self._authority_sha
                or cap_watch is not self._roster or cap_watch.roster_sha256 != self._roster_sha
                or runtime_pid != self._runtime_pid or cap_watch._pid != runtime_pid
                or _sha(config) != self._config_sha
                or self._certificates.source_config_sha256 != self._config_sha
                or self._routes._roster is not cap_watch):
            raise ValueError("pinned TLS inputs differ from exact signed authority or original roster")
        self._check_clock()
        if (self._fds != (self._certificates.config_fd, *self._certificates.material_fds,
                          self._routes.directory_fd)
                or len(set(self._fds)) != len(self._fds)
                or any(fd < 3 or os.get_inheritable(fd) for fd in self._fds)):
            raise ValueError("pinned TLS child descriptor set changed")
        if self._certificates.ensure_current() is not None:
            raise ValueError("sealed TLS input check cannot authorize ingress")
        if self._routes.ensure_current() is not None:
            raise ValueError("pinned TLS route check cannot authorize ingress")
        self._check_clock()
        return None

    def verify_child(self, child):
        """Read back the actual inherited descriptors; never start or admit."""
        if self._closed:
            raise ValueError("pinned TLS inputs are closed")
        self._check_clock()
        # Capture was bound at assembly, not to whichever descriptors
        # happen to occupy these numbers at the time of the child proof.
        if (self._fds != (self._certificates.config_fd, *self._certificates.material_fds,
                          self._routes.directory_fd)
                or self._protected_fds != tuple(fd for fd in (
                    *self._certificates._fds, *self._routes._fds) if fd not in self._fds)):
            raise ValueError("pinned TLS descriptor set changed")
        if public_tls_child_inputs.verify(
                child, expected=self._fds, forbidden=self._protected_fds,
                route_fd=self._routes.directory_fd, pinned=self._child_identity) is not None:
            raise ValueError("child descriptor proof cannot authorize ingress")
        self._check_clock()
        return None

    @property
    def child_fds(self):
        if self._closed:
            raise ValueError("pinned TLS inputs are closed")
        return self._fds

    @property
    def config_path(self):
        if self._closed:
            raise ValueError("pinned TLS inputs are closed")
        return f"/proc/self/fd/{self._certificates.config_fd}"

    @property
    def ingress_state(self):
        if self._closed:
            raise ValueError("pinned TLS inputs are closed")
        return self._routes.ingress_state

    def close(self):
        if not self._closed:
            self._closed = True
            try:
                if self._routes is not None:
                    self._routes.close()
            finally:
                if self._certificates is not None:
                    self._certificates.close()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
