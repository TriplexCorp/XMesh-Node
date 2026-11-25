#!/usr/bin/env python3
"""STOP-ONLY host pre-spawn evidence check for future Quota V2 public TLS.

This does not create a subprocess, open/bind a port, install a cap or return a
positive ingress permit. A production launcher MUST call this before spawning
any TLS child and still enforce systemd KillMode=control-group, an independent
pidfd deadman and continuous post-spawn StopOnlyTlsMonitor checks. No installed
service currently calls it: passing this check is NEVER sufficient to publish
a listener without the missing production Nexus SQL-backed revocation issuer
and verified off-host metering/WAL proofs.
"""
import hashlib
import time

import public_tls_cap_watch
import public_tls_certificates
import public_tls_frontend
import public_tls_revocation_watch
import wal_transport

# Bound all checks under the independent guardian's 10s interval; even a
# completed proof is useless if a deadline expired while it was collected.
MAX_PREFLIGHT_NS = 8_000_000_000
MAX_DIVERGENCE_NS = 2_000_000_000


def check_before_spawn(*, profile, authority, node, activation, genesis_sha,
                       runtime_id, pinned, runtime_pid, cap_watch,
                       revocation_watch):
    """Perform all independent, read-only evidence checks BEFORE a TLS spawn.

    Return None, never config, a boolean permit, an FD or a subprocess.
    This is NOT an issuer and a caller cannot use it to obtain a new quota.
    An installed supervisor would need to repeat the same validation AFTER
    creation of its owned child and stop that child on any lost proof.
    """
    start_wall = time.time_ns() // 1_000_000
    start_mono = time.monotonic_ns()
    if type(runtime_pid) is not int or runtime_pid <= 1:
        raise ValueError("missing trusted metered runtime PID")
    if not isinstance(profile, dict) or not isinstance(authority, bytes):
        raise ValueError("missing signed metered profile or TLS policy")
    revision = hashlib.sha256(wal_transport.observed.canonical(profile)).hexdigest()
    if (not isinstance(cap_watch, public_tls_cap_watch.SignedCapRosterWatch)
            or cap_watch.profile_sha256 != revision
            or cap_watch.node != node
            or cap_watch.activation != activation
            or cap_watch.genesis_sha != genesis_sha
            or cap_watch.runtime_id != runtime_id
            or cap_watch.pinned != pinned):
        raise ValueError("foreign or incomplete signed cap roster")
    if (not isinstance(
            revocation_watch,
            public_tls_revocation_watch.SignedTlsRevocationWatch)
            or revocation_watch.node != node
            or revocation_watch.activation != activation
            or revocation_watch.genesis_sha != genesis_sha
            or revocation_watch.runtime_id != runtime_id
            or revocation_watch.profile_sha256 != revision
            or revocation_watch.roster_sha256 != cap_watch.roster_sha256
            or revocation_watch.authority_sha256 != hashlib.sha256(
                authority).hexdigest()
            or revocation_watch.pinned != pinned):
        raise ValueError("foreign or incomplete signed revocation witness")
    # Reuse the existing exact Ed25519 compiler. Do not accept an arbitrary
    # caller-supplied public TLS configuration or alternate public key.
    config = public_tls_frontend.compile_signed_public_tls(
        profile, authority, node=node, activation=activation,
        genesis_sha=genesis_sha, runtime_id=runtime_id, pinned=pinned)
    expires = wal_transport.observed.strict_json(authority)["payload"]["validUntilMs"]
    if (type(expires) is not int or expires <= start_wall
            or expires - start_wall > 120_000):
        raise ValueError("invalid TLS authority lifetime at pre-spawn")
    if wal_transport.runtime_identity.trusted_runtime_identity(
            runtime_pid) != runtime_id:
        raise ValueError("metered Xray changed before TLS spawn")
    public_tls_certificates.verify_certificate_lineage(config)
    if cap_watch.check() is not None:
        raise ValueError("cap watcher cannot issue public TLS permission")
    if revocation_watch.check() is not None:
        raise ValueError("revocation watcher cannot issue public TLS permission")
    if revocation_watch.ensure_fresh() is not None:
        raise ValueError("expired or authorizing Nexus revocation witness")
    # The metered process might restart WHILE certificate, cap and Nexus
    # revocation checks are in progress. The pre-spawn proof must bind the
    # actual final runtime, not just the PID witnessed before those calls.
    if wal_transport.runtime_identity.trusted_runtime_identity(
            runtime_pid) != runtime_id:
        raise ValueError("metered Xray changed during TLS pre-spawn proof")
    end_wall = time.time_ns() // 1_000_000
    end_mono = time.monotonic_ns()
    if (end_wall < start_wall or end_mono < start_mono
            or end_wall >= expires
            or end_mono - start_mono >= MAX_PREFLIGHT_NS
            or abs((end_wall - start_wall) * 1_000_000
                   - (end_mono - start_mono)) > MAX_DIVERGENCE_NS):
        raise ValueError("TLS pre-spawn proofs expired or clock changed")
    # Negative capability: even a complete successful inspection may NOT
    # carry authorization to a future process, PID, socket or user.
    return None
