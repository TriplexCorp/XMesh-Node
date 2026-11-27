"""Bind the dormant native namespace inputs to the stop-only monitor.

A successful check carries no traffic permission. The owner must separately
prove signed authority, measured WAL and installed runtime qualification.
This object does not spawn, transfer, listen, stop or issue authority.
"""
import os
import time

import public_tls_child_inputs as child_inputs
import public_tls_listener_manifest as manifests
import public_tls_listener_readback as readback
import public_tls_namespace as namespace
import public_tls_namespace_route as routes
import public_tls_pinned_inputs as pinned

MAX_PROOF_NS = 8_000_000_000


class NamespaceTlsInputs:
    """Borrow all original objects until the directly owned child is reaped."""

    def __init__(self, *, original, native, manifest, root_fd, root_token):
        if (os.geteuid() != 0
                or type(original) is not pinned.PinnedTlsInputs
                or type(native) is not routes.NamespaceMeterInputs
                or type(manifest) is not manifests.ListenerManifest
                or native._original is not original._routes
                or manifest._inputs is not original
                or namespace.capture_root(root_fd) != root_token):
            raise ValueError("exact original native TLS input and root proof required")
        self._original, self._native, self._manifest = original, native, manifest
        self._root_fd, self._root_token = root_fd, root_token
        self._fixed = self._fixed_fds()
        self._forbidden = self._forbidden_fds()
        self._route_fd = native.child_fds[0]
        self._tokens = tuple(sorted(manifest._tokens.items()))
        self._prebound = tuple(sorted(manifest._listener_fds.items()))
        if (set(self._fixed) & {fd for _, fd in self._prebound}
                or {tag for tag, _ in self._tokens} != {tag for tag, _ in self._prebound}):
            raise ValueError("native TLS listener/input descriptor overlap")
        self._identity = child_inputs.capture(expected=self._fixed,
            forbidden=self._forbidden, route_fd=self._route_fd)
        self._adopted = None
        self._child = None

    def _fixed_fds(self):
        return (self._original._certificates.config_fd,
                *self._original._certificates.material_fds,
                *self._native.child_fds, self._manifest.manifest_fd)

    def _forbidden_fds(self):
        return tuple(fd for fd in (*self._original._certificates._fds,
                                   *self._original._routes._fds, self._root_fd)
                     if fd not in self._fixed)

    def _check_pins(self):
        if (self._fixed != self._fixed_fds()
                or self._forbidden != self._forbidden_fds()
                or self._route_fd != self._native.child_fds[0]
                or self._tokens != tuple(sorted(self._manifest._tokens.items()))
                or self._prebound != tuple(sorted(self._manifest._listener_fds.items()))
                or namespace.capture_root(self._root_fd) != self._root_token):
            raise ValueError("original namespace TLS input changed")
        if self._native.ensure_current() is not None:
            raise ValueError("namespace meter proof cannot authorize ingress")
        if self._manifest.ensure_manifest() is not None:
            raise ValueError("namespace listener manifest cannot authorize ingress")

    def ensure_current(self, *, config, authority, cap_watch, runtime_pid):
        if self._original.ensure_current(config=config, authority=authority,
                cap_watch=cap_watch, runtime_pid=runtime_pid) is not None:
            raise ValueError("original TLS input proof cannot authorize ingress")
        self._check_pins()
        return None

    @property
    def child_fds(self):
        return self._fixed

    def _prove_child(self, child):
        self._check_pins()
        if self._child is not None and child is not self._child:
            raise ValueError("namespace TLS proof belongs to another child")
        if namespace.verify(child.pid, self._root_fd, self._root_token) is not None:
            raise ValueError("namespace proof cannot authorize ingress")
        if child_inputs.verify(child, expected=self._fixed, forbidden=self._forbidden,
                route_fd=self._route_fd, pinned=self._identity) is not None:
            raise ValueError("native child input proof cannot authorize ingress")

    def _readback(self, child, entries, *, listening, released):
        started = time.monotonic_ns()
        self._prove_child(child)
        for tag, fd in entries:
            token = dict(self._tokens)[tag]
            if released:
                readback.require_no_copy(os.getpid(), token)
            readback.verify_child_fd(child, fd, token)
            readback.verify_listen_state(token, listening=listening)
        if not 0 <= time.monotonic_ns() - started < MAX_PROOF_NS:
            raise ValueError("native TLS child proof missed watchdog budget")
        return None

    def verify_pretransfer(self, child):
        """Read original prebound FDs before the owner releases them."""
        if self._child is not None or self._adopted is not None:
            raise ValueError("native TLS transfer proof is one-shot")
        self._manifest.ensure_current()
        self._readback(child, self._prebound, listening=False, released=False)
        self._child = child
        return None

    def verify_child(self, child):
        """Stop-monitor proof; parent must hold no original listener FD."""
        if child is not self._child:
            raise ValueError("native TLS transfer was not independently measured")
        entries = self._prebound if self._adopted is None else self._adopted
        return self._readback(child, entries, listening=self._adopted is not None, released=True)

    def verify_guardian(self, guardian):
        """The independent watchdog must not be a second listener owner."""
        for _, token in self._tokens:
            readback.require_no_copy(guardian.pid, token)
        return None

    def observe_adopted(self, child, entries):
        """Latch actual post-adoption FD/readback only, not an approval."""
        if (self._adopted is not None or child is not self._child
                or type(entries) is not dict or set(entries) != dict(self._tokens).keys()
                or any(type(fd) is not int or fd < 3 or fd in self._fixed
                       for fd in entries.values())
                or len(set(entries.values())) != len(entries)):
            raise ValueError("invalid or repeated native listener adoption")
        observed = tuple(sorted(entries.items()))
        self._readback(child, observed, listening=True, released=True)
        self._adopted = observed
        return None
