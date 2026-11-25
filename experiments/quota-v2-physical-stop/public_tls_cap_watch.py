"""Read-only signed-cap roster witness for a FUTURE Quota V2 TLS supervisor.

This is deliberately NOT a public listener gate or a revocation source.
Every signed VLESS alias must be backed by a CURRENT local Unix peer
observation from its actual metered Xray. This code never starts a process,
issues permits, opens ports, charges or refunds bytes. It fails closed if
even one alias is missing, expired, exhausted or changed. A live public
listener additionally requires a real signed TLS issuer, authenticated
continuous revocation, bounded watchdog and installed two-node proof.
"""
import hashlib
import os
import re
import tempfile
import time

import cap_install
import first_cap_handoff
import vless_ingress
import wal_transport

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
EMAIL = re.compile(r"xmesh-u([1-9][0-9]{0,18})--vless-(main|cdn)\Z")
MAX_USERS = 2048


class SignedCapRosterWatch:
    """A fail-closed, non-authorizing snapshot of signed roster and grants.

    The profile MUST be obtained from independently verified enrolled Genesis.
    Grant bytes MUST be reconciled to Nexus's durable confirmed lease and WAL
    witness by the future installed supervisor. This class is not proof of
    those facts. It independently verifies the pinned Nexus Ed25519 signature
    and the live kernel-authenticated Xray installed-cap receipt.
    """

    def __init__(self, *, profile, signed_grants, pinned, node, activation,
                 genesis_sha, runtime_id, trusted_pid, socket_path):
        if (type(node) is not int or node <= 0
                or type(trusted_pid) is not int or trusted_pid <= 0
                or not isinstance(socket_path, (str, os.PathLike))
                or not os.path.isabs(socket_path)
                or any(not isinstance(x, str) or not HEX64.fullmatch(x)
                       for x in (pinned, activation, genesis_sha, runtime_id))):
            raise ValueError("invalid independently enrolled TLS-cap watch identity")
        # Reuse the pinned staging compiler; it rejects foreign VLESS
        # protocols, public source listeners, unsupported flows and routing.
        compiled = vless_ingress.frontend(profile)
        roster = {}
        identities = {}
        seen_emails = set()
        for inbound in compiled["inbounds"]:
            tag = inbound["tag"]
            cls = tag.removeprefix("vless-")
            clients = inbound["settings"]["clients"]
            for client in clients:
                email = client["email"]
                match = EMAIL.fullmatch(email)
                if match is None or match.group(2) != cls or email in seen_emails:
                    raise ValueError("duplicate or foreign signed VLESS roster identity")
                seen_emails.add(email)
                user = int(match.group(1))
                if user > 2**63 - 1:
                    raise ValueError("signed user identity overflows Xray")
                if user not in identities:
                    identities[user] = client["id"]
                elif identities[user] != client["id"]:
                    raise ValueError("one user changed UUID between MAIN and CDN")
                roster.setdefault(user, []).append({"email": email, "class": cls})
        if (not roster or len(roster) > MAX_USERS or not isinstance(signed_grants, dict)
                or set(signed_grants) != set(roster)
                or any(type(user) is not int for user in signed_grants)):
            raise ValueError("missing, excessive or unexpected signed cap roster")
        grants = {}
        with tempfile.TemporaryDirectory(prefix="xmesh-tls-capwatch-") as temp:
            public = os.path.join(temp, "pinned-nexus.pem")
            wal_transport._write_public(pinned, public)
            for user, aliases in sorted(roster.items()):
                raw = signed_grants[user]
                if not isinstance(raw, bytes):
                    raise ValueError("signed cap must retain exact original bytes")
                p = first_cap_handoff._verify_cap_envelope(raw, pinned, public)
                aliases.sort(key=lambda alias: alias["email"])
                if (p["kind"] not in ("xmesh.quota-v2.xray-cap-admission",
                                     "xmesh.quota-v2.xray-cap-renewal")
                        or type(p["nodeId"]) is not int or p["nodeId"] != node
                        or type(p["userId"]) is not int or p["userId"] != user
                        or p["activationReceiptSha256"] != activation
                        or p["runtimeId"] != runtime_id
                        or p["policySha256"] != genesis_sha
                        or p["aliasScopes"] != aliases
                        or type(p["reservationRevision"]) is not int
                        or p["reservationRevision"] <= 0
                        or type(p["issuedAtMs"]) is not int
                        or type(p["validUntilMs"]) is not int
                        or p["issuedAtMs"] > time.time_ns() // 1_000_000
                        or p["validUntilMs"] <= time.time_ns() // 1_000_000):
                    raise ValueError("signed cap does not cover the exact measured roster")
                scope = {
                    "userId": user, "policySha256": p["policySha256"],
                    "accountEpoch": p["accountEpoch"],
                    "meterEpoch": p["meterEpoch"],
                    "reservationId": p["reservationId"],
                    "revision": p["reservationRevision"],
                    "nonce": p["nonce"], "aliases": aliases,
                }
                # Freeze source bytes and derived values. A caller changing
                # their dict later cannot silently switch grant or aliases.
                grants[user] = (raw, scope, tuple(alias["email"] for alias in aliases))
        self.profile_sha256 = hashlib.sha256(
            wal_transport.observed.canonical(profile)).hexdigest()
        self.node = node
        self.activation = activation
        self.runtime_id = runtime_id
        self.genesis_sha = genesis_sha
        self.pinned = pinned
        self._pid = trusted_pid
        self._socket = os.fspath(socket_path)
        self._grants = grants

    def check(self):
        """Fresh proof for EVERY signed alias; return no authorization."""
        for user, (raw, scope, aliases) in sorted(self._grants.items()):
            for email in aliases:
                result = cap_install.observe_installed_cap_in_xray(
                    self._socket, self._pid, self.runtime_id, self.node,
                    self.activation, raw, scope, email)
                # The lower layer checks nonce/digest, permit and consumption.
                # Independently ensure this never becomes public authority.
                if (not isinstance(result, dict)
                        or result.get("userId") != user
                        or result.get("email") != email
                        or result.get("installedLocalCap") is not True
                        or result.get("canServePublic") is not False
                        or result.get("canStart") is not False
                        or result.get("canResume") is not False):
                    raise ValueError("local Xray witness is foreign or claims TLS authority")
        return None
