#!/usr/bin/env python3
"""XMesh v6 policy-guard compatibility layer for independent protocol secrets.

Nexus signs the complete desired Xray configuration through configSha256, while
policy users retain the stable VLESS xrayId used for quota/expiry accounting.
Newer Nexus releases intentionally provision distinct credentials for VMess,
Trojan, Hysteria2, MASQUE and Shadowsocks. This layer keeps the existing policy
guard and its offline-accounting rules intact while resolving signed accounts
through their signed xmesh-u<ID>--<tag> identity instead of requiring every
transport secret to equal the VLESS UUID.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import re
import sys
import uuid

HERE = Path(__file__).resolve().parent
BASE_CANDIDATES = [
    HERE / "xmesh-policy-guard-base.py",
    Path("/opt/xmesh-node/deploy/xmesh-policy-guard-base.py"),
]
BASE = next((path for path in BASE_CANDIDATES if path.is_file() and path.resolve() != Path(__file__).resolve()), None)
if BASE is None:
    raise SystemExit("XMesh v6 policy guard base helper is missing")

spec = importlib.util.spec_from_file_location("xmesh_policy_guard_base", BASE)
if spec is None or spec.loader is None:
    raise SystemExit("XMesh v6 policy guard base helper cannot be loaded")
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

# Keep immutable references to the reviewed historical helpers before the base
# module globals are redirected to the v6 independent-credential semantics.
_base_configured_accounts = base.configured_accounts

# Export the base module API so xmesh-profile-attest.py can import this installed
# file exactly as it imported the historical guard.
for _name in dir(base):
    if not _name.startswith("__"):
        globals()[_name] = getattr(base, _name)

HEX_256 = re.compile(r"^[0-9a-fA-F]{64}$")


def _valid_signed_credential(protocol: str, method: str, credential: str, legacy_xray_id: str) -> bool:
    """Validate shape only; authenticity comes from the signed config digest."""
    if credential == legacy_xray_id:
        # Existing records may intentionally retain the historical UUID until
        # the owner performs an explicit VPN credential rotation.
        return True
    if protocol == "vmess":
        try:
            uuid.UUID(credential)
            return True
        except (ValueError, AttributeError):
            return False
    if protocol == "shadowsocks" and method.startswith("2022-"):
        # The complete independent PSK is covered by the signed config digest.
        return bool(credential) and len(credential) <= 512
    if protocol in ("trojan", "hysteria", "masque", "shadowsocks"):
        # Nexus currently generates 256-bit hex secrets for these protocols.
        return bool(HEX_256.fullmatch(credential))
    return protocol == "vless" and credential == legacy_xray_id


def configured_accounts(inbound):
    entries, credential_key = _base_configured_accounts(inbound)
    # A signed config must not assign one transport credential to two panel
    # identities. The email is the stable accounting binding, but authentication
    # at Xray still happens through the transport credential itself.
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Malformed signed proxy account")
        credential = entry.get(credential_key)
        if not isinstance(credential, str) or not credential or credential in seen:
            raise ValueError("Duplicate or missing signed proxy credential")
        seen.add(credential)
    return entries, credential_key


def account_uuid(entry, credential_key, identities):
    if not isinstance(entry, dict):
        return None
    email = entry.get("email")
    if not isinstance(email, str) or not email.startswith("xmesh-u"):
        # New managed profiles always carry the signed accounting identity.
        # Preserve only the historical VLESS email-less form.
        credential = entry.get(credential_key)
        if identities.get("_protocol") != "vless" or not isinstance(credential, str):
            return None
        return credential
    match = re.fullmatch(r"xmesh-u([1-9][0-9]*)--[^\s]+", email)
    if match is None:
        return None
    user = identities.get(int(match.group(1)))
    if not isinstance(user, str):
        return None
    credential = entry.get(credential_key)
    if not isinstance(credential, str) or not credential:
        return None
    protocol = str(identities.get("_protocol") or "")
    method = str(identities.get("_method") or "")
    if not _valid_signed_credential(protocol, method, credential, user):
        return None
    # Return the stable policy UUID, not the protocol secret. Quota, expiry and
    # offline revocation continue to be keyed by the panel user's xrayId.
    return user


# Functions defined in the base module resolve globals from the base module's
# dictionary. Replace both helpers there before exposing/using verify_envelope
# or enforce, otherwise the compatibility layer would be cosmetic only.
base.configured_accounts = configured_accounts
base.account_uuid = account_uuid
globals()["configured_accounts"] = configured_accounts
globals()["account_uuid"] = account_uuid

if __name__ == "__main__":
    try:
        base.main()
    except (ValueError, TypeError, KeyError, OSError, base.subprocess.SubprocessError) as exc:
        print(f"XMesh policy/user meter: {exc}", file=sys.stderr)
        raise SystemExit(1)
