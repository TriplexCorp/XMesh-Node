"""Pure, non-authorizing public TLS overlay for a private Quota V2 VLESS ingress.

This module deliberately does NOT install or enable a listener. Its input must
come from a separately authenticated, signed Nexus public-ingress admission
bound to the exact enrolled metering policy and original strict-PQ receipt.
Until that issuer and the installed release tests exist, callers MUST NOT use
its output to expose a port. The metered Xray's signed raw TCP configuration
is neither mutated nor allowed to accept unmetered traffic.
"""
from copy import deepcopy
import re

import vless_ingress

DOMAIN = re.compile(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
TAGS = {"vless-main", "vless-cdn"}
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
HEX128 = re.compile(r"[a-f0-9]{128}\Z")


def verify_signed_public_tls(raw, *, node, activation, genesis_sha,
                             runtime_id, profile_revision, pinned, now_ms=None):
    """Authenticate a short-lived independent Nexus Ed25519 TLS authority.

    This is a public-listener CONFIG approval, not a traffic grant. The
    installed worker must still require the original metered Genesis policy,
    active per-user signed spending caps, and the trusted runtime identity.
    Runtime expiry/revocation must be enforced by the eventual supervisor;
    checking validity only at initial startup is insufficient for promotion.
    """
    import time
    import quarantine_policy as quarantine
    import wal_transport

    if not isinstance(raw, bytes) or not 0 < len(raw) <= 8192:
        raise ValueError("invalid signed public TLS envelope size")
    doc = wal_transport.observed.strict_json(raw)
    if (not isinstance(doc, dict)
            or set(doc) != {"algorithm", "payload", "signature"}
            or doc["algorithm"] != "Ed25519"
            or not isinstance(doc["signature"], str)
            or not HEX128.fullmatch(doc["signature"])):
        raise ValueError("invalid signed public TLS envelope")
    policy = doc["payload"]
    expected = {
        "schemaVersion": 1, "kind": "xmesh.quota-v2.public-tls-ingress",
        "nodeId": node, "activationReceiptSha256": activation,
        "genesisPolicySha256": genesis_sha,
        "runtimeId": runtime_id, "profileRevision": profile_revision,
        "canServePublic": True,
    }
    if (not isinstance(policy, dict)
            or set(policy) != set(expected) | {"issuedAtMs", "validUntilMs", "bindings"}
            or any(type(policy[k]) is not type(v) or policy[k] != v
                   for k, v in expected.items())
            or type(node) is not int or node <= 0
            or any(not isinstance(item, str) or not HEX64.fullmatch(item)
                   for item in (activation, genesis_sha, runtime_id, profile_revision, pinned))
            or type(policy["issuedAtMs"]) is not int
            or type(policy["validUntilMs"]) is not int):
        raise ValueError("foreign or malformed signed public TLS authority")
    now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    if (type(now) is not int or now < policy["issuedAtMs"]
            or policy["validUntilMs"] <= now
            or policy["validUntilMs"] - policy["issuedAtMs"] > 120_000):
        raise ValueError("expired or overlong public TLS authorization")
    quarantine._guard().check_signature(policy, doc["signature"], pinned)
    bindings = policy["bindings"]
    if not isinstance(bindings, list):
        raise ValueError("signed public TLS bindings must be a list")
    # Reuse exact compiler grammar; caller must independently bind it to the
    # signed VLESS roster and only then publish a public listener.
    return deepcopy(bindings)




def compile_signed_public_tls(profile, signed_envelope, *, node, activation,
                              genesis_sha, runtime_id, pinned, now_ms=None):
    """Only supported public compiler entry: fail closed without Ed25519 proof.

    Caller still must check current per-user caps, trusted meter process,
    certificate lineage and online revocation throughout the listener life.
    Production wiring is intentionally absent until those gates exist.
    """
    import hashlib
    import wal_transport

    # The revision is calculated from the original signed, QUARANTINED raw
    # VLESS configuration. Do not accept a caller-supplied revision that could
    # point at a different roster or transport after admission was signed.
    if not isinstance(profile, dict):
        raise ValueError("missing measured Genesis profile")
    profile_revision = hashlib.sha256(wal_transport.observed.canonical(profile)).hexdigest()
    bindings = verify_signed_public_tls(
        signed_envelope, node=node, activation=activation, genesis_sha=genesis_sha,
        runtime_id=runtime_id, profile_revision=profile_revision, pinned=pinned,
        now_ms=now_ms)
    return _compile_verified_tls_config(profile, bindings)



def _compile_verified_tls_config(profile, bindings):
    """Produce an isolated TLS frontend, never a metered Xray configuration.

    The caller, not this pure compiler, must cryptographically authenticate
    the independent signed public listener contract and check cap admission.
    Config output has no direct/freedom route, no fallback, and no unsecured
    inbound, even when clients are present on both main and CDN scopes.
    """
    base = vless_ingress.frontend(profile)
    if (not isinstance(bindings, list) or not 1 <= len(bindings) <= 2
            or len(bindings) != len(base["inbounds"])):
        raise ValueError("public TLS scope does not match signed VLESS roster")
    indexed = {}
    bound_ports = set()
    for binding in bindings:
        if not isinstance(binding, dict) or set(binding) != {"tag", "port", "domain"}:
            raise ValueError("unsupported public TLS binding shape")
        tag, port, domain = binding["tag"], binding["port"], binding["domain"]
        if (not isinstance(tag, str) or tag not in TAGS or tag in indexed
                or type(port) is not int or not 1 <= port <= 65535 or port in bound_ports
                or not isinstance(domain, str) or not DOMAIN.fullmatch(domain)):
            raise ValueError("noncanonical or conflicting public TLS listener")
        indexed[tag] = (port, domain)
        bound_ports.add(port)
    if set(indexed) != {inbound["tag"] for inbound in base["inbounds"]}:
        raise ValueError("public TLS binding does not cover exact signed inbounds")
    config = deepcopy(base)
    for inbound in config["inbounds"]:
        tag = inbound["tag"]
        current = inbound.get("streamSettings", {})
        if (not isinstance(current, dict) or
                any(k not in ("network", "security") for k in current) or
                current.get("network", "tcp") not in ("tcp", "raw") or
                current.get("security", "none") != "none"):
            raise ValueError("metering profile cannot already contain a TLS or tunnel transport")
        port, domain = indexed[tag]
        # Only canonical root-managed ACME lineages. No arbitrary paths can
        # be supplied by a user-controlled Host, profile or binding object.
        cert_root = f"/etc/letsencrypt/live/{domain}"
        inbound["listen"] = "0.0.0.0"
        inbound["port"] = port
        inbound["streamSettings"] = {
            "network": "tcp", "security": "tls",
            "tlsSettings": {
                "serverName": domain, "minVersion": "1.3",
                "certificates": [{
                    "certificateFile": cert_root + "/fullchain.pem",
                    "keyFile": cert_root + "/privkey.pem",
                }],
            },
        }
    # Defensive invariant: the bridge is allowed only a blackhole and the
    # exact patched private meter destination. If this ever changes, adding
    # a public listener must fail before a config is published.
    for outbound in config["outbounds"]:
        if outbound["tag"] == "deny":
            if outbound != {"tag": "deny", "protocol": "blackhole"}:
                raise ValueError("unexpected public TLS deny route")
        elif (outbound.get("protocol") != "vless" or
              any(next_hop.get("address") != "xmesh-meter.invalid" or
                  next_hop.get("port") != 1
                  for next_hop in outbound.get("settings", {}).get("vnext", [])) or
              len(outbound.get("settings", {}).get("vnext", [])) != 1):
            raise ValueError("public TLS may only dial the private signed meter")
    return config
