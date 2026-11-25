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


def compile_public_tls(profile, bindings):
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
