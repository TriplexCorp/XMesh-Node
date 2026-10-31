# XMesh Node v6.0.0 — strict-PQ-only bootstrap

Security invariant for fresh v6 nodes:

- no router, managed Xray, metrics, control or reconciliation runtime may start before the product client verifies a durable dual-signed activation receipt;
- bootstrap uses TLS 1.3 with `X25519MLKEM768`, ML-DSA-65 client identity, and Ed25519 + ML-DSA-65 XSP/2 message signatures;
- operational node API traffic is carried only through the strict-PQ product tunnel;
- automatic/classical fallback is forbidden;
- failure to enroll, activate, verify the receipt, or establish the strict-PQ transport leaves the node fail-closed.

`strictPQEnabled=true` is therefore an evidence-backed activation state, not an installation/version badge.
