# Strict-PQ-only clean bootstrap

XMesh Node v6.0.0 treats verified strict-PQ activation as a hard startup prerequisite.

A fresh node must complete the following sequence before any managed router/Xray/metrics/control runtime is allowed to start:

1. install the pinned v6 product client;
2. create/load the durable Ed25519 + ML-DSA-65 node identity;
3. redeem the owner-issued one-time enrollment token;
4. obtain the ML-DSA-65 mTLS client certificate and pinned panel response keys;
5. establish TLS 1.3 using `X25519MLKEM768`;
6. send the dual-signed XSP/2 activation request;
7. verify and persist the dual-signed activation receipt;
8. re-verify `productionActivation=true`, `strictPQEnabled=true`, and `automaticClassicalFallback=false`;
9. only then start the managed router and operational workers.

Any failure leaves the managed runtime stopped. There is no classical operational fallback in the v6 bootstrap path.
