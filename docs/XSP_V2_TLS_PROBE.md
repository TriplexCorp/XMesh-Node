# XSP-v2 — PR07 hybrid TLS transport probe (27 October 2026)

> **Research / test-only checkpoint. Do not enable strict-pq or edit production TLS/Nginx based on this file.** These tests exercise full TLS handshakes against ephemeral test servers; they do NOT mean production Nexus ↔ Node is hybrid-protected. XSP-v2 signed-message authentication, minimum suite/epoch persistence, per-node key migration and certificate lifecycle are separate, unfinished gates.

## 1. What is actually deployed today

- Nexus `backend/src/main.rs` serves **HTTP** behind a separately deployed TLS reverse proxy. `deploy/install-panel-host.sh` generates a generic Nginx public HTTPS vhost, currently specifying `ssl_protocols TLSv1.2 TLSv1.3`. It does **not** force a post-quantum group. **The public dashboard and subscriptions must not be switched to strict mode in this experimental stage.**
- The production XMesh-Node router is built with **Go 1.23**, while the isolated test-only Go probe uses **Go 1.27.3** in nested `security/xspv2/poc-go`; no production Node binary, service, agent update, certificate or Nginx configuration is modified.
- An HTTPS chain can have independent termination hops: **Node → CDN/LB → Nginx → Nexus**. Verifying one TLS connection proves **only that one hop**. The current final Nginx → backend hop is HTTP and is **not** given TLS/PQ confidentiality by the external handshake.
- Hybrid **key agreement** (`X25519MLKEM768`, RFC 10024) is distinct from dual **message signatures** (Ed25519 AND ML-DSA-65). An ECDSA or RSA X.509 certificate is not itself post-quantum authenticated. Both security properties and classical certificate trust are required by the eventual threat model.

## 2. Strict diagnostic contract

The Node research-only package `tlsprobe` and command `cmd/tlsprobe` enforce the following for a **new, complete handshake**:

1. TLS **1.3 only**; no TLS 1.2 or automatic fallback.
2. Offer **only** `tls.X25519MLKEM768`. Read `tls.ConnectionState.CurveID` after the handshake; reject anything else. This checks the **negotiated** key exchange, not a supported-groups list, advertising or successful generic HTTPS response.
3. Verify the server's X.509 chain against the OS roots (or a consciously chosen **local lab** CA) and verify the exact intended DNS hostname/SNI. Never use `InsecureSkipVerify`, `curl -k`, `--insecure` or accept arbitrary certificates for diagnostics.
4. Reject absent peer certificate chains, incomplete handshake and resumption. A resumed session may not prove a new hybrid key agreement; the probe disables session caching and checks `DidResume`.
5. Have a bounded timeout, close the connection, send **no HTTP requests**, and emit only a minimal confirmation report. It neither enrolls a node nor changes any security floor, keys, config or policy.

The verifier also rejects an observed classical `CurveID` **even if TLS 1.3 and the certificate are valid**. Its associated tests demonstrate why simply enforcing TLS 1.3 is insufficient.

### Manual probe of an operator-chosen terminator

Requires Go 1.27.3; run from **XMesh-Node**, only against an endpoint you administer:

```bash
cd security/xspv2/poc-go
go run ./cmd/tlsprobe -address node-api.example.com:443 -servername node-api.example.com
```

A successful output confirms only that connection's **TLS 1.3 / X25519MLKEM768 / verified certificate / fresh handshake**. A non-zero exit means strict-PQ is **not proven**; leave the deployment in existing legacy mode. For local throwaway test CAs only, `-ca-file /path/to/local-ca.pem` can add a trust anchor; never use it to blindly accept internet endpoints.

### Provider and proxy inventory before future activation

Check **exact** TLS terminator (Nginx/Caddy/HAProxy/CDN/LB) and linked crypto library, not only `openssl version` on the host. For Nginx, inspect `nginx -V` and an appropriately redacted `nginx -T`; verify that its TLS library actually supports `X25519MLKEM768` and that configuration/virtual host selects that group. OpenSSL 3.5+ and its `-groups X25519MLKEM768` option can be used for a separate independent diagnostic. OpenSSL upstream documentation: https://docs.openssl.org/3.5/man3/SSL_CONF_cmd/. Do not assume an unmodified Nginx vhost negotiates the hybrid group just because the linked library supports it.

For a future dedicated node-only endpoint, the likely prerequisites are TLS 1.3-only, an explicitly constrained `X25519MLKEM768` group, trusted certificate/hostname/SNI, exact signed path mapping, measured current negotiation and an intentionally planned compatibility window. Any actual Nginx changes need a **separate reviewed change** with `nginx -t`, staged restart/reload, DNS/ACME/renewal checks, canary metrics, and a rollback procedure that does not lower a node's durable `minimumSuite`.

## 3. CI evidence and negative controls

- The Node isolated Go workflow runs `go test -race -count=1 ./...` in `poc-go`; `tlsprobe/probe_test.go` uses fresh test certificates and an actual TCP/TLS listener, verifying a full `CurveID == X25519MLKEM768` handshake. Negative scenarios include TLS 1.2, TLS 1.3 X25519-only server, incorrect hostname, untrusted certificate and resumed/incomplete handshake state.
- The Nexus isolated `.github/workflows/xsp-hybrid-tls.yml` tests **real OpenSSL 3.5+ `s_server`/`s_client` handshakes**, verifies the reported group and chain, and invokes the separately built Go CLI against the same ephemeral OpenSSL server. It additionally establishes a **valid classical TLS 1.3 X25519 control handshake**, then asserts the strict Go hybrid probe refuses it.
- All test CAs/keys are generated at runtime and discarded. No real tenant secrets, public proxy settings or running nodes are touched.
- A green local or CI test **does not prove** the production ingress TLS terminator uses X25519MLKEM768, nor does it prove security on every TLS leg.

## 4. Still-open security gates

- [ ] Measure and record live canary Node → real HTTPS terminator handshake group, certificate chain and SNI; repeat across all regional proxies. **No probe has been run against the user's VPS.**
- [ ] Inventory and either secure or formally assess CDN/LB → origin and Nginx → API boundaries. The existing HTTP backend hop cannot be claimed to use hybrid TLS.
- [ ] Add durable per-node `minimumSuite`/epoch, atomic replay state, verified **responses and commands**, authenticated two-phase enrollment, key rotation and recovery. Refuse v1 fallback only **after** explicit owner-approved strict activation.
- [ ] Review TLS termination configuration and potential separate node-only endpoint; test ACME renewal, availability, session resumption, time drift, partial failure, downgrade telemetry and recovery.
- [ ] Independent security review, FIPS 204 known-answer/fuzz coverage, rollout on disposable VPS, backups and signed rollback protections.
- [ ] Before publishing production-ready claims, record latest **green CI in both repositories** and real, recorded canary evidence.

**Activation remains disabled.** PR07 research validates the TLS mechanism only; it is not a deployed strict-PQ node transport.
