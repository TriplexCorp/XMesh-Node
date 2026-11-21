package main

import "testing"

// Zero-authority first-genesis policy key discovery must remain reachable via
// the OWNER-ENROLLED product transport but must not broaden it to any arbitrary
// URL, grant issuer, legacy profile route or caller-chosen path suffix.
func TestOnlyExactRegisteredProductOperationPaths(t *testing.T) {
	allowed := []string{
		"/api/v1/metrics/ingest",
		"/api/v1/node/desired-config",
		"/api/v1/node/quota-v2/wal",
		"/api/v1/node/quota-v2/policy-pin",
		"/api/v1/node/quota-v2/genesis-reservation",
	}
	for _, path := range allowed {
		if !allowedProductTunnelPath(path) {
			t.Fatalf("registered private XSP2 operation missing: %s", path)
		}
	}
	for _, path := range []string{
		"/api/v1/node/quota-v2/grant",
		"/api/v1/node/quota-v2/policy-pin/",
		"/api/v1/node/quota-v2/policy-pin?nodeId=47",
		"/api/v1/node/quota-v2/policy-pin/../wal",
		"/api/v1/node/quota-v2/genesis-reservation/",
		"/api/v1/node/quota-v2/genesis-reservation?userId=1",
		"/api/v1/node/quota-v2/genesis-reservation/../grant",
		"http://evil.invalid/api/v1/node/quota-v2/policy-pin",
		"/api/v1/node/desired-config/unsafe",
	} {
		if allowedProductTunnelPath(path) {
			t.Fatalf("unregistered product tunnel path accepted: %s", path)
		}
	}
}
