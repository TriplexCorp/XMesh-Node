package retirementattestation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

type fixture struct {
	scope       Scope
	nodeSecret  ed25519.PrivateKey
	nexusSecret ed25519.PrivateKey
	observation map[string]any
	payload     map[string]any
}

func hash(c string) string { return strings.Repeat(c, 64) }

func newFixture(t *testing.T) fixture {
	t.Helper()
	node, nodeSecret, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	nexus, nexusSecret, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{
		scope:       Scope{NodeID: 42, ActivationReceiptSHA256: hash("a"), NodePublicKey: node, NexusPublicKey: nexus},
		nodeSecret:  nodeSecret,
		nexusSecret: nexusSecret,
	}
	f.observation = map[string]any{
		"schemaVersion":              1,
		"kind":                       "xmesh.quota-v2.nonfinal-first-meter-retirement",
		"nodeId":                     42,
		"runtimeId":                  hash("b"),
		"containerId":                hash("c"),
		"startedAt":                  "2026-11-27T04:00:00.123456789Z",
		"signedWalReadbackSha256":    hash("d"),
		"inventorySha256":            hash("e"),
		"committedChargeHeadsSha256": hash("f"),
		"durableUserDenials":         map[string]any{"100": hash("0"), "101": hash("1")},
		"originalMeterPidfdExited":   true,
		"lifetimeLockReleased":       true,
		"finalMeterVerified":         false,
		"settlementEligible":         false,
		"canResume":                  false,
		"refundableBytes":            0,
		"retiredLedgerSha256":        hash("2"),
		"deliveredBytesVerified":     false,
		"nodeSignatureVerified":      false,
		"canServePublic":             false,
		"canStart":                   false,
	}
	f.payload = map[string]any{
		"schemaVersion":                           2,
		"kind":                                    "xmesh.quota-v2.public-tls-wal-head",
		"nodeId":                                  42,
		"userId":                                  100,
		"activationReceiptSha256":                 hash("a"),
		"genesisPolicySha256":                     hash("3"),
		"runtimeId":                               hash("b"),
		"profileRevision":                         hash("4"),
		"capRosterSha256":                         hash("5"),
		"challenge":                               hash("6"),
		"containerId":                             hash("c"),
		"hostPid":                                 731,
		"startedAt":                               "2026-11-27T04:00:00.123456789Z",
		"issuedAtMs":                              11000,
		"validUntilMs":                            18000,
		"historyState":                            "committed_birth_index",
		"inventorySequence":                       2,
		"inventorySha256":                         hash("e"),
		"inventoryTailDigest":                     hash("7"),
		"committedChargeStreamCount":              2,
		"committedChargeHeadsSha256":              hash("f"),
		"preBootstrapHistoryCompletenessVerified": false,
		"liveMeterVerified":                       false,
		"finalMeterVerified":                      false,
		"canServePublic":                          false,
		"canSpend":                                false,
		"canStart":                                false,
		"canResume":                               false,
		"authorizedBytes":                         0,
		"refundableBytes":                         0,
	}
	return f
}

func marshal(t *testing.T, obj any) []byte {
	t.Helper()
	raw, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f fixture) archive(t *testing.T, domain string) []byte {
	t.Helper()
	message := append([]byte(domain), marshal(t, f.payload)...)
	doc := map[string]any{
		"algorithm": "Ed25519",
		"payload":   f.payload,
		"signature": hex.EncodeToString(ed25519.Sign(f.nexusSecret, message)),
	}
	wire := append(marshal(t, doc), '\n')
	response := marshal(t, map[string]any{"signedEnvelope": string(wire)})
	f.observation["signedWalReadbackSha256"] = digest(response)
	return append(marshal(t, map[string]any{
		"observation": f.observation, "nexusResponse": string(response),
	}), '\n')
}

func (f fixture) signer(message []byte) ([]byte, error) {
	return ed25519.Sign(f.nodeSecret, message), nil
}

func TestExactArchivePossessionNotPhysicalFinality(t *testing.T) {
	f := newFixture(t)
	raw := f.archive(t, nexusDomain)
	signature, err := Sign(raw, f.scope, f.signer)
	if err != nil || Verify(raw, f.scope, signature) != nil {
		t.Fatalf("valid historical archive rejected: %v", err)
	}
	message, err := Message(raw, f.scope)
	if err != nil || !bytes.HasPrefix(message, []byte(Domain)) {
		t.Fatalf("unexpected protocol message: %v", err)
	}
	p, err := object(message[len(Domain):], false)
	if err != nil || !flags(p, "archivePossessionOnly", true) ||
		!flags(p, "localObservationsVerified liveMeterVerified deliveredBytesVerified finalMeterVerified settlementEligible canServePublic canSpend canStart canResume", false) ||
		integer(p, "authorizedBytes") != 0 || integer(p, "refundableBytes") != 0 ||
		str(p, "archiveSha256") != digest(raw) {
		t.Fatal("signature falsely asserts authority or physical finality")
	}
	// The unsigned local claims could have been fabricated by a root process.
	// The protocol may attest the NEW archive's possession, but the old
	// signature must NOT validate it and no signature attests kernel truth.
	f.observation["retiredLedgerSha256"] = hash("8")
	changed := f.archive(t, nexusDomain)
	if Verify(changed, f.scope, signature) == nil {
		t.Fatal("signature accepted a modified local observation")
	}
	if _, err := Sign(changed, f.scope, f.signer); err != nil {
		t.Fatal("archive possession is not meant to certify the local observation")
	}
}

func TestForeignKeysScopesAndDomainsRejected(t *testing.T) {
	f := newFixture(t)
	raw := f.archive(t, nexusDomain)
	signature, err := Sign(raw, f.scope, f.signer)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Scope){
		func(s *Scope) { s.NodeID++ },
		func(s *Scope) { s.ActivationReceiptSHA256 = hash("9") },
		func(s *Scope) { s.NodePublicKey = s.NexusPublicKey },
		func(s *Scope) { s.NexusPublicKey = s.NodePublicKey },
	} {
		foreign := f.scope
		mutate(&foreign)
		if Verify(raw, foreign, signature) == nil {
			t.Fatal("foreign key or enrollment accepted")
		}
	}
	if _, err := Sign(raw, f.scope, func(message []byte) ([]byte, error) {
		return ed25519.Sign(f.nexusSecret, message), nil
	}); err == nil {
		t.Fatal("compatibility/wrong key accepted")
	}
	if _, err := Sign(f.archive(t, "XMESH_QUOTA_V2_OFFHOST_WAL_BIRTH_WITNESS_V1\x00"), f.scope, f.signer); err == nil {
		t.Fatal("cross-domain Nexus signature accepted")
	}
	if Verify(raw, f.scope, signature[:31]) == nil {
		t.Fatal("truncated signature accepted")
	}
}

func TestGenuinelySignedButInvalidWitnessesNeverReachSigner(t *testing.T) {
	for _, tc := range []struct {
		key   string
		value any
	}{
		{"nodeId", 43}, {"activationReceiptSha256", hash("9")},
		{"hostPid", 1}, {"runtimeId", hash("9")}, {"userId", 999},
		{"committedChargeHeadsSha256", hash("9")}, {"committedChargeStreamCount", 1},
		{"issuedAtMs", 10000}, {"validUntilMs", 10000},
		{"finalMeterVerified", true}, {"canSpend", true}, {"refundableBytes", 1},
		{"authorizedBytes", false}, {"schemaVersion", 2.1},
	} {
		t.Run(tc.key, func(t *testing.T) {
			f := newFixture(t)
			f.payload[tc.key] = tc.value
			called := false
			_, err := Sign(f.archive(t, nexusDomain), f.scope, func(message []byte) ([]byte, error) {
				called = true
				return f.signer(message)
			})
			if err == nil || called {
				t.Fatal("invalid Nexus payload reached enrolled signer")
			}
		})
	}
}

func TestRejectMalformedAndAuthorizingArchive(t *testing.T) {
	f := newFixture(t)
	raw := f.archive(t, nexusDomain)
	duplicate := bytes.Replace(raw, []byte(`"nodeId":42`), []byte(`"nodeId":42,"nodeId":42`), 1)
	// Replace operates on the nested observation, not escaped response bytes.
	if bytes.Equal(raw, duplicate) {
		t.Fatal("test did not form duplicate")
	}
	for _, bad := range [][]byte{
		nil, bytes.Repeat([]byte("a"), maxArchive+1), raw[:len(raw)-1],
		duplicate, append(bytes.Clone(raw), []byte("{}")...),
	} {
		if _, err := Message(bad, f.scope); err == nil {
			t.Fatal("invalid bytes accepted")
		}
	}
	for _, key := range []string{"canResume", "finalMeterVerified", "settlementEligible", "nodeSignatureVerified", "deliveredBytesVerified"} {
		f := newFixture(t)
		f.observation[key] = true
		if _, err := Message(f.archive(t, nexusDomain), f.scope); err == nil {
			t.Fatalf("authorizing observation accepted: %s", key)
		}
	}
	f = newFixture(t)
	f.observation["durableUserDenials"] = map[string]any{"0100": hash("a")}
	if _, err := Message(f.archive(t, nexusDomain), f.scope); err == nil {
		t.Fatal("invalid denial identity accepted")
	}
}

func TestEmptyHistoricalWitnessStillNotAStatementOfCompleteness(t *testing.T) {
	f := newFixture(t)
	f.payload["historyState"] = "empty_remote_history"
	f.payload["inventorySequence"] = 0
	f.payload["committedChargeStreamCount"] = 0
	f.payload["inventorySha256"] = digest(nil)
	f.payload["inventoryTailDigest"] = hash("0")
	f.payload["committedChargeHeadsSha256"] = digest([]byte("[]"))
	f.observation["inventorySha256"] = digest(nil)
	f.observation["committedChargeHeadsSha256"] = digest([]byte("[]"))
	if _, err := Sign(f.archive(t, nexusDomain), f.scope, f.signer); err != nil {
		t.Fatal(err)
	}
	f.payload["preBootstrapHistoryCompletenessVerified"] = true
	if _, err := Message(f.archive(t, nexusDomain), f.scope); err == nil {
		t.Fatal("signed empty history turned into pre-bootstrap completeness")
	}
}
