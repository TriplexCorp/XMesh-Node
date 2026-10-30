package recovery

import (
	"encoding/json"
	"reflect"
	"testing"
)

const (
	fuzzZeroDigest = "0000000000000000000000000000000000000000000000000000000000000000"
	fuzzDigestOne = "1111111111111111111111111111111111111111111111111111111111111111"
	fuzzDigestTwo = "2222222222222222222222222222222222222222222222222222222222222222"
)

var fuzzCheckpointSeed = []byte(`{"checkpoint":{"generation":1,"previousCheckpointSha256Hex":"` + fuzzZeroDigest + `","nodeId":1,"serverAuthority":"nexus.example","keyEpoch":1,"nodeEdKeyId":"ed-node","nodePqKeyId":"pq-node","commitRequestId":"req-1","commitReceiptSha256Hex":"` + fuzzDigestOne + `","nexusStateSha256Hex":"` + fuzzDigestTwo + `","issuedAtMs":1,"ownerId":"owner","ownerEdKeyId":"ed-owner","ownerPqKeyId":"pq-owner"},"signatures":{"ed25519":"","mldsa65":""}}`)

var fuzzRetirementRequestSeed = []byte(`{"schema":"xsp2-owner-retirement-request-1","nodeId":1,"serverAuthority":"nexus.example","fromEpoch":1,"toEpoch":2,"priorEdKeyId":"ed-old","priorPqKeyId":"pq-old","activeEdKeyId":"ed-new","activePqKeyId":"pq-new","checkpointGeneration":1,"checkpointSha256Hex":"` + fuzzDigestOne + `","checkpointIssuedAtMs":1,"ownerId":"owner","ownerEdKeyId":"ed-owner","ownerPqKeyId":"pq-owner","requestId":"req-1"}`)

var fuzzRetirementAuthorizationSeed = []byte(`{"authorization":{"nodeId":1,"serverAuthority":"nexus.example","fromEpoch":1,"toEpoch":2,"priorEdKeyId":"ed-old","priorPqKeyId":"pq-old","activeEdKeyId":"ed-new","activePqKeyId":"pq-new","checkpointGeneration":1,"checkpointSha256Hex":"` + fuzzDigestOne + `","issuedAtMs":1,"expiresAtMs":2,"requestId":"req-1","ownerId":"owner","ownerEdKeyId":"ed-owner","ownerPqKeyId":"pq-owner"},"signatures":{"ed25519":"","mldsa65":""}}`)

func fuzzSeeds(f *testing.F, valid []byte) {
	f.Helper()
	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{} {}`))
	f.Add([]byte(`{"unknown":true}`))
	f.Add([]byte{0xff, 0xfe, 0xfd})
}

func FuzzDecodeRecoveryCheckpoint(f *testing.F) {
	fuzzSeeds(f, fuzzCheckpointSeed)
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := Decode(raw)
		if err != nil {
			return
		}
		if _, err = Canonical(decoded.Checkpoint); err != nil {
			t.Fatalf("accepted checkpoint failed canonical validation: %v", err)
		}
		reencoded, err := json.Marshal(decoded)
		if err != nil {
			t.Fatalf("marshal accepted checkpoint: %v", err)
		}
		roundTrip, err := Decode(reencoded)
		if err != nil {
			t.Fatalf("strict decoder rejected its own accepted checkpoint: %v", err)
		}
		if !reflect.DeepEqual(decoded, roundTrip) {
			t.Fatal("checkpoint decode/marshal/decode changed semantic fields")
		}
	})
}

func FuzzDecodeRetirementRequest(f *testing.F) {
	fuzzSeeds(f, fuzzRetirementRequestSeed)
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := DecodeRetirementRequest(raw)
		if err != nil {
			return
		}
		if err = validateRetirementRequest(decoded); err != nil {
			t.Fatalf("accepted retirement request failed validation: %v", err)
		}
		reencoded, err := json.Marshal(decoded)
		if err != nil {
			t.Fatalf("marshal accepted retirement request: %v", err)
		}
		roundTrip, err := DecodeRetirementRequest(reencoded)
		if err != nil {
			t.Fatalf("strict decoder rejected its own accepted retirement request: %v", err)
		}
		if !reflect.DeepEqual(decoded, roundTrip) {
			t.Fatal("retirement request decode/marshal/decode changed semantic fields")
		}
	})
}

func FuzzDecodeRetirementAuthorization(f *testing.F) {
	fuzzSeeds(f, fuzzRetirementAuthorizationSeed)
	f.Fuzz(func(t *testing.T, raw []byte) {
		decoded, err := DecodeRetirementAuthorization(raw)
		if err != nil {
			return
		}
		if _, err = CanonicalRetirementAuthorization(decoded.Authorization); err != nil {
			t.Fatalf("accepted retirement authorization failed canonical validation: %v", err)
		}
		reencoded, err := json.Marshal(decoded)
		if err != nil {
			t.Fatalf("marshal accepted retirement authorization: %v", err)
		}
		roundTrip, err := DecodeRetirementAuthorization(reencoded)
		if err != nil {
			t.Fatalf("strict decoder rejected its own accepted retirement authorization: %v", err)
		}
		if !reflect.DeepEqual(decoded, roundTrip) {
			t.Fatal("retirement authorization decode/marshal/decode changed semantic fields")
		}
	})
}
