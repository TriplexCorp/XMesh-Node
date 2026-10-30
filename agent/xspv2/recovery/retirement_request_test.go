package recovery

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func issuanceFixture(t *testing.T) (RetirementRequest, SignedCheckpoint, OwnerPublic, []byte, []byte, int64, interface{}) {
	t.Helper()
	panic("unused helper placeholder")
}

func TestRetirementRequestAndOfflineIssuanceRoundTrip(t *testing.T) {
	layout, previous, candidate := appliedRetainedRotation(t)
	edPrivate, pqPrivate, pin := ownerPair(t)
	local := localEvidence(candidate.KeyEpoch, "req-offline-issuance-checkpoint",
		[]byte("offline-issuance-authoritative-receipt"), candidate.EdKeyID, candidate.PQKeyID)
	checkpointValue := checkpointFor(t, 3, strings.Repeat("a", 64), local, pin)
	checkpoint, err := Sign(checkpointValue, edPrivate, pqPrivate)
	if err != nil {
		t.Fatal(err)
	}

	paths := []string{layout.Vault, layout.Vault + ".previous", layout.Vault + ".next", layout.Vault + ".min-epoch"}
	before := make(map[string][]byte, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = raw
	}

	request, err := BuildRetirementRequest(checkpoint, layout, "retirement-request-3")
	if err != nil {
		t.Fatal(err)
	}
	if request.FromEpoch != previous.KeyEpoch || request.ToEpoch != candidate.KeyEpoch ||
		request.PriorEdKeyID != previous.EdKeyID || request.PriorPQKeyID != previous.PQKeyID ||
		request.ActiveEdKeyID != candidate.EdKeyID || request.ActivePQKeyID != candidate.PQKeyID ||
		request.OwnerID != pin.OwnerID || request.OwnerEdKeyID != pin.EdKeyID || request.OwnerPQKeyID != pin.PQKeyID {
		t.Fatalf("unexpected public retirement request: %+v", request)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before[path], raw) {
			t.Fatalf("request export mutated Agent state: %s", filepath.Base(path))
		}
	}

	now := checkpointValue.IssuedAtMS + 1000
	signed, err := IssueRetirementAuthorization(request, checkpoint, edPrivate, pqPrivate, now, 60_000)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Authorization.RequestID != request.RequestID || signed.Authorization.IssuedAtMS != now ||
		signed.Authorization.ExpiresAtMS != now+60_000 {
		t.Fatal("offline issuance changed request identity or validity window")
	}
	if err = VerifyRetirementAuthorization(signed, pin, checkpoint, checkpointValue.Generation, layout, now+1); err != nil {
		t.Fatalf("offline-issued authorization rejected by final Agent verifier: %v", err)
	}
}

func TestOfflineIssuanceRejectsWrongOwnerTamperAndInvalidLifetime(t *testing.T) {
	layout, _, candidate := appliedRetainedRotation(t)
	edPrivate, pqPrivate, pin := ownerPair(t)
	local := localEvidence(candidate.KeyEpoch, "req-offline-negative",
		[]byte("offline-negative-receipt"), candidate.EdKeyID, candidate.PQKeyID)
	checkpointValue := checkpointFor(t, 1, strings.Repeat("0", 64), local, pin)
	checkpoint, err := Sign(checkpointValue, edPrivate, pqPrivate)
	if err != nil {
		t.Fatal(err)
	}
	request, err := BuildRetirementRequest(checkpoint, layout, "retirement-negative")
	if err != nil {
		t.Fatal(err)
	}
	now := checkpointValue.IssuedAtMS + 1

	wrongEd, wrongPQ, _ := ownerPair(t)
	if _, err = IssueRetirementAuthorization(request, checkpoint, wrongEd, wrongPQ, now, 60_000); err == nil {
		t.Fatal("wrong owner private keys issued retirement authorization")
	}

	tampered := request
	tampered.ActiveEdKeyID = "ed-tampered"
	if _, err = IssueRetirementAuthorization(tampered, checkpoint, edPrivate, pqPrivate, now, 60_000); err == nil {
		t.Fatal("checkpoint-mismatched retirement request was signed")
	}
	badAuthority := request
	badAuthority.ServerAuthority = "https://evil.invalid"
	if _, err = IssueRetirementAuthorization(badAuthority, checkpoint, edPrivate, pqPrivate, now, 60_000); err == nil {
		t.Fatal("URL-like server authority was signed")
	}
	if _, err = IssueRetirementAuthorization(request, checkpoint, edPrivate, pqPrivate, now, 0); err == nil {
		t.Fatal("zero authorization lifetime accepted")
	}
	if _, err = IssueRetirementAuthorization(request, checkpoint, edPrivate, pqPrivate, now, 300_001); err == nil {
		t.Fatal("authorization lifetime above five minutes accepted")
	}
	if _, err = IssueRetirementAuthorization(request, checkpoint, edPrivate, pqPrivate,
		checkpointValue.IssuedAtMS-1, 1); err == nil {
		t.Fatal("authorization issued before checkpoint accepted")
	}
}

func TestRetirementRequestDecodeRejectsAmbiguity(t *testing.T) {
	layout, _, candidate := appliedRetainedRotation(t)
	edPrivate, pqPrivate, pin := ownerPair(t)
	local := localEvidence(candidate.KeyEpoch, "req-decode-request",
		[]byte("decode-request-receipt"), candidate.EdKeyID, candidate.PQKeyID)
	checkpointValue := checkpointFor(t, 1, strings.Repeat("0", 64), local, pin)
	checkpoint, err := Sign(checkpointValue, edPrivate, pqPrivate)
	if err != nil {
		t.Fatal(err)
	}
	request, err := BuildRetirementRequest(checkpoint, layout, "decode-request")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeRetirementRequest(raw); err != nil {
		t.Fatalf("valid retirement request rejected: %v", err)
	}
	duplicate := strings.Replace(string(raw), `"nodeId":42`, `"nodeId":42,"nodeId":42`, 1)
	if _, err = DecodeRetirementRequest([]byte(duplicate)); err == nil {
		t.Fatal("duplicate retirement request field accepted")
	}
	unknown := strings.Replace(string(raw), `"schema":`, `"unexpected":1,"schema":`, 1)
	if _, err = DecodeRetirementRequest([]byte(unknown)); err == nil {
		t.Fatal("unknown retirement request field accepted")
	}
}

func TestBuildRetirementRequestRejectsCheckpointStateMismatch(t *testing.T) {
	layout, _, candidate := appliedRetainedRotation(t)
	edPrivate, pqPrivate, pin := ownerPair(t)
	local := localEvidence(candidate.KeyEpoch, "req-state-mismatch",
		[]byte("state-mismatch-receipt"), candidate.EdKeyID, candidate.PQKeyID)
	checkpointValue := checkpointFor(t, 1, strings.Repeat("0", 64), local, pin)
	checkpointValue.KeyEpoch++
	checkpoint, err := Sign(checkpointValue, edPrivate, pqPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = BuildRetirementRequest(checkpoint, layout, "state-mismatch"); err == nil {
		t.Fatal("checkpoint ahead of retained Agent state exported as retirement request")
	}
}
