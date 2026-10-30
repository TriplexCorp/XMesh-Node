package recovery

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

func appliedRetainedRotation(t *testing.T) (state.Layout, keyring.PublicBundle, keyring.PublicBundle) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "state")
	layout, err := state.Prepare(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = keyring.CreateMasterKey(layout.MasterKey); err != nil {
		t.Fatal(err)
	}
	previous, err := keyring.Initialize(layout.Vault, layout.MasterKey, 42, "node_request")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := keyring.PrepareRotation(layout.Vault, layout.MasterKey, previous.KeyEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = keyring.ActivatePreparedRotation(layout.Vault, layout.MasterKey, previous.KeyEpoch,
		candidate.EdKeyID, candidate.PQKeyID); err != nil {
		t.Fatal(err)
	}
	return layout, previous, candidate
}

func retirementFixture(t *testing.T) (SignedRetirementAuthorization, OwnerPublic, SignedCheckpoint, state.Layout) {
	t.Helper()
	layout, previous, candidate := appliedRetainedRotation(t)
	edPrivate, pqPrivate, pin := ownerPair(t)
	local := localEvidence(candidate.KeyEpoch, "req-retirement-checkpoint",
		[]byte("authoritative-dual-signed-retirement-receipt"), candidate.EdKeyID, candidate.PQKeyID)
	checkpoint := checkpointFor(t, 1, strings.Repeat("0", 64), local, pin)
	signedCheckpoint, err := Sign(checkpoint, edPrivate, pqPrivate)
	if err != nil {
		t.Fatal(err)
	}
	checkpointDigest, err := CheckpointDigest(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	authorization := RetirementAuthorization{
		NodeID:               uint64(candidate.NodeID),
		ServerAuthority:      checkpoint.ServerAuthority,
		FromEpoch:            previous.KeyEpoch,
		ToEpoch:              candidate.KeyEpoch,
		PriorEdKeyID:         previous.EdKeyID,
		PriorPQKeyID:         previous.PQKeyID,
		ActiveEdKeyID:        candidate.EdKeyID,
		ActivePQKeyID:        candidate.PQKeyID,
		CheckpointGeneration: checkpoint.Generation,
		CheckpointSHA256Hex:  checkpointDigest,
		IssuedAtMS:           checkpoint.IssuedAtMS + 100,
		ExpiresAtMS:          checkpoint.IssuedAtMS + 60_100,
		RequestID:            "retire-previous-epoch-1",
		OwnerID:              pin.OwnerID,
		OwnerEdKeyID:         pin.EdKeyID,
		OwnerPQKeyID:         pin.PQKeyID,
	}
	signedAuthorization, err := SignRetirementAuthorization(authorization, edPrivate, pqPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return signedAuthorization, pin, signedCheckpoint, layout
}

func TestOwnerRetirementAuthorizationBindsExactRetainedStateWithoutMutation(t *testing.T) {
	signed, pin, checkpoint, layout := retirementFixture(t)
	paths := []string{layout.Vault, layout.Vault + ".previous", layout.Vault + ".next", layout.Vault + ".min-epoch"}
	before := make(map[string][]byte, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = raw
	}

	now := signed.Authorization.IssuedAtMS + 1
	if err := VerifyRetirementAuthorization(signed, pin, checkpoint, 1, layout, now); err != nil {
		t.Fatalf("valid owner retirement authorization rejected: %v", err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before[path], raw) {
			t.Fatalf("retirement authorization mutated %s", filepath.Base(path))
		}
	}
}

func TestOwnerRetirementAuthorizationRejectsTamperStaleAndStateMismatch(t *testing.T) {
	signed, pin, checkpoint, layout := retirementFixture(t)
	now := signed.Authorization.IssuedAtMS + 1

	missingPQ := signed
	missingPQ.Signatures.MLDSA65 = ""
	if err := VerifyRetirementAuthorization(missingPQ, pin, checkpoint, 1, layout, now); err == nil {
		t.Fatal("missing ML-DSA-65 owner signature accepted")
	}
	if err := VerifyRetirementAuthorization(signed, pin, checkpoint, 1, layout,
		signed.Authorization.ExpiresAtMS+1); err == nil {
		t.Fatal("expired owner retirement authorization accepted")
	}

	edPrivate, pqPrivate, _ := ownerPair(t)
	_ = edPrivate
	_ = pqPrivate

	// Keep the authorization cryptographically valid while making its retained
	// previous identity disagree with the real encrypted Agent state.
	ownerEd, ownerPQ, ownerPin := ownerPair(t)
	mismatch := signed.Authorization
	mismatch.OwnerID = ownerPin.OwnerID
	mismatch.OwnerEdKeyID = ownerPin.EdKeyID
	mismatch.OwnerPQKeyID = ownerPin.PQKeyID
	mismatch.PriorEdKeyID = "ed-intentionally-wrong"
	mismatchSigned, err := SignRetirementAuthorization(mismatch, ownerEd, ownerPQ)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyRetirementAuthorization(mismatchSigned, ownerPin, checkpoint, 1, layout, now); err == nil {
		t.Fatal("retirement authorization for the wrong previous key accepted")
	}
}

func TestOwnerRetirementAuthorizationRejectsCheckpointSubstitution(t *testing.T) {
	signed, pin, checkpoint, layout := retirementFixture(t)
	edPrivate, pqPrivate, _ := ownerPair(t)
	_ = edPrivate
	_ = pqPrivate

	// A different, still-validly signed checkpoint cannot be substituted because
	// the authorization carries the exact canonical checkpoint digest.
	ownerEd, ownerPQ, ownerPin := ownerPair(t)
	local := localEvidence(signed.Authorization.ToEpoch, "different-request",
		[]byte("different-receipt"), signed.Authorization.ActiveEdKeyID, signed.Authorization.ActivePQKeyID)
	otherCheckpoint := checkpointFor(t, signed.Authorization.CheckpointGeneration,
		strings.Repeat("0", 64), local, ownerPin)
	otherSignedCheckpoint, err := Sign(otherCheckpoint, ownerEd, ownerPQ)
	if err != nil {
		t.Fatal(err)
	}
	migrated := signed.Authorization
	migrated.OwnerID = ownerPin.OwnerID
	migrated.OwnerEdKeyID = ownerPin.EdKeyID
	migrated.OwnerPQKeyID = ownerPin.PQKeyID
	migratedSigned, err := SignRetirementAuthorization(migrated, ownerEd, ownerPQ)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyRetirementAuthorization(migratedSigned, ownerPin, otherSignedCheckpoint, 1, layout,
		migrated.IssuedAtMS+1); err == nil {
		t.Fatal("different signed recovery checkpoint accepted for retirement")
	}

	// Preserve the original fixture check so this test cannot pass merely because
	// all verification paths are broken.
	if err = VerifyRetirementAuthorization(signed, pin, checkpoint, 1, layout,
		signed.Authorization.IssuedAtMS+1); err != nil {
		t.Fatalf("original retirement fixture unexpectedly invalid: %v", err)
	}
}

func TestRetirementAuthorizationDecodeRejectsAmbiguity(t *testing.T) {
	signed, _, _, _ := retirementFixture(t)
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeRetirementAuthorization(raw); err != nil {
		t.Fatalf("valid retirement authorization JSON rejected: %v", err)
	}
	duplicate := strings.Replace(string(raw), `"nodeId":42`, `"nodeId":42,"nodeId":42`, 1)
	if _, err = DecodeRetirementAuthorization([]byte(duplicate)); err == nil {
		t.Fatal("duplicate retirement authorization field accepted")
	}
	unknown := strings.Replace(string(raw), `"authorization":{`, `"authorization":{"unexpected":1,`, 1)
	if _, err = DecodeRetirementAuthorization([]byte(unknown)); err == nil {
		t.Fatal("unknown retirement authorization field accepted")
	}
}
