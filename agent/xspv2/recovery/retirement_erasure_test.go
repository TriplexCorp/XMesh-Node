package recovery

import (
	"bytes"
	"os"
	"testing"

	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

func TestRetireAuthorizedPreviousErasesOnlyRetainedOldMaterial(t *testing.T) {
	signed, pin, checkpoint, layout := retirementFixture(t)
	activeBefore, err := os.ReadFile(layout.Vault)
	if err != nil {
		t.Fatal(err)
	}
	floorBefore, err := os.ReadFile(layout.Vault + ".min-epoch")
	if err != nil {
		t.Fatal(err)
	}
	now := signed.Authorization.IssuedAtMS + 1

	snapshot, err := RetireAuthorizedPrevious(signed, pin, checkpoint, 1, layout, now)
	if err != nil {
		t.Fatalf("authorized retirement failed: %v", err)
	}
	if snapshot.NodeID <= 0 || uint64(snapshot.NodeID) != signed.Authorization.NodeID ||
		snapshot.KeyEpoch != signed.Authorization.ToEpoch || snapshot.EdKeyID != signed.Authorization.ActiveEdKeyID ||
		snapshot.PQKeyID != signed.Authorization.ActivePQKeyID || snapshot.PreviousRetained || snapshot.CandidateRetained {
		t.Fatalf("unexpected post-retirement Agent snapshot: %+v", snapshot)
	}
	for _, path := range []string{layout.Vault + ".previous", layout.Vault + ".next"} {
		if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
			t.Fatalf("retired key material still exists: %s err=%v", path, statErr)
		}
	}
	activeAfter, err := os.ReadFile(layout.Vault)
	if err != nil {
		t.Fatal(err)
	}
	floorAfter, err := os.ReadFile(layout.Vault + ".min-epoch")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(activeBefore, activeAfter) || !bytes.Equal(floorBefore, floorAfter) {
		t.Fatal("retirement rewrote active vault or monotonic epoch floor")
	}
	digest, err := RetirementAuthorizationDigest(signed)
	if err != nil {
		t.Fatal(err)
	}
	record, ok, err := keyring.DescribeRetirement(layout.Vault, layout.MasterKey)
	if err != nil || !ok {
		t.Fatalf("durable retirement marker missing: %+v ok=%v err=%v", record, ok, err)
	}
	if record.AuthorizationSHA256 != digest || record.FromEpoch != signed.Authorization.FromEpoch ||
		record.ToEpoch != signed.Authorization.ToEpoch {
		t.Fatalf("retirement marker does not bind owner authorization: %+v", record)
	}
}

func TestRetireAuthorizedPreviousRejectsExpiredBeforeIntentWithoutMutation(t *testing.T) {
	signed, pin, checkpoint, layout := retirementFixture(t)
	paths := []string{layout.Vault, layout.Vault + ".min-epoch", layout.Vault + ".previous", layout.Vault + ".next"}
	before := make(map[string][]byte, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = raw
	}

	if _, err := RetireAuthorizedPrevious(signed, pin, checkpoint, 1, layout, signed.Authorization.ExpiresAtMS+1); err == nil {
		t.Fatal("expired authorization created retirement intent")
	}
	if _, ok, err := keyring.DescribeRetirement(layout.Vault, layout.MasterKey); err != nil || ok {
		t.Fatalf("expired authorization persisted retirement marker: ok=%v err=%v", ok, err)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before[path], raw) {
			t.Fatalf("expired authorization mutated %s", path)
		}
	}
}

func TestRetireAuthorizedPreviousRejectsSignatureTamperBeforeIntent(t *testing.T) {
	signed, pin, checkpoint, layout := retirementFixture(t)
	missingPQ := signed
	missingPQ.Signatures.MLDSA65 = ""
	if _, err := RetireAuthorizedPrevious(missingPQ, pin, checkpoint, 1, layout, signed.Authorization.IssuedAtMS+1); err == nil {
		t.Fatal("missing ML-DSA-65 signature authorized key erasure")
	}
	if _, ok, err := keyring.DescribeRetirement(layout.Vault, layout.MasterKey); err != nil || ok {
		t.Fatalf("invalid signature persisted retirement marker: ok=%v err=%v", ok, err)
	}

	tampered := signed
	tampered.Authorization.PriorEdKeyID = "ed-tampered"
	if _, err := RetireAuthorizedPrevious(tampered, pin, checkpoint, 1, layout, signed.Authorization.IssuedAtMS+1); err == nil {
		t.Fatal("tampered authorization authorized key erasure")
	}
	for _, path := range []string{layout.Vault + ".previous", layout.Vault + ".next"} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("invalid authorization removed retained material: %s: %v", path, err)
		}
	}
}

func TestRetireAuthorizedPreviousExactRetryAfterCompletionIsIdempotent(t *testing.T) {
	signed, pin, checkpoint, layout := retirementFixture(t)
	now := signed.Authorization.IssuedAtMS + 1
	first, err := RetireAuthorizedPrevious(signed, pin, checkpoint, 1, layout, now)
	if err != nil {
		t.Fatal(err)
	}
	// The durable exact intent makes this a continuation/idempotency path, not a
	// new retirement command. Expiry and a newer independent generation floor do
	// not make already-authorized deletion reversible.
	second, err := RetireAuthorizedPrevious(signed, pin, checkpoint, checkpoint.Checkpoint.Generation+10,
		layout, signed.Authorization.ExpiresAtMS+60_000)
	if err != nil {
		t.Fatalf("exact post-intent retry failed after expiry/newer floor: %v", err)
	}
	if first.NodeID != second.NodeID || first.KeyEpoch != second.KeyEpoch || first.EdKeyID != second.EdKeyID ||
		first.PQKeyID != second.PQKeyID || second.PreviousRetained || second.CandidateRetained {
		t.Fatalf("idempotent retry changed current state: first=%+v second=%+v", first, second)
	}
}
