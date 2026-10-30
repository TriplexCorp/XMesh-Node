package keyring

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func appliedRetirementFixture(t *testing.T) (string, string, PublicBundle, PublicBundle, []byte, []byte) {
	t.Helper()
	vault, master, previous := rotationFixture(t)
	candidate, err := PrepareRotation(vault, master, previous.KeyEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ActivatePreparedRotation(vault, master, previous.KeyEpoch, candidate.EdKeyID, candidate.PQKeyID); err != nil {
		t.Fatal(err)
	}
	previousRaw, err := os.ReadFile(previousPath(vault))
	if err != nil {
		t.Fatal(err)
	}
	candidateRaw, err := os.ReadFile(stagedPath(vault))
	if err != nil {
		t.Fatal(err)
	}
	return vault, master, previous, candidate, previousRaw, candidateRaw
}

func retireExact(t *testing.T, vault, master string, previous, candidate PublicBundle, digest string) PublicBundle {
	t.Helper()
	active, err := RetireAppliedRotation(vault, master, previous.NodeID, previous.KeyEpoch, candidate.KeyEpoch,
		previous.EdKeyID, previous.PQKeyID, candidate.EdKeyID, candidate.PQKeyID, digest)
	if err != nil {
		t.Fatal(err)
	}
	return active
}

func TestRetireAppliedRotationPersistsIntentBeforeErasureAndIsIdempotent(t *testing.T) {
	vault, master, previous, candidate, _, _ := appliedRetirementFixture(t)
	activeBefore, err := os.ReadFile(vault)
	if err != nil {
		t.Fatal(err)
	}
	floorBefore, err := os.ReadFile(floorPath(vault))
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("ab", 32)
	active := retireExact(t, vault, master, previous, candidate, digest)
	if active.KeyEpoch != candidate.KeyEpoch || active.EdKeyID != candidate.EdKeyID || active.PQKeyID != candidate.PQKeyID {
		t.Fatal("retirement changed active identity")
	}
	for _, path := range []string{previousPath(vault), stagedPath(vault)} {
		if _, err = os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("retired snapshot still exists: %s err=%v", path, err)
		}
	}
	record, ok, err := DescribeRetirement(vault, master)
	if err != nil || !ok {
		t.Fatalf("authenticated retirement marker missing: %+v ok=%v err=%v", record, ok, err)
	}
	if record.FromEpoch != previous.KeyEpoch || record.ToEpoch != candidate.KeyEpoch ||
		record.PriorEdKeyID != previous.EdKeyID || record.ActiveEdKeyID != candidate.EdKeyID ||
		record.AuthorizationSHA256 != digest {
		t.Fatalf("retirement marker mismatch: %+v", record)
	}
	activeAfter, _ := os.ReadFile(vault)
	floorAfter, _ := os.ReadFile(floorPath(vault))
	if !bytes.Equal(activeBefore, activeAfter) || !bytes.Equal(floorBefore, floorAfter) {
		t.Fatal("retirement rewrote active vault or epoch floor")
	}

	// Exact retry after both files are gone is a no-op success.
	again := retireExact(t, vault, master, previous, candidate, digest)
	if again.KeyEpoch != candidate.KeyEpoch || again.EdKeyID != candidate.EdKeyID {
		t.Fatal("idempotent retirement retry changed active identity")
	}
}

func TestRetirementMarkerRejectsReintroducedOldMaterial(t *testing.T) {
	vault, master, previous, candidate, previousRaw, candidateRaw := appliedRetirementFixture(t)
	digest := strings.Repeat("cd", 32)
	retireExact(t, vault, master, previous, candidate, digest)

	if err := atomicFile(previousPath(vault), previousRaw); err != nil {
		t.Fatal(err)
	}
	if err := atomicFile(stagedPath(vault), candidateRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := DescribeRetainedRotation(vault, master); err == nil {
		t.Fatal("reintroduced retired snapshots were accepted as retained rotation evidence")
	}
	if _, err := AttestAppliedRotation(vault, master, previous.NodeID, previous.KeyEpoch, candidate.KeyEpoch,
		previous.EdKeyID, previous.PQKeyID, candidate.EdKeyID, candidate.PQKeyID); err == nil {
		t.Fatal("reintroduced retired snapshots were accepted by applied attestation")
	}
	if _, err := RecoverRotation(vault, master); err == nil {
		t.Fatal("reintroduced retired snapshots were accepted by rotation recovery")
	}

	// The exact retirement operation may safely clean the reintroduced files
	// again because the authenticated intent is unchanged.
	retireExact(t, vault, master, previous, candidate, digest)
}

func TestRetirementMarkerChainsMonotonicallyAcrossNextRotation(t *testing.T) {
	vault, master, previous, candidate, _, _ := appliedRetirementFixture(t)
	firstDigest := strings.Repeat("01", 32)
	retireExact(t, vault, master, previous, candidate, firstDigest)

	next, err := PrepareRotation(vault, master, candidate.KeyEpoch)
	if err != nil {
		t.Fatalf("next rotation blocked by completed retirement floor: %v", err)
	}
	if _, err = ActivatePreparedRotation(vault, master, candidate.KeyEpoch, next.EdKeyID, next.PQKeyID); err != nil {
		t.Fatal(err)
	}
	secondDigest := strings.Repeat("02", 32)
	retireExact(t, vault, master, candidate, next, secondDigest)
	record, ok, err := DescribeRetirement(vault, master)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if record.FromEpoch != candidate.KeyEpoch || record.ToEpoch != next.KeyEpoch || record.AuthorizationSHA256 != secondDigest {
		t.Fatalf("retirement marker did not advance monotonically: %+v", record)
	}

	if _, err = RetireAppliedRotation(vault, master, previous.NodeID, previous.KeyEpoch, candidate.KeyEpoch,
		previous.EdKeyID, previous.PQKeyID, candidate.EdKeyID, candidate.PQKeyID, firstDigest); err == nil {
		t.Fatal("older retirement transition was accepted after marker advanced")
	}
}

func TestRetirementMarkerTamperFailsClosed(t *testing.T) {
	vault, master, previous, candidate, _, _ := appliedRetirementFixture(t)
	retireExact(t, vault, master, previous, candidate, strings.Repeat("ef", 32))
	raw, err := os.ReadFile(retirementPath(vault))
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	if err = atomicFile(retirementPath(vault), raw); err != nil {
		t.Fatal(err)
	}
	if _, _, err = DescribeRetirement(vault, master); err == nil {
		t.Fatal("tampered retirement marker accepted")
	}
	if _, err = PrepareRotation(vault, master, candidate.KeyEpoch); err == nil {
		t.Fatal("new rotation ignored tampered retirement marker")
	}
}
