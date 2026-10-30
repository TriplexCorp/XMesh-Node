package keyring

import (
	"bytes"
	"os"
	"testing"
)

func TestDescribeRetainedRotationRequiresExactAppliedCutover(t *testing.T) {
	vault, master, previous := rotationFixture(t)
	candidate, err := PrepareRotation(vault, master, previous.KeyEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DescribeRetainedRotation(vault, master); err == nil {
		t.Fatal("prepared-only rotation was described as applied")
	}
	if _, err = ActivatePreparedRotation(vault, master, previous.KeyEpoch, candidate.EdKeyID, candidate.PQKeyID); err != nil {
		t.Fatal(err)
	}

	activeBefore, err := os.ReadFile(vault)
	if err != nil {
		t.Fatal(err)
	}
	previousBefore, err := os.ReadFile(previousPath(vault))
	if err != nil {
		t.Fatal(err)
	}
	candidateBefore, err := os.ReadFile(stagedPath(vault))
	if err != nil {
		t.Fatal(err)
	}

	retained, err := DescribeRetainedRotation(vault, master)
	if err != nil {
		t.Fatal(err)
	}
	if retained.Previous.KeyEpoch != previous.KeyEpoch || retained.Active.KeyEpoch != candidate.KeyEpoch ||
		retained.Candidate.KeyEpoch != candidate.KeyEpoch || retained.Previous.EdKeyID != previous.EdKeyID ||
		retained.Previous.PQKeyID != previous.PQKeyID || retained.Active.EdKeyID != candidate.EdKeyID ||
		retained.Active.PQKeyID != candidate.PQKeyID {
		t.Fatal("retained rotation evidence does not match applied identities")
	}

	activeAfter, _ := os.ReadFile(vault)
	previousAfter, _ := os.ReadFile(previousPath(vault))
	candidateAfter, _ := os.ReadFile(stagedPath(vault))
	if !bytes.Equal(activeBefore, activeAfter) || !bytes.Equal(previousBefore, previousAfter) ||
		!bytes.Equal(candidateBefore, candidateAfter) {
		t.Fatal("retained rotation description mutated private key state")
	}
}

func TestDescribeRetainedRotationRejectsPartialOrSubstitutedEvidence(t *testing.T) {
	vault, master, previous := rotationFixture(t)
	candidate, err := PrepareRotation(vault, master, previous.KeyEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ActivatePreparedRotation(vault, master, previous.KeyEpoch, candidate.EdKeyID, candidate.PQKeyID); err != nil {
		t.Fatal(err)
	}

	if err = os.Remove(previousPath(vault)); err != nil {
		t.Fatal(err)
	}
	if _, err = DescribeRetainedRotation(vault, master); err == nil {
		t.Fatal("missing previous identity accepted")
	}

	vault, master, previous = rotationFixture(t)
	candidate, err = PrepareRotation(vault, master, previous.KeyEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ActivatePreparedRotation(vault, master, previous.KeyEpoch, candidate.EdKeyID, candidate.PQKeyID); err != nil {
		t.Fatal(err)
	}
	otherVault, otherMaster, _ := rotationFixture(t)
	otherCandidate, err := PrepareRotation(otherVault, otherMaster, 1)
	if err != nil {
		t.Fatal(err)
	}
	otherRaw, err := os.ReadFile(stagedPath(otherVault))
	if err != nil {
		t.Fatal(err)
	}
	if otherCandidate.KeyEpoch != candidate.KeyEpoch {
		t.Fatal("fixture epoch mismatch")
	}
	if err = atomicFile(stagedPath(vault), otherRaw); err != nil {
		t.Fatal(err)
	}
	if _, err = DescribeRetainedRotation(vault, master); err == nil {
		t.Fatal("substituted retained candidate accepted")
	}
}
