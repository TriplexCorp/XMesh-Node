package keyring

import (
    "bytes"
    "os"
    "path/filepath"
    "testing"
)

func rotationFixture(t *testing.T) (string, string, PublicBundle) {
    t.Helper()
    dir := t.TempDir()
    if err := os.Chmod(dir, 0700); err != nil { t.Fatal(err) }
    master := filepath.Join(dir, "wrapping.key")
    vault := filepath.Join(dir, "private.json")
    if err := CreateMasterKey(master); err != nil { t.Fatal(err) }
    original, err := Initialize(vault, master, 42, "node_request")
    if err != nil { t.Fatal(err) }
    return vault, master, original
}

func TestTwoPhaseRotationPreservesActiveIdentityUntilExplicitCutover(t *testing.T) {
    vault, master, old := rotationFixture(t)
    before, err := os.ReadFile(vault)
    if err != nil { t.Fatal(err) }
    candidate, err := PrepareRotation(vault, master, 1)
    if err != nil { t.Fatal(err) }
    if candidate.KeyEpoch != 2 || candidate.EdKeyID == old.EdKeyID ||
        candidate.PQKeyID == old.PQKeyID {
        t.Fatal("candidate must be fresh, epoch-incremented keys")
    }
    active, err := Description(vault, master)
    if err != nil || active.EdKeyID != old.EdKeyID || active.KeyEpoch != 1 {
        t.Fatal("preparation changed active key or floor", err)
    }
    after, err := os.ReadFile(vault)
    if err != nil || !bytes.Equal(before, after) {
        t.Fatal("preparation modified active encrypted vault")
    }
    if _, err := PrepareRotation(vault, master, 1); err == nil {
        t.Fatal("second pending candidate replaced the first")
    }
    if _, err := ActivatePreparedRotation(vault, master, 1, "unapproved", candidate.PQKeyID); err == nil {
        t.Fatal("unapproved key fingerprint activated")
    }
    if _, err := ActivatePreparedRotation(vault, master, 2, candidate.EdKeyID, candidate.PQKeyID); err == nil {
        t.Fatal("wrong previous epoch activated")
    }
    active, err = Description(vault, master)
    if err != nil || active.KeyEpoch != 1 { t.Fatal("rejection changed active key") }
    next, err := ActivatePreparedRotation(vault, master, 1, candidate.EdKeyID, candidate.PQKeyID)
    if err != nil || next.KeyEpoch != 2 { t.Fatal("cutover failed", err) }
    active, err = Description(vault, master)
    if err != nil || active.EdKeyID != next.EdKeyID { t.Fatal("cutover not active", err) }
    archived, err := os.ReadFile(previousPath(vault))
    if err != nil || !bytes.Equal(before, archived) { t.Fatal("previous encrypted identity not retained") }
    if err := AbortPreparedRotation(vault, master, 1); err == nil {
        t.Fatal("aborted after activation")
    }
    if _, err := PrepareRotation(vault, master, 2); err == nil {
        t.Fatal("replaced keys before old epoch retired")
    }
    if err := os.WriteFile(vault, before, 0600); err != nil { t.Fatal(err) }
    if _, _, err := Open(vault, master); err == nil {
        t.Fatal("persisted epoch floor accepted old identity")
    }
    restored, err := RecoverRotation(vault, master)
    if err != nil || restored.KeyEpoch != 2 { t.Fatal("recovery did not safely move forward", err) }
}

func TestAbortPreparedRotationLeavesOriginalIdentityIntact(t *testing.T) {
    vault, master, original := rotationFixture(t)
    if _, err := PrepareRotation(vault, master, 1); err != nil { t.Fatal(err) }
    if err := AbortPreparedRotation(vault, master, 2); err == nil {
        t.Fatal("aborted candidate from an incorrect epoch")
    }
    if err := AbortPreparedRotation(vault, master, 1); err != nil { t.Fatal(err) }
    if _, err := os.Lstat(stagedPath(vault)); !os.IsNotExist(err) { t.Fatal("unactivated candidate still exists") }
    current, err := Description(vault, master)
    if err != nil || current.KeyEpoch != original.KeyEpoch ||
        current.EdKeyID != original.EdKeyID {
        t.Fatal("abort modified old active identity", err)
    }
    if _, err := PrepareRotation(vault, master, 1); err != nil {
        t.Fatal("abort blocked future preparation", err)
    }
    if _, err := RecoverRotation(vault, master); err == nil {
        t.Fatal("recovery accepted a rotation that was never activated")
    }
}

func TestRotationRecoveryAfterCrashBetweenFloorAndActiveSwap(t *testing.T) {
    vault, master, old := rotationFixture(t)
    candidate, err := PrepareRotation(vault, master, 1)
    if err != nil { t.Fatal(err) }
    activeRaw, err := os.ReadFile(vault)
    if err != nil { t.Fatal(err) }
    if err = atomicFile(previousPath(vault), activeRaw); err != nil { t.Fatal(err) }
    // Simulate a crash just after the first durable cutover operation.
    if err = updateFloor(vault, candidate.KeyEpoch); err != nil { t.Fatal(err) }
    if _, _, err = Open(vault, master); err == nil {
        t.Fatal("crashed cutover should fail closed before explicit recovery")
    }
    recovered, err := RecoverRotation(vault, master)
    if err != nil || recovered.KeyEpoch != 2 || recovered.NodeID != old.NodeID {
        t.Fatal("failed crash forward recovery", err)
    }
    current, err := Description(vault, master)
    if err != nil || current.KeyEpoch != 2 { t.Fatal("recovered vault not active", err) }
    again, err := RecoverRotation(vault, master)
    if err != nil || again.KeyEpoch != 2 { t.Fatal("recovery not idempotent", err) }
}

func TestRotationRecoveryRejectsTamperAndPreCutover(t *testing.T) {
    vault, master, _ := rotationFixture(t)
    candidate, err := PrepareRotation(vault, master, 1)
    if err != nil { t.Fatal(err) }
    raw, err := os.ReadFile(vault)
    if err != nil { t.Fatal(err) }
    if err = atomicFile(previousPath(vault), raw); err != nil { t.Fatal(err) }
    // A crash BEFORE floor advance must preserve old active keys; a recover
    // operation cannot silently complete that unauthorized cutover.
    if _, err = RecoverRotation(vault, master); err == nil {
        t.Fatal("recovery advanced keys before persisted authorization floor")
    }
    if err = updateFloor(vault, candidate.KeyEpoch); err != nil { t.Fatal(err) }
    if err = os.WriteFile(stagedPath(vault), []byte("tampered ciphertext"), 0600); err != nil {
        t.Fatal(err)
    }
    if _, err = RecoverRotation(vault, master); err == nil {
        t.Fatal("accepted tampered candidate vault")
    }
}
