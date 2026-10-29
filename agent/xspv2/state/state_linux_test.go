//go:build linux

package state

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

func TestPrepareCreatesPrivateCanonicalLayout(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent-state")
	layout, err := Prepare(root)
	if err != nil {
		t.Fatal(err)
	}
	if layout != expectedLayout(root) {
		t.Fatalf("unexpected layout: %+v", layout)
	}
	for _, path := range []string{layout.Root, layout.Journal, layout.Keys} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode = %04o", path, info.Mode().Perm())
		}
	}
	for _, path := range []string{layout.Vault, layout.MasterKey} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("Prepare must not create enrollment identity %s: %v", path, err)
		}
	}
}

func TestPrepareRejectsRelativeAndSymlinkRoots(t *testing.T) {
	if _, err := Prepare("relative/state"); err == nil {
		t.Fatal("relative state root accepted")
	}
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(filepath.Join(link, "state")); err == nil {
		t.Fatal("symlinked state path accepted")
	}
}

func TestPrepareRepairsPrivateModeButNotOwnership(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent-state")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	layout, err := Prepare(root)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(layout.Root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("state root remained too broad: %04o", info.Mode().Perm())
	}
}

func appliedRotation(t *testing.T) (Layout, keyring.PublicBundle, keyring.PublicBundle) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "agent-state")
	layout, err := Prepare(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = keyring.CreateMasterKey(layout.MasterKey); err != nil {
		t.Fatal(err)
	}
	prior, err := keyring.Initialize(layout.Vault, layout.MasterKey, 41, "node_request")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := keyring.PrepareRotation(layout.Vault, layout.MasterKey, prior.KeyEpoch)
	if err != nil {
		t.Fatal(err)
	}
	active, err := keyring.ActivatePreparedRotation(layout.Vault, layout.MasterKey,
		prior.KeyEpoch, candidate.EdKeyID, candidate.PQKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if active.KeyEpoch != candidate.KeyEpoch || active.EdKeyID != candidate.EdKeyID || active.PQKeyID != candidate.PQKeyID {
		t.Fatal("activated identity differs from prepared candidate")
	}
	return layout, prior, candidate
}

func attestApplied(t *testing.T, layout Layout, prior, candidate keyring.PublicBundle) SecuritySnapshot {
	t.Helper()
	snapshot, err := AttestAppliedRotation(layout, prior.NodeID, prior.KeyEpoch, candidate.KeyEpoch,
		prior.EdKeyID, prior.PQKeyID, candidate.EdKeyID, candidate.PQKeyID)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.KeyEpoch != candidate.KeyEpoch || snapshot.EdKeyID != candidate.EdKeyID ||
		snapshot.PQKeyID != candidate.PQKeyID || !snapshot.PreviousRetained || !snapshot.CandidateRetained {
		t.Fatalf("unexpected durable snapshot: %+v", snapshot)
	}
	return snapshot
}

func TestAppliedSecurityStateSurvivesAgentRestartWithoutRegeneration(t *testing.T) {
	layout, prior, candidate := appliedRotation(t)
	before := attestApplied(t, layout, prior, candidate)

	paths := []string{
		layout.MasterKey,
		layout.Vault,
		layout.Vault + ".min-epoch",
		layout.Vault + ".previous",
		layout.Vault + ".next",
	}
	contents := make(map[string][]byte, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		contents[path] = raw
	}

	restarted, err := Prepare(layout.Root)
	if err != nil {
		t.Fatal(err)
	}
	if restarted != layout {
		t.Fatalf("restart changed layout: before=%+v after=%+v", layout, restarted)
	}
	after := attestApplied(t, restarted, prior, candidate)
	if !after.Matches(uint64(candidate.NodeID), candidate.KeyEpoch, candidate.Purpose,
		candidate.EdKeyID, candidate.PQKeyID, candidate.EdPublic, candidate.PQPublic) {
		t.Fatal("restart lost exact active security identity")
	}
	if before.KeyEpoch != after.KeyEpoch || before.EdKeyID != after.EdKeyID || before.PQKeyID != after.PQKeyID {
		t.Fatal("restart changed monotonic security identity")
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw, contents[path]) {
			t.Fatalf("Prepare rewrote durable security material: %s", path)
		}
	}
}

func TestOldVaultRestoreBelowEpochFloorFailsClosed(t *testing.T) {
	layout, prior, candidate := appliedRotation(t)
	_ = attestApplied(t, layout, prior, candidate)
	oldRaw, err := os.ReadFile(layout.Vault + ".previous")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(layout.Vault, oldRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = DescribeCurrent(layout); err == nil {
		t.Fatal("old active vault below persisted epoch floor was accepted")
	}
	if _, err = AttestAppliedRotation(layout, prior.NodeID, prior.KeyEpoch, candidate.KeyEpoch,
		prior.EdKeyID, prior.PQKeyID, candidate.EdKeyID, candidate.PQKeyID); err == nil {
		t.Fatal("restored old vault passed applied-rotation attestation")
	}
}

func TestLoweredCorruptOrMissingDurableEvidenceFailsClosed(t *testing.T) {
	t.Run("lowered-floor", func(t *testing.T) {
		layout, prior, candidate := appliedRotation(t)
		if err := os.WriteFile(layout.Vault+".min-epoch", []byte("1"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := AttestAppliedRotation(layout, prior.NodeID, prior.KeyEpoch, candidate.KeyEpoch,
			prior.EdKeyID, prior.PQKeyID, candidate.EdKeyID, candidate.PQKeyID); err == nil {
			t.Fatal("lowered epoch floor accepted")
		}
	})

	t.Run("corrupt-floor", func(t *testing.T) {
		layout, prior, candidate := appliedRotation(t)
		if err := os.WriteFile(layout.Vault+".min-epoch", []byte("broken"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := AttestAppliedRotation(layout, prior.NodeID, prior.KeyEpoch, candidate.KeyEpoch,
			prior.EdKeyID, prior.PQKeyID, candidate.EdKeyID, candidate.PQKeyID); err == nil {
			t.Fatal("corrupt epoch floor accepted")
		}
	})

	t.Run("missing-old-key", func(t *testing.T) {
		layout, prior, candidate := appliedRotation(t)
		if err := os.Remove(layout.Vault + ".previous"); err != nil {
			t.Fatal(err)
		}
		if _, err := AttestAppliedRotation(layout, prior.NodeID, prior.KeyEpoch, candidate.KeyEpoch,
			prior.EdKeyID, prior.PQKeyID, candidate.EdKeyID, candidate.PQKeyID); err == nil {
			t.Fatal("missing retained old key identity accepted")
		}
	})
}
