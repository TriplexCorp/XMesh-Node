//go:build linux

package observability

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

func observedAppliedRotation(t *testing.T) (state.Layout, keyring.PublicBundle, keyring.PublicBundle) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "agent-state")
	layout, err := state.Prepare(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = keyring.CreateMasterKey(layout.MasterKey); err != nil {
		t.Fatal(err)
	}
	prior, err := keyring.Initialize(layout.Vault, layout.MasterKey, 77, "node_request")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := keyring.PrepareRotation(layout.Vault, layout.MasterKey, prior.KeyEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = keyring.ActivatePreparedRotation(layout.Vault, layout.MasterKey,
		prior.KeyEpoch, candidate.EdKeyID, candidate.PQKeyID); err != nil {
		t.Fatal(err)
	}
	return layout, prior, candidate
}

func TestSnapshotExposesOnlyBoundedNonSecretMetadata(t *testing.T) {
	layout, prior, candidate := observedAppliedRotation(t)
	before, err := Snapshot(layout.Root)
	if err != nil {
		t.Fatal(err)
	}
	if before.Schema != Schema || before.NodeID != candidate.NodeID || before.KeyEpoch != candidate.KeyEpoch ||
		before.ActiveKeyIDs.Ed25519 != candidate.EdKeyID || before.ActiveKeyIDs.MLDSA65 != candidate.PQKeyID ||
		!before.Retained.Previous || !before.Retained.Candidate || before.Retirement.Present ||
		!before.ReadOnly || before.ProductionActivated || before.StrictPQEnabled {
		t.Fatalf("unexpected pre-retirement snapshot: %+v", before)
	}

	authorizationDigest := strings.Repeat("a", 64)
	if _, err = keyring.RetireAppliedRotation(layout.Vault, layout.MasterKey, prior.NodeID,
		prior.KeyEpoch, candidate.KeyEpoch, prior.EdKeyID, prior.PQKeyID,
		candidate.EdKeyID, candidate.PQKeyID, authorizationDigest); err != nil {
		t.Fatal(err)
	}
	after, err := Snapshot(layout.Root)
	if err != nil {
		t.Fatal(err)
	}
	if after.Retained.Previous || after.Retained.Candidate || !after.Retirement.Present ||
		after.Retirement.FromEpoch != prior.KeyEpoch || after.Retirement.ToEpoch != candidate.KeyEpoch ||
		after.Retirement.PriorKeyIDs == nil || after.Retirement.ActiveKeyIDs == nil {
		t.Fatalf("unexpected post-retirement snapshot: %+v", after)
	}

	raw, err := json.Marshal(after)
	if err != nil {
		t.Fatal(err)
	}
	output := string(raw)
	for name, forbidden := range map[string]string{
		"authorization digest": authorizationDigest,
		"state root":           layout.Root,
		"vault path":           layout.Vault,
		"master path":          layout.MasterKey,
		"Ed public hex":        hex.EncodeToString(candidate.EdPublic),
		"PQ public hex":        hex.EncodeToString(candidate.PQPublic),
		"Ed public base64":     base64.StdEncoding.EncodeToString(candidate.EdPublic),
		"PQ public base64":     base64.StdEncoding.EncodeToString(candidate.PQPublic),
	} {
		if forbidden != "" && strings.Contains(output, forbidden) {
			t.Fatalf("observability JSON leaked %s", name)
		}
	}
	for _, forbiddenKey := range []string{"authorizationSha256", "edPublic", "pqPublic", "masterKey", "stateRoot", "journal"} {
		if strings.Contains(output, forbiddenKey) {
			t.Fatalf("observability JSON exposed forbidden field %q: %s", forbiddenKey, output)
		}
	}
}

func TestSnapshotFailsClosedOnMissingOrCorruptState(t *testing.T) {
	if _, err := Snapshot(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing Agent state was accepted")
	}
	layout, _, _ := observedAppliedRotation(t)
	if err := osWriteFile(layout.Vault+".min-epoch", []byte("broken")); err != nil {
		t.Fatal(err)
	}
	if _, err := Snapshot(layout.Root); err == nil {
		t.Fatal("corrupt epoch floor was accepted")
	}
}

func osWriteFile(path string, data []byte) error {
	return writePrivateFile(path, data)
}

func writePrivateFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
