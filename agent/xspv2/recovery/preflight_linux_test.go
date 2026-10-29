//go:build linux

package recovery

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

func appliedRecoveryLayout(t *testing.T, root string) (state.Layout, keyring.PublicBundle) {
	t.Helper()
	layout, err := state.Prepare(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = keyring.CreateMasterKey(layout.MasterKey); err != nil {
		t.Fatal(err)
	}
	prior, err := keyring.Initialize(layout.Vault, layout.MasterKey, 42, "node_request")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := keyring.PrepareRotation(layout.Vault, layout.MasterKey, prior.KeyEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = keyring.ActivatePreparedRotation(
		layout.Vault, layout.MasterKey, prior.KeyEpoch, candidate.EdKeyID, candidate.PQKeyID,
	); err != nil {
		t.Fatal(err)
	}
	return layout, candidate
}

func TestDurableAgentPreflightRejectsOlderRestoredIdentity(t *testing.T) {
	layout, candidate := appliedRecoveryLayout(t, filepath.Join(t.TempDir(), "current"))
	local := localEvidence(candidate.KeyEpoch, "preflight-request", []byte("verified-current-receipt"), candidate.EdKeyID, candidate.PQKeyID)
	edPrivate, pqPrivate, pin := ownerPair(t)
	checkpoint := checkpointFor(t, 2, strings.Repeat("11", 32), local, pin)
	signed, err := Sign(checkpoint, edPrivate, pqPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if err = VerifyDurableAgentPreflight(signed, pin, layout, local.serverAuthority, 2); err != nil {
		t.Fatalf("current durable Agent identity rejected: %v", err)
	}

	oldRoot := filepath.Join(t.TempDir(), "restored-old")
	oldLayout, err := state.Prepare(oldRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err = keyring.CreateMasterKey(oldLayout.MasterKey); err != nil {
		t.Fatal(err)
	}
	if _, err = keyring.Initialize(oldLayout.Vault, oldLayout.MasterKey, 42, "node_request"); err != nil {
		t.Fatal(err)
	}
	if err = VerifyDurableAgentPreflight(signed, pin, oldLayout, local.serverAuthority, 2); err == nil {
		t.Fatal("older restored Agent identity passed current owner/off-host checkpoint preflight")
	}
	if err = VerifyDurableAgentPreflight(signed, pin, layout, "different.example.invalid", 2); err == nil {
		t.Fatal("wrong authenticated server authority passed checkpoint preflight")
	}
	if err = VerifyDurableAgentPreflight(signed, pin, layout, local.serverAuthority, 3); err == nil {
		t.Fatal("checkpoint below independent off-host generation floor passed preflight")
	}
}
