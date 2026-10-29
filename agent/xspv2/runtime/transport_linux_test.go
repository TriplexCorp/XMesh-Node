//go:build linux

package runtime

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
	cutover "github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/cutover"
	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

func TestEndpointValidationSeparatesConnectAddressAndAuthority(t *testing.T) {
	if err := (Endpoint{Address: "10.0.0.8:8444", ServerName: "node-ingress.xsp.invalid"}).Validate(); err != nil {
		t.Fatalf("valid direct address + authenticated authority rejected: %v", err)
	}
	for _, endpoint := range []Endpoint{
		{Address: "https://node.example:8444", ServerName: "node.example"},
		{Address: "node.example:8444/path", ServerName: "node.example"},
		{Address: "node.example", ServerName: "node.example"},
		{Address: "node.example:8444", ServerName: ""},
		{Address: "node.example:8444", ServerName: "node.example:8444"},
	} {
		if err := endpoint.Validate(); err == nil {
			t.Fatalf("invalid endpoint accepted: %+v", endpoint)
		}
	}
}

func testID(prefix string, raw []byte) string {
	digest := sha256.Sum256(raw)
	return prefix + hex.EncodeToString(digest[:12])
}

func panelSigner(t *testing.T, nodeID uint64) (ed25519.PrivateKey, *mldsa.PrivateKey, Pin) {
	t.Helper()
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqPrivate, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	pqPublic := pqPrivate.PublicKey().Bytes()
	return edPrivate, pqPrivate, Pin{
		IssuerID: "nexus-p0d-test",
		Purpose:  "panel_response",
		NodeID:   nodeID,
		EdKeyID:  testID("ed-", edPublic),
		PQKeyID:  testID("pq-", pqPublic),
		EdPublic: append([]byte(nil), edPublic...),
		PQPublic: append([]byte(nil), pqPublic...),
	}
}

func durablePermitFixture(t *testing.T) (state.Layout, Permit, Pin, keyring.PublicBundle, keyring.PublicBundle) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "agent-state")
	layout, err := state.Prepare(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = keyring.CreateMasterKey(layout.MasterKey); err != nil {
		t.Fatal(err)
	}
	prior, err := keyring.Initialize(layout.Vault, layout.MasterKey, 73, "node_request")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := keyring.PrepareRotation(layout.Vault, layout.MasterKey, prior.KeyEpoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = keyring.ActivatePreparedRotation(layout.Vault, layout.MasterKey, prior.KeyEpoch,
		candidate.EdKeyID, candidate.PQKeyID); err != nil {
		t.Fatal(err)
	}

	candidateDigest, err := cutover.CandidateDigest(cutover.CandidateSource{
		NodeID:       uint64(prior.NodeID),
		FromEpoch:    prior.KeyEpoch,
		ToEpoch:      candidate.KeyEpoch,
		Purpose:      "node_request",
		FromEdKeyID:  prior.EdKeyID,
		FromPQKeyID:  prior.PQKeyID,
		ToEdKeyID:    candidate.EdKeyID,
		ToPQKeyID:    candidate.PQKeyID,
		FromEdPublic: prior.EdPublic,
		FromPQPublic: prior.PQPublic,
		ToEdPublic:   candidate.EdPublic,
		ToPQPublic:   candidate.PQPublic,
	})
	if err != nil {
		t.Fatal(err)
	}

	panelEd, panelPQ, panel := panelSigner(t, uint64(prior.NodeID))
	nowMS := int64(1_800_000_000_000)
	message := cutover.Message{
		Kind:                   "permit",
		IssuerID:               panel.IssuerID,
		SignerEdKeyID:          panel.EdKeyID,
		SignerPQKeyID:          panel.PQKeyID,
		NodeID:                 uint64(prior.NodeID),
		FromEpoch:              prior.KeyEpoch,
		ToEpoch:                candidate.KeyEpoch,
		RequestID:              "p0d-durable-state-test",
		FromEdKeyID:            prior.EdKeyID,
		FromPQKeyID:            prior.PQKeyID,
		ToEdKeyID:              candidate.EdKeyID,
		ToPQKeyID:              candidate.PQKeyID,
		Method:                 "POST",
		Path:                   "/api/v2/node/keys/rotation/permit",
		IssuedAtMS:             nowMS,
		ExpiresAtMS:            nowMS + 60_000,
		PermitNonceHex:         "11111111111111111111111111111111",
		NonceHex:               "11111111111111111111111111111111",
		CandidateSHA256Hex:     candidateDigest,
		PermitSHA256Hex:        "0000000000000000000000000000000000000000000000000000000000000000",
		AppliedStateSHA256Hex:  "0000000000000000000000000000000000000000000000000000000000000000",
	}
	signed, err := cutover.Sign(message, panelEd, panelPQ)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	want := cutover.ExpectedPermit{
		NodeID:                 message.NodeID,
		FromEpoch:              message.FromEpoch,
		ToEpoch:                message.ToEpoch,
		RequestID:              message.RequestID,
		FromEdKeyID:            message.FromEdKeyID,
		FromPQKeyID:            message.FromPQKeyID,
		ToEdKeyID:              message.ToEdKeyID,
		ToPQKeyID:              message.ToPQKeyID,
		CandidateSHA256Hex:     message.CandidateSHA256Hex,
	}
	permit, err := cutover.PersistVerifiedPermit(layout.Journal, raw, panel, want, nowMS+1_000)
	if err != nil {
		t.Fatal(err)
	}
	next := Pin{
		IssuerID: fmt.Sprintf("node-%d", candidate.NodeID),
		Purpose:  candidate.Purpose,
		NodeID:   uint64(candidate.NodeID),
		EdKeyID:  candidate.EdKeyID,
		PQKeyID:  candidate.PQKeyID,
		EdPublic: append([]byte(nil), candidate.EdPublic...),
		PQPublic: append([]byte(nil), candidate.PQPublic...),
	}
	return layout, permit, next, prior, candidate
}

func TestDurableAppliedStateIsRequiredBeforeNetwork(t *testing.T) {
	layout, permit, next, _, candidate := durablePermitFixture(t)
	if err := attestDurableAppliedState(layout, permit, next, candidate.KeyEpoch); err != nil {
		t.Fatalf("valid durable state rejected: %v", err)
	}

	wrongEpoch := candidate.KeyEpoch + 1
	if err := attestDurableAppliedState(layout, permit, next, wrongEpoch); err == nil {
		t.Fatal("wrong minimum epoch accepted")
	}

	wrongNext := next
	wrongNext.EdPublic = append([]byte(nil), next.EdPublic...)
	wrongNext.EdPublic[0] ^= 0xff
	if err := attestDurableAppliedState(layout, permit, wrongNext, candidate.KeyEpoch); err == nil {
		t.Fatal("substituted pending public key accepted")
	}

	if err := os.Remove(layout.Vault + ".previous"); err != nil {
		t.Fatal(err)
	}
	if err := attestDurableAppliedState(layout, permit, next, candidate.KeyEpoch); err == nil {
		t.Fatal("missing retained old-key snapshot accepted")
	}
}
