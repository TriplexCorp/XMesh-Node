//go:build linux

package runtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
	cutover "github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/cutover"
	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

type rollbackFixture struct {
	layout       state.Layout
	snapshotRoot string
	permitRaw    []byte
	panel        Pin
	want         cutover.ExpectedPermit
	permit       Permit
	next         Pin
	prior        keyring.PublicBundle
	candidate    keyring.PublicBundle
	nowMS        int64
}

func copyPrivateTree(t *testing.T, src, dst string) {
	t.Helper()
	if err := filepath.WalkDir(src, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("security-state snapshot unexpectedly contains a symlink")
		}
		if entry.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return errors.New("security-state snapshot unexpectedly contains a non-regular file")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, info.Mode().Perm())
	}); err != nil {
		t.Fatal(err)
	}
}

func newRollbackFixture(t *testing.T) rollbackFixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "agent-state")
	layout, err := state.Prepare(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = keyring.CreateMasterKey(layout.MasterKey); err != nil {
		t.Fatal(err)
	}
	prior, err := keyring.Initialize(layout.Vault, layout.MasterKey, 91, "node_request")
	if err != nil {
		t.Fatal(err)
	}

	// Capture the complete local Agent state before the authorized rotation.
	// Restoring this tree later models a one-sided VM/filesystem snapshot rollback:
	// Nexus remains current while every local key/journal/floor file goes backwards.
	snapshotRoot := filepath.Join(t.TempDir(), "pre-rotation-snapshot")
	copyPrivateTree(t, layout.Root, snapshotRoot)

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
	nowMS := int64(1_810_000_000_000)
	message := cutover.Message{
		Kind:                  "permit",
		IssuerID:              panel.IssuerID,
		SignerEdKeyID:         panel.EdKeyID,
		SignerPQKeyID:         panel.PQKeyID,
		NodeID:                uint64(prior.NodeID),
		FromEpoch:             prior.KeyEpoch,
		ToEpoch:               candidate.KeyEpoch,
		RequestID:             "p0e-snapshot-rollback-test",
		FromEdKeyID:           prior.EdKeyID,
		FromPQKeyID:           prior.PQKeyID,
		ToEdKeyID:             candidate.EdKeyID,
		ToPQKeyID:             candidate.PQKeyID,
		Method:                "POST",
		Path:                  "/api/v2/node/keys/rotation/permit",
		IssuedAtMS:            nowMS,
		ExpiresAtMS:           nowMS + 60_000,
		PermitNonceHex:        "22222222222222222222222222222222",
		NonceHex:              "22222222222222222222222222222222",
		CandidateSHA256Hex:    candidateDigest,
		PermitSHA256Hex:       "0000000000000000000000000000000000000000000000000000000000000000",
		AppliedStateSHA256Hex: "0000000000000000000000000000000000000000000000000000000000000000",
	}
	signed, err := cutover.Sign(message, panelEd, panelPQ)
	if err != nil {
		t.Fatal(err)
	}
	permitRaw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	want := cutover.ExpectedPermit{
		NodeID:             message.NodeID,
		FromEpoch:          message.FromEpoch,
		ToEpoch:            message.ToEpoch,
		RequestID:          message.RequestID,
		FromEdKeyID:        message.FromEdKeyID,
		FromPQKeyID:        message.FromPQKeyID,
		ToEdKeyID:          message.ToEdKeyID,
		ToPQKeyID:          message.ToPQKeyID,
		CandidateSHA256Hex: message.CandidateSHA256Hex,
	}
	permit, err := cutover.PersistVerifiedPermit(layout.Journal, permitRaw, panel, want, nowMS+1_000)
	if err != nil {
		t.Fatal(err)
	}
	next := Pin{
		IssuerID: "node-rollback-test",
		Purpose:  candidate.Purpose,
		NodeID:   uint64(candidate.NodeID),
		EdKeyID:  candidate.EdKeyID,
		PQKeyID:  candidate.PQKeyID,
		EdPublic: append([]byte(nil), candidate.EdPublic...),
		PQPublic: append([]byte(nil), candidate.PQPublic...),
	}
	if err := attestDurableAppliedState(layout, permit, next, candidate.KeyEpoch); err != nil {
		t.Fatalf("current applied state rejected before rollback: %v", err)
	}

	return rollbackFixture{
		layout:       layout,
		snapshotRoot: snapshotRoot,
		permitRaw:    permitRaw,
		panel:        panel,
		want:         want,
		permit:       permit,
		next:         next,
		prior:        prior,
		candidate:    candidate,
		nowMS:        nowMS,
	}
}

func restoreOneSidedSnapshot(t *testing.T, fixture rollbackFixture) state.Layout {
	t.Helper()
	if err := os.RemoveAll(fixture.layout.Root); err != nil {
		t.Fatal(err)
	}
	copyPrivateTree(t, fixture.snapshotRoot, fixture.layout.Root)
	layout, err := state.Prepare(fixture.layout.Root)
	if err != nil {
		t.Fatal(err)
	}
	if layout != fixture.layout {
		t.Fatalf("restored snapshot changed canonical layout: before=%+v after=%+v", fixture.layout, layout)
	}
	return layout
}

func assertNoTCPConnection(t *testing.T, listener net.Listener) {
	t.Helper()
	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		t.Fatal("expected TCP listener")
	}
	if err := tcpListener.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := tcpListener.Accept()
	if err == nil {
		_ = conn.Close()
		t.Fatal("rolled-back Agent reached the network before durable-state rejection")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("unexpected listener result while proving no network I/O: %v", err)
	}
}

func TestOneSidedAgentSnapshotRollbackRequiresCurrentRemoteWitness(t *testing.T) {
	fixture := newRollbackFixture(t)
	layout := restoreOneSidedSnapshot(t, fixture)

	// A complete local snapshot can be self-consistent: vault and epoch floor
	// both moved backwards together. This is why a second, non-rolled-back trust
	// domain is required; local files alone cannot prove that time moved backward.
	rolledBack, err := state.DescribeCurrent(layout)
	if err != nil {
		t.Fatalf("pre-rotation snapshot should be internally self-consistent: %v", err)
	}
	if rolledBack.KeyEpoch != fixture.prior.KeyEpoch || rolledBack.EdKeyID != fixture.prior.EdKeyID ||
		rolledBack.PQKeyID != fixture.prior.PQKeyID {
		t.Fatalf("snapshot did not restore the exact prior identity: %+v", rolledBack)
	}
	if rolledBack.PreviousRetained || rolledBack.CandidateRetained {
		t.Fatal("pre-rotation snapshot unexpectedly contains post-rotation key evidence")
	}

	// Nexus did NOT roll back. Re-delivery of its current dual-signed permit is
	// the external witness for epoch 2. Persisting that permit is allowed, but the
	// rolled-back local applied state must fail attestation before any network I/O.
	currentPermit, err := cutover.PersistVerifiedPermit(layout.Journal, fixture.permitRaw,
		fixture.panel, fixture.want, fixture.nowMS+1_000)
	if err != nil {
		t.Fatalf("current signed permit could not be re-delivered after local snapshot rollback: %v", err)
	}
	if err = attestDurableAppliedState(layout, currentPermit, fixture.next, fixture.candidate.KeyEpoch); err == nil {
		t.Fatal("one-sided local snapshot rollback satisfied current remote epoch attestation")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	endpoint := Endpoint{Address: listener.Addr().String(), ServerName: "rollback-proof.invalid"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = Exchange(ctx, endpoint, (*x509.CertPool)(nil), tls.Certificate{}, layout,
		fixture.panel, currentPermit, fixture.next, fixture.candidate.KeyEpoch, fixture.nowMS+2_000); err == nil {
		t.Fatal("Exchange accepted a one-sided rolled-back Agent snapshot")
	}
	assertNoTCPConnection(t, listener)
}

func TestOneSidedAgentSnapshotRollbackBlocksHistoricalRecoveryBeforeNetwork(t *testing.T) {
	fixture := newRollbackFixture(t)
	layout := restoreOneSidedSnapshot(t, fixture)
	currentPermit, err := cutover.PersistVerifiedPermit(layout.Journal, fixture.permitRaw,
		fixture.panel, fixture.want, fixture.nowMS+1_000)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	endpoint := Endpoint{Address: listener.Addr().String(), ServerName: "rollback-proof.invalid"}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err = Recover(ctx, endpoint, (*x509.CertPool)(nil), tls.Certificate{}, layout,
		fixture.panel, currentPermit, fixture.next, fixture.candidate.KeyEpoch, fixture.nowMS+2_000); err == nil {
		t.Fatal("Recover accepted a one-sided rolled-back Agent snapshot")
	}
	assertNoTCPConnection(t, listener)
}
