//go:build linux

package state

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

type SecuritySnapshot struct {
	NodeID            int64
	KeyEpoch          uint64
	EdKeyID           string
	PQKeyID           string
	EdPublic          []byte
	PQPublic          []byte
	PreviousRetained  bool
	CandidateRetained bool
}

func validateLayout(layout Layout) error {
	if layout.Root == "" || filepath.Clean(layout.Root) != layout.Root || !filepath.IsAbs(layout.Root) {
		return errors.New("invalid Agent state root")
	}
	expected := expectedLayout(layout.Root)
	if layout != expected {
		return errors.New("Agent security-state layout mismatch")
	}
	for _, dir := range []string{layout.Root, layout.Journal, layout.Keys} {
		if err := validatePrivateDir(dir); err != nil {
			return fmt.Errorf("invalid private state directory %s: %w", dir, err)
		}
	}
	for _, path := range []string{layout.Vault, layout.MasterKey} {
		if err := rejectSymlinkComponents(path); err != nil {
			return err
		}
	}
	return nil
}

func retainedPrivateFile(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return false, errors.New("retained security snapshot must be a private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return false, errors.New("retained security snapshot owner mismatch")
	}
	return true, nil
}

func snapshot(pub keyring.PublicBundle, previous, candidate bool) SecuritySnapshot {
	return SecuritySnapshot{
		NodeID:            pub.NodeID,
		KeyEpoch:          pub.KeyEpoch,
		EdKeyID:           pub.EdKeyID,
		PQKeyID:           pub.PQKeyID,
		EdPublic:          append([]byte(nil), pub.EdPublic...),
		PQPublic:          append([]byte(nil), pub.PQPublic...),
		PreviousRetained:  previous,
		CandidateRetained: candidate,
	}
}

// DescribeCurrent reopens the encrypted real-Agent identity using the existing
// keyring implementation. It does not initialize, rotate, retire or repair any
// key material. An old active vault below the persisted epoch floor therefore
// fails closed inside keyring.Description.
func DescribeCurrent(layout Layout) (SecuritySnapshot, error) {
	if err := validateLayout(layout); err != nil {
		return SecuritySnapshot{}, err
	}
	pub, err := keyring.Description(layout.Vault, layout.MasterKey)
	if err != nil {
		return SecuritySnapshot{}, fmt.Errorf("open durable Agent identity: %w", err)
	}
	previous, err := retainedPrivateFile(layout.Vault + ".previous")
	if err != nil {
		return SecuritySnapshot{}, err
	}
	candidate, err := retainedPrivateFile(layout.Vault + ".next")
	if err != nil {
		return SecuritySnapshot{}, err
	}
	return snapshot(pub, previous, candidate), nil
}

// AttestAppliedRotation binds the real-Agent layout to the already-proven
// keyring applied-rotation attestation. That primitive verifies the exact
// persisted epoch floor, active candidate, authenticated .next snapshot and
// retained authenticated .previous identity under the wrapping-key lock.
// Nothing here creates a second epoch/replay state machine.
func AttestAppliedRotation(layout Layout, nodeID int64, fromEpoch, toEpoch uint64,
	priorEdID, priorPQID, nextEdID, nextPQID string,
) (SecuritySnapshot, error) {
	if err := validateLayout(layout); err != nil {
		return SecuritySnapshot{}, err
	}
	pub, err := keyring.AttestAppliedRotation(layout.Vault, layout.MasterKey, nodeID,
		fromEpoch, toEpoch, priorEdID, priorPQID, nextEdID, nextPQID)
	if err != nil {
		return SecuritySnapshot{}, fmt.Errorf("durable applied rotation not attested: %w", err)
	}
	previous, err := retainedPrivateFile(layout.Vault + ".previous")
	if err != nil {
		return SecuritySnapshot{}, err
	}
	candidate, err := retainedPrivateFile(layout.Vault + ".next")
	if err != nil {
		return SecuritySnapshot{}, err
	}
	if !previous || !candidate {
		return SecuritySnapshot{}, errors.New("old/new authenticated key snapshots must be retained")
	}
	return snapshot(pub, previous, candidate), nil
}

func (s SecuritySnapshot) Matches(nodeID uint64, epoch uint64, purpose, edID, pqID string,
	edPublic, pqPublic []byte,
) bool {
	return s.NodeID > 0 && uint64(s.NodeID) == nodeID && s.KeyEpoch == epoch &&
		purpose == "node_request" && s.EdKeyID == edID && s.PQKeyID == pqID &&
		bytes.Equal(s.EdPublic, edPublic) && bytes.Equal(s.PQPublic, pqPublic)
}
