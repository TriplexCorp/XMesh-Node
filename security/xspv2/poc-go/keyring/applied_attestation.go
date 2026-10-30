package keyring

// Staging-only, read-only local applied-vault attestation. It is NOT an
// independent hardware-protected anti-rollback mechanism or Nexus cutover
// authorization. The caller must verify a pinned Nexus permit before using
// this evidence to store an ACK.
import (
	"bytes"
	"errors"
)

// AttestAppliedRotation checks whether the encrypted active Node keypair is
// already the exact prepared candidate, that the minimum epoch floor was
// persistently advanced, and that an old encrypted snapshot was retained.
// No file is modified and no key is activated here.
//
// A filesystem restore that replaces master, active vault, snapshots AND floor
// could fool this software-only attestation. Production needs a protected
// monotonic counter / remote consistency check before accepting cutover.
func attestAppliedRotationLocked(vault string, key []byte, nodeID int64,
	fromEpoch, toEpoch uint64, priorEdID, priorPQID, nextEdID, nextPQID string,
) (PublicBundle, error) {
	var empty PublicBundle
	if nodeID <= 0 || fromEpoch == 0 || fromEpoch == ^uint64(0) ||
		toEpoch != fromEpoch+1 || priorEdID == "" || priorPQID == "" || nextEdID == "" || nextPQID == "" {
		return empty, errors.New("invalid expected cutover identity")
	}
	if err := secureDir(vault); err != nil {
		return empty, err
	}
	floor, err := readFloor(vault)
	if err != nil {
		return empty, err
	}
	if floor != toEpoch {
		return empty, errors.New("applied epoch floor missing or mismatched")
	}
	currentRaw, err := secureFile(vault)
	if err != nil {
		return empty, err
	}
	nextRaw, err := secureFile(stagedPath(vault))
	if err != nil {
		return empty, err
	}
	previousRaw, err := secureFile(previousPath(vault))
	if err != nil {
		return empty, err
	}
	if !bytes.Equal(currentRaw, nextRaw) || bytes.Equal(previousRaw, currentRaw) {
		return empty, errors.New("active encrypted vault does not match prepared candidate")
	}
	_, active, err := openWithMaster(vault, key)
	if err != nil {
		return empty, err
	}
	if err = enforceRetirementFloorLocked(vault, key, active); err != nil {
		return empty, err
	}
	// Previous and pending snapshots are authenticated using the encrypted
	// wrapping key, not accepted merely because two 0600 files happen to exist.
	// The auxiliary paths do not have a floor file; this does not lower the
	// active vault's independently verified floor.
	_, prior, err := openWithMaster(previousPath(vault), key)
	if err != nil {
		return empty, err
	}
	_, candidate, err := openWithMaster(stagedPath(vault), key)
	if err != nil {
		return empty, err
	}
	if err = validateRetirementRecordForPair(vault, key, prior, candidate); err != nil {
		return empty, err
	}
	if prior.NodeID != nodeID || prior.Purpose != "node_request" ||
		prior.KeyEpoch != fromEpoch || prior.EdKeyID != priorEdID ||
		prior.PQKeyID != priorPQID || candidate.NodeID != nodeID ||
		candidate.Purpose != "node_request" || candidate.KeyEpoch != toEpoch ||
		candidate.EdKeyID != nextEdID || candidate.PQKeyID != nextPQID ||
		!bytes.Equal(candidate.EdPublic, active.EdPublic) ||
		!bytes.Equal(candidate.PQPublic, active.PQPublic) {
		return empty, errors.New("authenticated old/new rotation snapshots mismatch")
	}
	if active.NodeID != nodeID || active.Purpose != "node_request" ||
		active.KeyEpoch != toEpoch || active.EdKeyID != nextEdID ||
		active.PQKeyID != nextPQID {
		return empty, errors.New("active decrypted public identity mismatches signed permit")
	}
	return active, nil
}

// WithAttestedAppliedRotation holds the shared wrapping-key flock for the
// entire verified operation, blocking cooperative Prepare/Activate/Recover
// writers that use the exclusive master lock. The callback must not acquire
// this same master lock again or invoke a nested vault rotation.
func WithAttestedAppliedRotation(vault, master string, nodeID int64,
	fromEpoch, toEpoch uint64, priorEdID, priorPQID, nextEdID, nextPQID string,
	action func(PublicBundle) error,
) error {
	if action == nil {
		return errors.New("missing attested action")
	}
	lock, key, err := masterLocked(master, false)
	if err != nil {
		return err
	}
	defer lock.Close()
	defer clear(key)
	active, err := attestAppliedRotationLocked(vault, key, nodeID, fromEpoch, toEpoch,
		priorEdID, priorPQID, nextEdID, nextPQID)
	if err != nil {
		return err
	}
	return action(active)
}

// AttestAppliedRotation is a read-only convenience probe. For writing an
// ACK journal, use WithAttestedAppliedRotation to avoid the check/write race.
func AttestAppliedRotation(vault, master string, nodeID int64,
	fromEpoch, toEpoch uint64, priorEdID, priorPQID, nextEdID, nextPQID string,
) (PublicBundle, error) {
	var active PublicBundle
	err := WithAttestedAppliedRotation(vault, master, nodeID, fromEpoch, toEpoch,
		priorEdID, priorPQID, nextEdID, nextPQID, func(pub PublicBundle) error {
			active = pub
			return nil
		})
	return active, err
}
