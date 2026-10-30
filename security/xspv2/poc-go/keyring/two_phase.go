package keyring

// Research-only two-phase, operator-mediated Node key rotation. No automatic
// Nexus enrollment, signed approval, policy application or production agent
// integration is implied. The old encrypted keys remain sealed until a
// separately authenticated Nexus cutover acknowledgement exists.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func stagedPath(vault string) string { return vault + ".next" }
func previousPath(vault string) string { return vault + ".previous" }

func mustBeAbsent(path string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return fmt.Errorf("rotation file already exists: %s", filepath.Base(path))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func syncParent(path string) error {
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// PrepareRotation creates a fresh encrypted candidate on disk. It never
// advances the active epoch floor or changes the current active private key.
// No second rotation is allowed until a previous cutover is resolved.
func PrepareRotation(vault, master string, expectedEpoch uint64) (PublicBundle, error) {
	var empty PublicBundle
	lock, key, err := masterLocked(master, true)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	defer clear(key)
	if err = secureDir(vault); err != nil {
		return empty, err
	}
	if err = mustBeAbsent(stagedPath(vault)); err != nil {
		return empty, err
	}
	if err = mustBeAbsent(previousPath(vault)); err != nil {
		return empty, err
	}
	_, current, err := openWithMaster(vault, key)
	if err != nil {
		return empty, err
	}
	if err = enforceRetirementFloorLocked(vault, key, current); err != nil {
		return empty, err
	}
	floor, err := readFloor(vault)
	if err != nil {
		return empty, err
	}
	if expectedEpoch == 0 || current.KeyEpoch != expectedEpoch ||
		floor != expectedEpoch || expectedEpoch == ^uint64(0) {
		return empty, errors.New("active epoch or trusted floor mismatch")
	}
	newKeys, candidate, err := Generate(current.NodeID, current.Purpose, expectedEpoch+1)
	if err != nil {
		return empty, err
	}
	raw, err := seal(newKeys, candidate, key)
	if err != nil {
		return empty, err
	}
	if err = atomicFile(stagedPath(vault), raw); err != nil {
		return empty, err
	}
	return candidate, nil
}

// AbortPreparedRotation discards ONLY an unactivated candidate. It never
// decreases an epoch floor and refuses to abort once activation has started.
func AbortPreparedRotation(vault, master string, expectedEpoch uint64) error {
	lock, key, err := masterLocked(master, true)
	if err != nil {
		return err
	}
	defer lock.Close()
	defer clear(key)
	_, current, err := openWithMaster(vault, key)
	if err != nil {
		return err
	}
	if err = enforceRetirementFloorLocked(vault, key, current); err != nil {
		return err
	}
	_, candidate, err := openWithMaster(stagedPath(vault), key)
	if err != nil {
		return err
	}
	if err = mustBeAbsent(previousPath(vault)); err != nil {
		return err
	}
	floor, err := readFloor(vault)
	if err != nil {
		return err
	}
	if current.KeyEpoch != expectedEpoch || floor != expectedEpoch ||
		expectedEpoch == 0 || expectedEpoch == ^uint64(0) ||
		candidate.KeyEpoch != expectedEpoch+1 ||
		candidate.NodeID != current.NodeID || candidate.Purpose != current.Purpose {
		return errors.New("prepared rotation is not safely abortable")
	}
	if err = os.Remove(stagedPath(vault)); err != nil {
		return err
	}
	return syncParent(vault)
}

// ActivatePreparedRotation is an explicit LOCAL operator step, only after
// independently confirming the owner-approved candidate fingerprint. It does
// not claim to verify a network approval or to have received a Nexus ACK.
//
// Crash ordering: backup old -> floor new -> replace active with new.
// If power fails after floor change, Open fails closed until RecoverRotation
// explicitly finishes the authorized cutover using the preserved candidate.
func ActivatePreparedRotation(
	vault, master string, expectedOldEpoch uint64,
	expectedEdID, expectedPQID string,
) (PublicBundle, error) {
	var empty PublicBundle
	lock, key, err := masterLocked(master, true)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	defer clear(key)
	if err = mustBeAbsent(previousPath(vault)); err != nil {
		return empty, err
	}
	_, current, err := openWithMaster(vault, key)
	if err != nil {
		return empty, err
	}
	if err = enforceRetirementFloorLocked(vault, key, current); err != nil {
		return empty, err
	}
	_, candidate, err := openWithMaster(stagedPath(vault), key)
	if err != nil {
		return empty, err
	}
	floor, err := readFloor(vault)
	if err != nil {
		return empty, err
	}
	if expectedOldEpoch == 0 || expectedOldEpoch == ^uint64(0) ||
		floor != expectedOldEpoch || current.KeyEpoch != expectedOldEpoch ||
		candidate.KeyEpoch != expectedOldEpoch+1 ||
		current.NodeID != candidate.NodeID || current.Purpose != candidate.Purpose ||
		expectedEdID == "" || expectedPQID == "" ||
		candidate.EdKeyID != expectedEdID || candidate.PQKeyID != expectedPQID {
		return empty, errors.New("candidate not explicitly approved for this active identity")
	}
	oldRaw, err := secureFile(vault)
	if err != nil {
		return empty, err
	}
	nextRaw, err := secureFile(stagedPath(vault))
	if err != nil {
		return empty, err
	}
	if err = atomicFile(previousPath(vault), oldRaw); err != nil {
		return empty, err
	}
	rotationDurabilityCheckpoint("after-previous")
	if err = updateFloor(vault, candidate.KeyEpoch); err != nil {
		return empty, err
	}
	rotationDurabilityCheckpoint("after-floor")
	if err = atomicFile(vault, nextRaw); err != nil {
		return empty, err
	}
	rotationDurabilityCheckpoint("after-active")
	// Keep BOTH .next and .previous for crash reconciliation and evidence.
	// Never automatically retire prior signing material here.
	return candidate, nil
}

// RecoverRotation repairs a power interruption AFTER an owner-mediated local
// activation increased the persisted floor. It never rolls the floor backward,
// never selects the previous key as active, and never invents a new identity.
// Both immutable encrypted snapshots must still be present and authenticated.
func RecoverRotation(vault, master string) (PublicBundle, error) {
	var empty PublicBundle
	lock, key, err := masterLocked(master, true)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	defer clear(key)
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
	floor, err := readFloor(vault)
	if err != nil {
		return empty, err
	}
	if prior.KeyEpoch == 0 || prior.KeyEpoch == ^uint64(0) ||
		candidate.KeyEpoch != prior.KeyEpoch+1 ||
		prior.NodeID != candidate.NodeID || prior.Purpose != candidate.Purpose {
		return empty, errors.New("untrusted rotation recovery state")
	}
	currentRaw, err := secureFile(vault)
	if err != nil {
		return empty, err
	}
	priorRaw, err := secureFile(previousPath(vault))
	if err != nil {
		return empty, err
	}
	nextRaw, err := secureFile(stagedPath(vault))
	if err != nil {
		return empty, err
	}
	if floor == prior.KeyEpoch {
		// Crash after preserving .previous but BEFORE advancing the floor.
		// Return to an unactivated prepared state, never auto-cutover.
		if !bytes.Equal(currentRaw, priorRaw) {
			return empty, errors.New("untrusted active key before cutover")
		}
		if err = os.Remove(previousPath(vault)); err != nil {
			return empty, err
		}
		if err = syncParent(vault); err != nil {
			return empty, err
		}
		rotationDurabilityCheckpoint("after-recovery-abort")
		return prior, nil
	}
	if floor != candidate.KeyEpoch {
		return empty, errors.New("untrusted rotation epoch floor")
	}
	if bytes.Equal(currentRaw, priorRaw) {
		if err = atomicFile(vault, nextRaw); err != nil {
			return empty, err
		}
		rotationDurabilityCheckpoint("after-recovery-active")
	} else if !bytes.Equal(currentRaw, nextRaw) {
		return empty, errors.New("active encrypted identity was substituted")
	}
	_, active, err := openWithMaster(vault, key)
	if err != nil {
		return empty, err
	}
	if err = enforceRetirementFloorLocked(vault, key, active); err != nil {
		return empty, err
	}
	// A successful cutover is NOT permission to erase old keys. A separate
	// owner authorization and durable retirement journal remain mandatory.
	return candidate, nil
}
