package keyring

import (
	"bytes"
	"errors"
)

// RetainedRotation is read-only public evidence for one already-applied
// two-phase rotation. It contains no private key material.
type RetainedRotation struct {
	Previous  PublicBundle
	Active    PublicBundle
	Candidate PublicBundle
}

func clonePublicBundle(value PublicBundle) PublicBundle {
	value.EdPublic = append([]byte(nil), value.EdPublic...)
	value.PQPublic = append([]byte(nil), value.PQPublic...)
	return value
}

// DescribeRetainedRotation proves that the active vault is exactly the retained
// candidate, the previous identity is exactly one epoch behind, and the
// persisted epoch floor matches the active epoch. It never mutates key state.
func DescribeRetainedRotation(vault, master string) (RetainedRotation, error) {
	var empty RetainedRotation
	lock, key, err := masterLocked(master, false)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	defer clear(key)

	_, previous, err := openWithMaster(previousPath(vault), key)
	if err != nil {
		return empty, err
	}
	_, active, err := openWithMaster(vault, key)
	if err != nil {
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
	activeRaw, err := secureFile(vault)
	if err != nil {
		return empty, err
	}
	candidateRaw, err := secureFile(stagedPath(vault))
	if err != nil {
		return empty, err
	}

	if previous.NodeID <= 0 || previous.KeyEpoch == 0 || previous.KeyEpoch == ^uint64(0) ||
		active.KeyEpoch != previous.KeyEpoch+1 || candidate.KeyEpoch != active.KeyEpoch ||
		floor != active.KeyEpoch || previous.NodeID != active.NodeID || candidate.NodeID != active.NodeID ||
		previous.Purpose != active.Purpose || candidate.Purpose != active.Purpose ||
		active.EdKeyID != candidate.EdKeyID || active.PQKeyID != candidate.PQKeyID ||
		!bytes.Equal(active.EdPublic, candidate.EdPublic) || !bytes.Equal(active.PQPublic, candidate.PQPublic) ||
		!bytes.Equal(activeRaw, candidateRaw) {
		return empty, errors.New("retained rotation state is not an exact applied cutover")
	}

	return RetainedRotation{
		Previous:  clonePublicBundle(previous),
		Active:    clonePublicBundle(active),
		Candidate: clonePublicBundle(candidate),
	}, nil
}
