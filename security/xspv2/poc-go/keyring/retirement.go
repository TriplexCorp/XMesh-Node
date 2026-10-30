package keyring

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

const retirementMarkerVersion = 1
const retirementMarkerDomain = "XSP2-RETIRED-ROTATION-V1"

// RetirementRecord contains no private key material. AuthorizationSHA256 is
// the digest of the already-verified dual-signed owner retirement proof.
type RetirementRecord struct {
	Version             int    `json:"version"`
	NodeID              int64  `json:"nodeId"`
	Purpose             string `json:"purpose"`
	FromEpoch           uint64 `json:"fromEpoch"`
	ToEpoch             uint64 `json:"toEpoch"`
	PriorEdKeyID        string `json:"priorEdKeyId"`
	PriorPQKeyID        string `json:"priorPqKeyId"`
	ActiveEdKeyID       string `json:"activeEdKeyId"`
	ActivePQKeyID       string `json:"activePqKeyId"`
	AuthorizationSHA256 string `json:"authorizationSha256"`
}

type retirementMarker struct {
	RetirementRecord
	MAC string `json:"mac"`
}

func retirementPath(vault string) string { return vault + ".retirement" }

func putRetirementText(out *bytes.Buffer, value string, max int) error {
	if value == "" || len(value) > max || bytes.IndexByte([]byte(value), 0) >= 0 {
		return errors.New("invalid retirement text field")
	}
	if err := binary.Write(out, binary.BigEndian, uint16(len(value))); err != nil {
		return err
	}
	_, err := out.WriteString(value)
	return err
}

func canonicalRetirementRecord(record RetirementRecord) ([]byte, error) {
	if record.Version != retirementMarkerVersion || record.NodeID <= 0 || record.Purpose != "node_request" ||
		record.FromEpoch == 0 || record.FromEpoch == ^uint64(0) || record.ToEpoch != record.FromEpoch+1 {
		return nil, errors.New("invalid retirement record identity or epoch")
	}
	digest, err := hex.DecodeString(record.AuthorizationSHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != record.AuthorizationSHA256 {
		return nil, errors.New("invalid retirement authorization digest")
	}
	var out bytes.Buffer
	out.WriteString(retirementMarkerDomain)
	out.WriteByte(0)
	if err = binary.Write(&out, binary.BigEndian, record.NodeID); err != nil {
		return nil, err
	}
	if err = binary.Write(&out, binary.BigEndian, record.FromEpoch); err != nil {
		return nil, err
	}
	if err = binary.Write(&out, binary.BigEndian, record.ToEpoch); err != nil {
		return nil, err
	}
	for _, field := range []struct {
		value string
		max   int
	}{
		{record.Purpose, 32},
		{record.PriorEdKeyID, 64},
		{record.PriorPQKeyID, 64},
		{record.ActiveEdKeyID, 64},
		{record.ActivePQKeyID, 64},
	} {
		if err = putRetirementText(&out, field.value, field.max); err != nil {
			return nil, err
		}
	}
	out.Write(digest)
	return out.Bytes(), nil
}

func retirementMAC(record RetirementRecord, key []byte) (string, error) {
	canonical, err := canonicalRetirementRecord(record)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func writeRetirementMarker(vault string, record RetirementRecord, key []byte) error {
	mac, err := retirementMAC(record, key)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(retirementMarker{RetirementRecord: record, MAC: mac})
	if err != nil {
		return err
	}
	return atomicFile(retirementPath(vault), raw)
}

func readRetirementMarker(vault string, key []byte) (RetirementRecord, bool, error) {
	var empty RetirementRecord
	raw, err := secureFile(retirementPath(vault))
	if errors.Is(err, os.ErrNotExist) {
		return empty, false, nil
	}
	if err != nil {
		return empty, false, err
	}
	if len(raw) > 8192 {
		return empty, false, errors.New("oversized retirement marker")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var marker retirementMarker
	if err = decoder.Decode(&marker); err != nil {
		return empty, false, err
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return empty, false, errors.New("trailing retirement marker data")
	}
	expected, err := retirementMAC(marker.RetirementRecord, key)
	if err != nil {
		return empty, false, err
	}
	provided, err := hex.DecodeString(marker.MAC)
	if err != nil || len(provided) != sha256.Size || !hmac.Equal(provided, mustDecodeHex(expected)) {
		return empty, false, errors.New("retirement marker authentication failed")
	}
	return marker.RetirementRecord, true, nil
}

func mustDecodeHex(value string) []byte {
	raw, _ := hex.DecodeString(value)
	return raw
}

func sameRetirementRecord(left, right RetirementRecord) bool {
	return left == right
}

func retirementPairWasRetiredLocked(vault string, key []byte, prior, candidate PublicBundle) (bool, error) {
	record, ok, err := readRetirementMarker(vault, key)
	if err != nil || !ok {
		return false, err
	}
	return record.NodeID == prior.NodeID && record.Purpose == prior.Purpose &&
		record.FromEpoch == prior.KeyEpoch && record.ToEpoch == candidate.KeyEpoch &&
		record.PriorEdKeyID == prior.EdKeyID && record.PriorPQKeyID == prior.PQKeyID &&
		record.ActiveEdKeyID == candidate.EdKeyID && record.ActivePQKeyID == candidate.PQKeyID, nil
}

func enforceRetirementFloorLocked(vault string, key []byte, active PublicBundle) error {
	record, ok, err := readRetirementMarker(vault, key)
	if err != nil || !ok {
		return err
	}
	floor, err := readFloor(vault)
	if err != nil {
		return err
	}
	if floor < record.ToEpoch {
		return errors.New("retirement floor rejected rolled-back persisted epoch floor")
	}
	if active.NodeID != record.NodeID || active.Purpose != record.Purpose || active.KeyEpoch < record.ToEpoch {
		return errors.New("retirement floor rejected rolled-back active identity")
	}
	if active.KeyEpoch == record.ToEpoch &&
		(active.EdKeyID != record.ActiveEdKeyID || active.PQKeyID != record.ActivePQKeyID) {
		return errors.New("retirement floor active identity mismatch")
	}
	return nil
}

func expectedRetirementRecord(nodeID int64, fromEpoch, toEpoch uint64,
	priorEdID, priorPQID, activeEdID, activePQID, authorizationSHA256 string,
) RetirementRecord {
	return RetirementRecord{
		Version:             retirementMarkerVersion,
		NodeID:              nodeID,
		Purpose:             "node_request",
		FromEpoch:           fromEpoch,
		ToEpoch:             toEpoch,
		PriorEdKeyID:        priorEdID,
		PriorPQKeyID:        priorPQID,
		ActiveEdKeyID:       activeEdID,
		ActivePQKeyID:       activePQID,
		AuthorizationSHA256: authorizationSHA256,
	}
}

func validateRetirementResumeFile(path string, key []byte, expectedNodeID int64, expectedEpoch uint64,
	expectedEdID, expectedPQID string,
) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, bundle, err := openWithMaster(path, key)
	if err != nil {
		return false, err
	}
	if bundle.NodeID != expectedNodeID || bundle.KeyEpoch != expectedEpoch ||
		bundle.EdKeyID != expectedEdID || bundle.PQKeyID != expectedPQID || bundle.Purpose != "node_request" {
		return false, errors.New("retirement resume snapshot does not match authenticated intent")
	}
	return true, nil
}

// RetireAppliedRotation durably retires only the exact already-applied
// previous/candidate snapshots named by a separately verified owner
// authorization digest. The authenticated marker is persisted before either
// snapshot is removed, making retries after a process crash deterministic.
func RetireAppliedRotation(vault, master string, nodeID int64, fromEpoch, toEpoch uint64,
	priorEdID, priorPQID, activeEdID, activePQID, authorizationSHA256 string,
) (PublicBundle, error) {
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

	expected := expectedRetirementRecord(nodeID, fromEpoch, toEpoch,
		priorEdID, priorPQID, activeEdID, activePQID, authorizationSHA256)
	if _, err = canonicalRetirementRecord(expected); err != nil {
		return empty, err
	}

	marker, markerExists, err := readRetirementMarker(vault, key)
	if err != nil {
		return empty, err
	}
	resume := markerExists && sameRetirementRecord(marker, expected)
	if markerExists && !resume {
		if marker.NodeID != nodeID || marker.Purpose != "node_request" || marker.ToEpoch != fromEpoch ||
			marker.ActiveEdKeyID != priorEdID || marker.ActivePQKeyID != priorPQID {
			return empty, errors.New("retirement marker monotonic chain mismatch")
		}
	}

	if !resume {
		active, attestErr := attestAppliedRotationLocked(vault, key, nodeID, fromEpoch, toEpoch,
			priorEdID, priorPQID, activeEdID, activePQID)
		if attestErr != nil {
			return empty, attestErr
		}
		if err = enforceRetirementFloorLocked(vault, key, active); err != nil {
			return empty, err
		}
		if err = writeRetirementMarker(vault, expected, key); err != nil {
			return empty, err
		}
		rotationDurabilityCheckpoint("after-retirement-intent")
	}

	_, active, err := openWithMaster(vault, key)
	if err != nil {
		return empty, err
	}
	floor, err := readFloor(vault)
	if err != nil {
		return empty, err
	}
	if active.NodeID != nodeID || active.Purpose != "node_request" || active.KeyEpoch != toEpoch || floor != toEpoch ||
		active.EdKeyID != activeEdID || active.PQKeyID != activePQID {
		return empty, errors.New("active identity changed after retirement intent")
	}
	if err = enforceRetirementFloorLocked(vault, key, active); err != nil {
		return empty, err
	}

	previousPresent, err := validateRetirementResumeFile(previousPath(vault), key, nodeID, fromEpoch, priorEdID, priorPQID)
	if err != nil {
		return empty, err
	}
	candidatePresent, err := validateRetirementResumeFile(stagedPath(vault), key, nodeID, toEpoch, activeEdID, activePQID)
	if err != nil {
		return empty, err
	}
	if candidatePresent {
		currentRaw, rawErr := secureFile(vault)
		if rawErr != nil {
			return empty, rawErr
		}
		candidateRaw, rawErr := secureFile(stagedPath(vault))
		if rawErr != nil {
			return empty, rawErr
		}
		if !bytes.Equal(currentRaw, candidateRaw) {
			return empty, errors.New("retirement candidate no longer equals active encrypted identity")
		}
	}

	if previousPresent {
		if err = os.Remove(previousPath(vault)); err != nil {
			return empty, err
		}
		if err = syncParent(vault); err != nil {
			return empty, err
		}
		rotationDurabilityCheckpoint("after-retirement-previous")
	}
	if candidatePresent {
		if err = os.Remove(stagedPath(vault)); err != nil {
			return empty, err
		}
		if err = syncParent(vault); err != nil {
			return empty, err
		}
		rotationDurabilityCheckpoint("after-retirement-next")
	}
	return active, nil
}

// DescribeRetirement verifies the persistent authenticated retirement floor.
func DescribeRetirement(vault, master string) (RetirementRecord, bool, error) {
	lock, key, err := masterLocked(master, false)
	if err != nil {
		return RetirementRecord{}, false, err
	}
	defer lock.Close()
	defer clear(key)
	return readRetirementMarker(vault, key)
}

func validateRetirementRecordForPair(vault string, key []byte, prior, candidate PublicBundle) error {
	retired, err := retirementPairWasRetiredLocked(vault, key, prior, candidate)
	if err != nil {
		return err
	}
	if retired {
		return fmt.Errorf("retired rotation material reappeared for epoch %d -> %d", prior.KeyEpoch, candidate.KeyEpoch)
	}
	return nil
}
