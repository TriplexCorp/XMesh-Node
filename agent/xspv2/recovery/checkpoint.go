package recovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
)

const (
	checkpointDomain = "XSP2-OWNER-RECOVERY-CHECKPOINT-V1"
	nexusStateDomain = "XSP2-NEXUS-RECOVERY-STATE-V1"
	ownerPurpose     = "owner_recovery"
)

type NexusState struct {
	NodeID            uint64 `json:"nodeId"`
	KeyEpoch          uint64 `json:"keyEpoch"`
	RequestID         string `json:"requestId"`
	PermitState       string `json:"permitState"`
	ReceiptSHA256Hex  string `json:"receiptSha256Hex"`
	OutboxCount       uint64 `json:"outboxCount"`
	ReplayNonceCount  uint64 `json:"replayNonceCount"`
}

type Checkpoint struct {
	Generation                  uint64 `json:"generation"`
	PreviousCheckpointSHA256Hex string `json:"previousCheckpointSha256Hex"`
	NodeID                      uint64 `json:"nodeId"`
	ServerAuthority             string `json:"serverAuthority"`
	KeyEpoch                    uint64 `json:"keyEpoch"`
	NodeEdKeyID                 string `json:"nodeEdKeyId"`
	NodePQKeyID                 string `json:"nodePqKeyId"`
	CommitRequestID             string `json:"commitRequestId"`
	CommitReceiptSHA256Hex      string `json:"commitReceiptSha256Hex"`
	NexusStateSHA256Hex         string `json:"nexusStateSha256Hex"`
	IssuedAtMS                  int64  `json:"issuedAtMs"`
	OwnerID                     string `json:"ownerId"`
	OwnerEdKeyID                string `json:"ownerEdKeyId"`
	OwnerPQKeyID                string `json:"ownerPqKeyId"`
}

type Signatures struct {
	Ed25519 string `json:"ed25519"`
	MLDSA65 string `json:"mldsa65"`
}

type SignedCheckpoint struct {
	Checkpoint Checkpoint `json:"checkpoint"`
	Signatures Signatures `json:"signatures"`
}

type OwnerPublic struct {
	OwnerID  string
	Purpose  string
	EdKeyID  string
	PQKeyID  string
	EdPublic []byte
	PQPublic []byte
}

type LocalEvidence struct {
	NodeID          uint64
	ServerAuthority string
	KeyEpoch        uint64
	NodeEdKeyID     string
	NodePQKeyID     string
	CommitRequestID string
	CommitReceipt   []byte
	Nexus           NexusState
}

func putU64(out *bytes.Buffer, value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	out.Write(raw[:])
}

func putI64(out *bytes.Buffer, value int64) { putU64(out, uint64(value)) }

func putText(out *bytes.Buffer, value string, max int) error {
	if len(value) == 0 || len(value) > max {
		return errors.New("invalid text field length")
	}
	for _, b := range []byte(value) {
		if b < 33 || b > 126 {
			return errors.New("text field must be graphic ASCII")
		}
	}
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], uint32(len(value)))
	out.Write(raw[:])
	out.WriteString(value)
	return nil
}

func decodeDigest(value string, allowZero bool) ([]byte, error) {
	if len(value) != sha256.Size*2 {
		return nil, errors.New("digest must be SHA-256 hex")
	}
	raw, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(raw) != value {
		return nil, errors.New("digest must be canonical lowercase hex")
	}
	zero := true
	for _, b := range raw {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero && !allowZero {
		return nil, errors.New("zero digest is not allowed")
	}
	return raw, nil
}

func shaHex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func keyID(prefix string, raw []byte) string {
	digest := sha256.Sum256(raw)
	return prefix + hex.EncodeToString(digest[:12])
}

func NexusStateDigest(value NexusState) (string, error) {
	if value.NodeID == 0 || value.KeyEpoch == 0 || value.PermitState != "ack_verified" ||
		value.OutboxCount == 0 || value.ReplayNonceCount == 0 {
		return "", errors.New("Nexus recovery state is not a committed security state")
	}
	receiptDigest, err := decodeDigest(value.ReceiptSHA256Hex, false)
	if err != nil {
		return "", fmt.Errorf("invalid Nexus receipt digest: %w", err)
	}
	var out bytes.Buffer
	out.WriteString(nexusStateDomain)
	out.WriteByte(0)
	putU64(&out, value.NodeID)
	putU64(&out, value.KeyEpoch)
	if err = putText(&out, value.RequestID, 64); err != nil {
		return "", err
	}
	if err = putText(&out, value.PermitState, 32); err != nil {
		return "", err
	}
	out.Write(receiptDigest)
	putU64(&out, value.OutboxCount)
	putU64(&out, value.ReplayNonceCount)
	return shaHex(out.Bytes()), nil
}

func Canonical(value Checkpoint) ([]byte, error) {
	if value.Generation == 0 || value.NodeID == 0 || value.KeyEpoch == 0 || value.IssuedAtMS <= 0 {
		return nil, errors.New("invalid checkpoint generation, node, epoch or timestamp")
	}
	if strings.ContainsAny(value.ServerAuthority, "/:@?#") {
		return nil, errors.New("server authority must be an authenticated DNS name")
	}
	previous, err := decodeDigest(value.PreviousCheckpointSHA256Hex, value.Generation == 1)
	if err != nil {
		return nil, fmt.Errorf("invalid previous checkpoint digest: %w", err)
	}
	previousZero := true
	for _, b := range previous {
		if b != 0 {
			previousZero = false
			break
		}
	}
	if (value.Generation == 1) != previousZero {
		return nil, errors.New("checkpoint chain genesis/successor mismatch")
	}
	receiptDigest, err := decodeDigest(value.CommitReceiptSHA256Hex, false)
	if err != nil {
		return nil, fmt.Errorf("invalid commit receipt digest: %w", err)
	}
	nexusDigest, err := decodeDigest(value.NexusStateSHA256Hex, false)
	if err != nil {
		return nil, fmt.Errorf("invalid Nexus state digest: %w", err)
	}

	var out bytes.Buffer
	out.WriteString(checkpointDomain)
	out.WriteByte(0)
	putU64(&out, value.Generation)
	putU64(&out, value.NodeID)
	putU64(&out, value.KeyEpoch)
	putI64(&out, value.IssuedAtMS)
	for _, field := range []struct {
		value string
		max   int
	}{
		{value.ServerAuthority, 253},
		{value.NodeEdKeyID, 64},
		{value.NodePQKeyID, 64},
		{value.CommitRequestID, 64},
		{value.OwnerID, 64},
		{value.OwnerEdKeyID, 64},
		{value.OwnerPQKeyID, 64},
	} {
		if err = putText(&out, field.value, field.max); err != nil {
			return nil, err
		}
	}
	out.Write(previous)
	out.Write(receiptDigest)
	out.Write(nexusDigest)
	return out.Bytes(), nil
}

func CheckpointDigest(value Checkpoint) (string, error) {
	canonical, err := Canonical(value)
	if err != nil {
		return "", err
	}
	return shaHex(canonical), nil
}

func signatureBytes(value string, size int) ([]byte, error) {
	expected := ((size + 2) / 3) * 4
	if len(value) != expected {
		return nil, errors.New("signature size mismatch")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != size || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("noncanonical signature")
	}
	return raw, nil
}

func verifyOwnerIdentity(pin OwnerPublic, checkpoint Checkpoint) error {
	if pin.Purpose != ownerPurpose || pin.OwnerID == "" || pin.OwnerID != checkpoint.OwnerID ||
		pin.EdKeyID != checkpoint.OwnerEdKeyID || pin.PQKeyID != checkpoint.OwnerPQKeyID ||
		len(pin.EdPublic) != ed25519.PublicKeySize || len(pin.PQPublic) != mldsa.MLDSA65PublicKeySize ||
		pin.EdKeyID != keyID("ed-", pin.EdPublic) || pin.PQKeyID != keyID("pq-", pin.PQPublic) {
		return errors.New("untrusted owner recovery signer identity, purpose or fingerprint")
	}
	return nil
}

func Sign(checkpoint Checkpoint, edPrivate ed25519.PrivateKey, pqPrivate *mldsa.PrivateKey) (SignedCheckpoint, error) {
	canonical, err := Canonical(checkpoint)
	if err != nil {
		return SignedCheckpoint{}, err
	}
	if len(edPrivate) != ed25519.PrivateKeySize || pqPrivate == nil {
		return SignedCheckpoint{}, errors.New("owner recovery signing keys are absent")
	}
	pqSignature, err := pqPrivate.Sign(nil, canonical, nil)
	if err != nil {
		return SignedCheckpoint{}, fmt.Errorf("ML-DSA-65 owner recovery signing: %w", err)
	}
	return SignedCheckpoint{
		Checkpoint: checkpoint,
		Signatures: Signatures{
			Ed25519: base64.StdEncoding.EncodeToString(ed25519.Sign(edPrivate, canonical)),
			MLDSA65: base64.StdEncoding.EncodeToString(pqSignature),
		},
	}, nil
}

func VerifySignature(signed SignedCheckpoint, pin OwnerPublic) error {
	if err := verifyOwnerIdentity(pin, signed.Checkpoint); err != nil {
		return err
	}
	canonical, err := Canonical(signed.Checkpoint)
	if err != nil {
		return err
	}
	edSignature, err := signatureBytes(signed.Signatures.Ed25519, ed25519.SignatureSize)
	if err != nil {
		return err
	}
	pqSignature, err := signatureBytes(signed.Signatures.MLDSA65, mldsa.MLDSA65SignatureSize)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pin.EdPublic, canonical, edSignature) {
		return errors.New("owner recovery Ed25519 signature invalid")
	}
	pqPublic, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pin.PQPublic)
	if err != nil {
		return err
	}
	if err = mldsa.Verify(pqPublic, canonical, pqSignature, nil); err != nil {
		return errors.New("owner recovery ML-DSA-65 signature invalid")
	}
	return nil
}

func VerifySuccessor(previous, next SignedCheckpoint, pin OwnerPublic) error {
	if err := VerifySignature(previous, pin); err != nil {
		return fmt.Errorf("previous checkpoint: %w", err)
	}
	if err := VerifySignature(next, pin); err != nil {
		return fmt.Errorf("next checkpoint: %w", err)
	}
	wantPrevious, err := CheckpointDigest(previous.Checkpoint)
	if err != nil {
		return err
	}
	if next.Checkpoint.Generation != previous.Checkpoint.Generation+1 ||
		next.Checkpoint.PreviousCheckpointSHA256Hex != wantPrevious ||
		next.Checkpoint.NodeID != previous.Checkpoint.NodeID ||
		next.Checkpoint.ServerAuthority != previous.Checkpoint.ServerAuthority ||
		next.Checkpoint.OwnerID != previous.Checkpoint.OwnerID ||
		next.Checkpoint.OwnerEdKeyID != previous.Checkpoint.OwnerEdKeyID ||
		next.Checkpoint.OwnerPQKeyID != previous.Checkpoint.OwnerPQKeyID {
		return errors.New("owner recovery checkpoint chain is not monotonic")
	}
	if next.Checkpoint.KeyEpoch < previous.Checkpoint.KeyEpoch {
		return errors.New("owner recovery checkpoint epoch moved backward")
	}
	return nil
}

func EvidenceFromAgent(snapshot state.SecuritySnapshot, serverAuthority, requestID string, receipt []byte, nexus NexusState) (LocalEvidence, error) {
	if snapshot.NodeID <= 0 || snapshot.KeyEpoch == 0 || snapshot.EdKeyID == "" || snapshot.PQKeyID == "" {
		return LocalEvidence{}, errors.New("invalid durable Agent security snapshot")
	}
	if !snapshot.PreviousRetained || !snapshot.CandidateRetained {
		return LocalEvidence{}, errors.New("old/new authenticated Agent key snapshots must remain retained")
	}
	if len(receipt) == 0 {
		return LocalEvidence{}, errors.New("authoritative commit receipt is required")
	}
	return LocalEvidence{
		NodeID:          uint64(snapshot.NodeID),
		ServerAuthority: serverAuthority,
		KeyEpoch:        snapshot.KeyEpoch,
		NodeEdKeyID:     snapshot.EdKeyID,
		NodePQKeyID:     snapshot.PQKeyID,
		CommitRequestID: requestID,
		CommitReceipt:   append([]byte(nil), receipt...),
		Nexus:           nexus,
	}, nil
}

func VerifyLocal(signed SignedCheckpoint, pin OwnerPublic, local LocalEvidence, minimumGeneration uint64) error {
	if minimumGeneration == 0 {
		return errors.New("independent off-host generation floor is required")
	}
	if err := VerifySignature(signed, pin); err != nil {
		return err
	}
	checkpoint := signed.Checkpoint
	if checkpoint.Generation < minimumGeneration {
		return errors.New("owner recovery checkpoint is below independent monotonic generation floor")
	}
	if len(local.CommitReceipt) == 0 {
		return errors.New("local authoritative commit receipt is absent")
	}
	receiptDigest := shaHex(local.CommitReceipt)
	if local.Nexus.NodeID != local.NodeID || local.Nexus.KeyEpoch != local.KeyEpoch ||
		local.Nexus.RequestID != local.CommitRequestID || local.Nexus.ReceiptSHA256Hex != receiptDigest {
		return errors.New("Agent and Nexus recovery evidence disagree")
	}
	nexusDigest, err := NexusStateDigest(local.Nexus)
	if err != nil {
		return err
	}
	if checkpoint.NodeID != local.NodeID || checkpoint.ServerAuthority != local.ServerAuthority ||
		checkpoint.KeyEpoch != local.KeyEpoch || checkpoint.NodeEdKeyID != local.NodeEdKeyID ||
		checkpoint.NodePQKeyID != local.NodePQKeyID || checkpoint.CommitRequestID != local.CommitRequestID ||
		checkpoint.CommitReceiptSHA256Hex != receiptDigest || checkpoint.NexusStateSHA256Hex != nexusDigest {
		return errors.New("local Agent/Nexus state is older than or different from owner recovery checkpoint")
	}
	return nil
}

func uniqueJSONFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	objects := 0
	var walk func(int) error
	walk = func(depth int) error {
		objects++
		if depth > 3 || objects > 64 {
			return errors.New("excessive checkpoint JSON complexity")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delim != '{' {
			return errors.New("arrays are not allowed in recovery checkpoint")
		}
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate recovery checkpoint JSON field")
			}
			seen[name] = true
			if err = walk(depth + 1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing recovery checkpoint JSON")
	}
	return nil
}

func Decode(raw []byte) (SignedCheckpoint, error) {
	if len(raw) == 0 || len(raw) > 24*1024 {
		return SignedCheckpoint{}, errors.New("recovery checkpoint size invalid")
	}
	if err := uniqueJSONFields(raw); err != nil {
		return SignedCheckpoint{}, err
	}
	var signed SignedCheckpoint
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return SignedCheckpoint{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return SignedCheckpoint{}, errors.New("trailing recovery checkpoint bytes")
	}
	if _, err := Canonical(signed.Checkpoint); err != nil {
		return SignedCheckpoint{}, err
	}
	return signed, nil
}
