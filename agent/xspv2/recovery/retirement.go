package recovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

const retirementAuthorizationDomain = "XSP2-OWNER-RETIRE-PREVIOUS-V1"
const retirementAuthorizationDigestDomain = "XSP2-OWNER-RETIRE-AUTH-DIGEST-V1"

type RetirementAuthorization struct {
	NodeID               uint64 `json:"nodeId"`
	ServerAuthority      string `json:"serverAuthority"`
	FromEpoch            uint64 `json:"fromEpoch"`
	ToEpoch              uint64 `json:"toEpoch"`
	PriorEdKeyID         string `json:"priorEdKeyId"`
	PriorPQKeyID         string `json:"priorPqKeyId"`
	ActiveEdKeyID        string `json:"activeEdKeyId"`
	ActivePQKeyID        string `json:"activePqKeyId"`
	CheckpointGeneration uint64 `json:"checkpointGeneration"`
	CheckpointSHA256Hex  string `json:"checkpointSha256Hex"`
	IssuedAtMS           int64  `json:"issuedAtMs"`
	ExpiresAtMS          int64  `json:"expiresAtMs"`
	RequestID            string `json:"requestId"`
	OwnerID              string `json:"ownerId"`
	OwnerEdKeyID         string `json:"ownerEdKeyId"`
	OwnerPQKeyID         string `json:"ownerPqKeyId"`
}

type SignedRetirementAuthorization struct {
	Authorization RetirementAuthorization `json:"authorization"`
	Signatures    Signatures              `json:"signatures"`
}

func CanonicalRetirementAuthorization(value RetirementAuthorization) ([]byte, error) {
	if value.NodeID == 0 || value.FromEpoch == 0 || value.FromEpoch == ^uint64(0) ||
		value.ToEpoch != value.FromEpoch+1 || value.CheckpointGeneration == 0 ||
		value.IssuedAtMS <= 0 || value.ExpiresAtMS <= value.IssuedAtMS ||
		value.ExpiresAtMS-value.IssuedAtMS > 300000 {
		return nil, errors.New("invalid retirement node, epoch, checkpoint generation or time window")
	}
	if strings.ContainsAny(value.ServerAuthority, "/:@?#") {
		return nil, errors.New("server authority must be an authenticated DNS name")
	}
	checkpointDigest, err := decodeDigest(value.CheckpointSHA256Hex, false)
	if err != nil {
		return nil, fmt.Errorf("invalid retirement checkpoint digest: %w", err)
	}

	var out bytes.Buffer
	out.WriteString(retirementAuthorizationDomain)
	out.WriteByte(0)
	putU64(&out, value.NodeID)
	putU64(&out, value.FromEpoch)
	putU64(&out, value.ToEpoch)
	putU64(&out, value.CheckpointGeneration)
	putI64(&out, value.IssuedAtMS)
	putI64(&out, value.ExpiresAtMS)
	for _, field := range []struct {
		value string
		max   int
	}{
		{value.ServerAuthority, 253},
		{value.PriorEdKeyID, 64},
		{value.PriorPQKeyID, 64},
		{value.ActiveEdKeyID, 64},
		{value.ActivePQKeyID, 64},
		{value.RequestID, 64},
		{value.OwnerID, 64},
		{value.OwnerEdKeyID, 64},
		{value.OwnerPQKeyID, 64},
	} {
		if err = putText(&out, field.value, field.max); err != nil {
			return nil, err
		}
	}
	out.Write(checkpointDigest)
	return out.Bytes(), nil
}

func SignRetirementAuthorization(value RetirementAuthorization, edPrivate ed25519.PrivateKey,
	pqPrivate *mldsa.PrivateKey,
) (SignedRetirementAuthorization, error) {
	canonical, err := CanonicalRetirementAuthorization(value)
	if err != nil {
		return SignedRetirementAuthorization{}, err
	}
	if len(edPrivate) != ed25519.PrivateKeySize || pqPrivate == nil {
		return SignedRetirementAuthorization{}, errors.New("owner recovery signing keys are absent")
	}
	pqSignature, err := pqPrivate.Sign(nil, canonical, nil)
	if err != nil {
		return SignedRetirementAuthorization{}, fmt.Errorf("ML-DSA-65 retirement signing: %w", err)
	}
	return SignedRetirementAuthorization{
		Authorization: value,
		Signatures: Signatures{
			Ed25519: base64.StdEncoding.EncodeToString(ed25519.Sign(edPrivate, canonical)),
			MLDSA65: base64.StdEncoding.EncodeToString(pqSignature),
		},
	}, nil
}

func VerifyRetirementAuthorizationSignature(signed SignedRetirementAuthorization, pin OwnerPublic) error {
	value := signed.Authorization
	if err := verifyOwnerIdentity(pin, Checkpoint{
		OwnerID:      value.OwnerID,
		OwnerEdKeyID: value.OwnerEdKeyID,
		OwnerPQKeyID: value.OwnerPQKeyID,
	}); err != nil {
		return err
	}
	canonical, err := CanonicalRetirementAuthorization(value)
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
		return errors.New("owner retirement Ed25519 signature invalid")
	}
	pqPublic, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pin.PQPublic)
	if err != nil {
		return err
	}
	if err = mldsa.Verify(pqPublic, canonical, pqSignature, nil); err != nil {
		return errors.New("owner retirement ML-DSA-65 signature invalid")
	}
	return nil
}

// RetirementAuthorizationDigest binds both owner signatures and the exact
// canonical authorization into the local authenticated retirement intent.
func RetirementAuthorizationDigest(signed SignedRetirementAuthorization) (string, error) {
	canonical, err := CanonicalRetirementAuthorization(signed.Authorization)
	if err != nil {
		return "", err
	}
	edSignature, err := signatureBytes(signed.Signatures.Ed25519, ed25519.SignatureSize)
	if err != nil {
		return "", err
	}
	pqSignature, err := signatureBytes(signed.Signatures.MLDSA65, mldsa.MLDSA65SignatureSize)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(retirementAuthorizationDigestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(canonical)
	_, _ = hash.Write(edSignature)
	_, _ = hash.Write(pqSignature)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func verifyRetirementAuthorizationBinding(signed SignedRetirementAuthorization, pin OwnerPublic,
	checkpoint SignedCheckpoint, minimumGeneration uint64, nowMS int64, resume bool,
) error {
	if minimumGeneration == 0 {
		return errors.New("independent off-host generation floor is required")
	}
	if err := VerifyRetirementAuthorizationSignature(signed, pin); err != nil {
		return err
	}
	if err := VerifySignature(checkpoint, pin); err != nil {
		return fmt.Errorf("retirement checkpoint: %w", err)
	}
	value := signed.Authorization
	currentCheckpoint := checkpoint.Checkpoint
	if !resume && currentCheckpoint.Generation < minimumGeneration {
		return errors.New("retirement checkpoint is below independent monotonic generation floor")
	}
	checkpointDigest, err := CheckpointDigest(currentCheckpoint)
	if err != nil {
		return err
	}
	if value.CheckpointGeneration != currentCheckpoint.Generation ||
		value.CheckpointSHA256Hex != checkpointDigest || value.NodeID != currentCheckpoint.NodeID ||
		value.ServerAuthority != currentCheckpoint.ServerAuthority || value.ToEpoch != currentCheckpoint.KeyEpoch ||
		value.ActiveEdKeyID != currentCheckpoint.NodeEdKeyID || value.ActivePQKeyID != currentCheckpoint.NodePQKeyID ||
		value.OwnerID != currentCheckpoint.OwnerID || value.OwnerEdKeyID != currentCheckpoint.OwnerEdKeyID ||
		value.OwnerPQKeyID != currentCheckpoint.OwnerPQKeyID {
		return errors.New("retirement authorization is not bound to the accepted owner recovery checkpoint")
	}
	if value.IssuedAtMS < currentCheckpoint.IssuedAtMS || nowMS < value.IssuedAtMS {
		return errors.New("retirement authorization is future-dated or predates the recovery checkpoint")
	}
	if !resume && nowMS > value.ExpiresAtMS {
		return errors.New("retirement authorization is stale")
	}
	return nil
}

func retirementRecordMatchesAuthorization(record keyring.RetirementRecord, value RetirementAuthorization, digest string) bool {
	return record.NodeID > 0 && uint64(record.NodeID) == value.NodeID && record.Purpose == "node_request" &&
		record.FromEpoch == value.FromEpoch && record.ToEpoch == value.ToEpoch &&
		record.PriorEdKeyID == value.PriorEdKeyID && record.PriorPQKeyID == value.PriorPQKeyID &&
		record.ActiveEdKeyID == value.ActiveEdKeyID && record.ActivePQKeyID == value.ActivePQKeyID &&
		record.AuthorizationSHA256 == digest
}

func verifyRetainedStateMatchesAuthorization(layout state.Layout, value RetirementAuthorization) error {
	retained, err := state.DescribeRetainedRotation(layout)
	if err != nil {
		return err
	}
	if retained.Purpose != "node_request" || retained.NodeID <= 0 || uint64(retained.NodeID) != value.NodeID ||
		retained.FromEpoch != value.FromEpoch || retained.ToEpoch != value.ToEpoch ||
		retained.PriorEdKeyID != value.PriorEdKeyID || retained.PriorPQKeyID != value.PriorPQKeyID ||
		retained.ActiveEdKeyID != value.ActiveEdKeyID || retained.ActivePQKeyID != value.ActivePQKeyID {
		return errors.New("retained Agent key state does not match owner retirement authorization")
	}
	return nil
}

// VerifyRetirementAuthorization is deliberately read-only. It proves that the
// owner signed retirement of exactly the retained previous identity for the
// current durable Agent state and newest accepted off-host recovery checkpoint.
func VerifyRetirementAuthorization(signed SignedRetirementAuthorization, pin OwnerPublic,
	checkpoint SignedCheckpoint, minimumGeneration uint64, layout state.Layout, nowMS int64,
) error {
	if err := verifyRetirementAuthorizationBinding(signed, pin, checkpoint, minimumGeneration, nowMS, false); err != nil {
		return err
	}
	return verifyRetainedStateMatchesAuthorization(layout, signed.Authorization)
}

// RetireAuthorizedPrevious performs the first actual old-key erasure gate. A
// fresh owner authorization and current off-host generation are mandatory
// before the authenticated retirement intent exists. After that intent is
// durably persisted, an exact retry may finish erasure after expiration or a
// newer off-host generation because it is continuing, not creating, the same
// previously authorized mutation. Signatures and checkpoint binding are still
// re-verified on every retry.
func RetireAuthorizedPrevious(signed SignedRetirementAuthorization, pin OwnerPublic,
	checkpoint SignedCheckpoint, minimumGeneration uint64, layout state.Layout, nowMS int64,
) (state.SecuritySnapshot, error) {
	digest, err := RetirementAuthorizationDigest(signed)
	if err != nil {
		return state.SecuritySnapshot{}, err
	}
	record, exists, err := keyring.DescribeRetirement(layout.Vault, layout.MasterKey)
	if err != nil {
		return state.SecuritySnapshot{}, err
	}
	resume := exists && retirementRecordMatchesAuthorization(record, signed.Authorization, digest)
	if err = verifyRetirementAuthorizationBinding(signed, pin, checkpoint, minimumGeneration, nowMS, resume); err != nil {
		return state.SecuritySnapshot{}, err
	}
	if !resume {
		if err = verifyRetainedStateMatchesAuthorization(layout, signed.Authorization); err != nil {
			return state.SecuritySnapshot{}, err
		}
	}
	value := signed.Authorization
	if _, err = keyring.RetireAppliedRotation(layout.Vault, layout.MasterKey, int64(value.NodeID),
		value.FromEpoch, value.ToEpoch, value.PriorEdKeyID, value.PriorPQKeyID,
		value.ActiveEdKeyID, value.ActivePQKeyID, digest); err != nil {
		return state.SecuritySnapshot{}, err
	}
	return state.DescribeCurrent(layout)
}

func DecodeRetirementAuthorization(raw []byte) (SignedRetirementAuthorization, error) {
	if len(raw) == 0 || len(raw) > 24*1024 {
		return SignedRetirementAuthorization{}, errors.New("retirement authorization size invalid")
	}
	if err := uniqueJSONFields(raw); err != nil {
		return SignedRetirementAuthorization{}, err
	}
	var signed SignedRetirementAuthorization
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signed); err != nil {
		return SignedRetirementAuthorization{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return SignedRetirementAuthorization{}, errors.New("trailing retirement authorization bytes")
	}
	if _, err := CanonicalRetirementAuthorization(signed.Authorization); err != nil {
		return SignedRetirementAuthorization{}, err
	}
	return signed, nil
}
