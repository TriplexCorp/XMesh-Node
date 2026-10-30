package recovery

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
)

const retirementRequestSchema = "xsp2-owner-retirement-request-1"

type RetirementRequest struct {
	Schema                   string `json:"schema"`
	NodeID                   uint64 `json:"nodeId"`
	ServerAuthority          string `json:"serverAuthority"`
	FromEpoch                uint64 `json:"fromEpoch"`
	ToEpoch                  uint64 `json:"toEpoch"`
	PriorEdKeyID             string `json:"priorEdKeyId"`
	PriorPQKeyID             string `json:"priorPqKeyId"`
	ActiveEdKeyID            string `json:"activeEdKeyId"`
	ActivePQKeyID            string `json:"activePqKeyId"`
	CheckpointGeneration     uint64 `json:"checkpointGeneration"`
	CheckpointSHA256Hex      string `json:"checkpointSha256Hex"`
	CheckpointIssuedAtMS     int64  `json:"checkpointIssuedAtMs"`
	OwnerID                  string `json:"ownerId"`
	OwnerEdKeyID             string `json:"ownerEdKeyId"`
	OwnerPQKeyID             string `json:"ownerPqKeyId"`
	RequestID                string `json:"requestId"`
}

func validateRetirementRequest(value RetirementRequest) error {
	if value.Schema != retirementRequestSchema || value.NodeID == 0 || value.FromEpoch == 0 ||
		value.FromEpoch == ^uint64(0) || value.ToEpoch != value.FromEpoch+1 ||
		value.CheckpointGeneration == 0 || value.CheckpointIssuedAtMS <= 0 {
		return errors.New("invalid retirement request schema, node, epoch, checkpoint generation or timestamp")
	}
	if _, err := decodeDigest(value.CheckpointSHA256Hex, false); err != nil {
		return fmt.Errorf("invalid retirement request checkpoint digest: %w", err)
	}
	for _, field := range []struct {
		value string
		max   int
	}{
		{value.ServerAuthority, 253},
		{value.PriorEdKeyID, 64},
		{value.PriorPQKeyID, 64},
		{value.ActiveEdKeyID, 64},
		{value.ActivePQKeyID, 64},
		{value.OwnerID, 64},
		{value.OwnerEdKeyID, 64},
		{value.OwnerPQKeyID, 64},
		{value.RequestID, 64},
	} {
		var out bytes.Buffer
		if err := putText(&out, field.value, field.max); err != nil {
			return err
		}
	}
	return nil
}

// BuildRetirementRequest exports only public evidence from an already-existing
// Agent state layout. It deliberately does not need owner private keys and does
// not mutate Agent state. The checkpoint signature is re-verified by the
// offline issuer before an authorization can be created.
func BuildRetirementRequest(checkpoint SignedCheckpoint, layout state.Layout, requestID string) (RetirementRequest, error) {
	if _, err := Canonical(checkpoint.Checkpoint); err != nil {
		return RetirementRequest{}, fmt.Errorf("retirement request checkpoint: %w", err)
	}
	retained, err := state.DescribeRetainedRotation(layout)
	if err != nil {
		return RetirementRequest{}, err
	}
	cp := checkpoint.Checkpoint
	if retained.Purpose != "node_request" || retained.NodeID <= 0 || uint64(retained.NodeID) != cp.NodeID ||
		retained.ToEpoch != cp.KeyEpoch || retained.ActiveEdKeyID != cp.NodeEdKeyID ||
		retained.ActivePQKeyID != cp.NodePQKeyID {
		return RetirementRequest{}, errors.New("retained Agent rotation does not match recovery checkpoint")
	}
	digest, err := CheckpointDigest(cp)
	if err != nil {
		return RetirementRequest{}, err
	}
	request := RetirementRequest{
		Schema:                   retirementRequestSchema,
		NodeID:                   cp.NodeID,
		ServerAuthority:          cp.ServerAuthority,
		FromEpoch:                retained.FromEpoch,
		ToEpoch:                  retained.ToEpoch,
		PriorEdKeyID:             retained.PriorEdKeyID,
		PriorPQKeyID:             retained.PriorPQKeyID,
		ActiveEdKeyID:            retained.ActiveEdKeyID,
		ActivePQKeyID:            retained.ActivePQKeyID,
		CheckpointGeneration:     cp.Generation,
		CheckpointSHA256Hex:      digest,
		CheckpointIssuedAtMS:     cp.IssuedAtMS,
		OwnerID:                  cp.OwnerID,
		OwnerEdKeyID:             cp.OwnerEdKeyID,
		OwnerPQKeyID:             cp.OwnerPQKeyID,
		RequestID:                requestID,
	}
	if err = validateRetirementRequest(request); err != nil {
		return RetirementRequest{}, err
	}
	return request, nil
}

func DecodeRetirementRequest(raw []byte) (RetirementRequest, error) {
	if len(raw) == 0 || len(raw) > 16*1024 {
		return RetirementRequest{}, errors.New("retirement request size invalid")
	}
	if err := uniqueJSONFields(raw); err != nil {
		return RetirementRequest{}, err
	}
	var request RetirementRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return RetirementRequest{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return RetirementRequest{}, errors.New("trailing retirement request bytes")
	}
	if err := validateRetirementRequest(request); err != nil {
		return RetirementRequest{}, err
	}
	return request, nil
}

func OwnerPublicFromPrivate(ownerID string, edPrivate ed25519.PrivateKey, pqPrivate *mldsa.PrivateKey) (OwnerPublic, error) {
	if ownerID == "" || len(edPrivate) != ed25519.PrivateKeySize || pqPrivate == nil {
		return OwnerPublic{}, errors.New("owner recovery private identity is incomplete")
	}
	edPublic, ok := edPrivate.Public().(ed25519.PublicKey)
	if !ok || len(edPublic) != ed25519.PublicKeySize {
		return OwnerPublic{}, errors.New("owner Ed25519 private key is invalid")
	}
	pqPublic := pqPrivate.PublicKey().Bytes()
	if len(pqPublic) != mldsa.MLDSA65PublicKeySize {
		return OwnerPublic{}, errors.New("owner PQ private key is not ML-DSA-65")
	}
	return OwnerPublic{
		OwnerID:  ownerID,
		Purpose:  ownerPurpose,
		EdKeyID:  keyID("ed-", edPublic),
		PQKeyID:  keyID("pq-", pqPublic),
		EdPublic: append([]byte(nil), edPublic...),
		PQPublic: append([]byte(nil), pqPublic...),
	}, nil
}

// IssueRetirementAuthorization is intended for an offline owner tool. It
// re-verifies the signed off-host checkpoint using public keys derived from the
// supplied owner private keys before it signs the public-only retirement
// request. It never opens or mutates Agent state.
func IssueRetirementAuthorization(request RetirementRequest, checkpoint SignedCheckpoint,
	edPrivate ed25519.PrivateKey, pqPrivate *mldsa.PrivateKey, nowMS, lifetimeMS int64,
) (SignedRetirementAuthorization, error) {
	if err := validateRetirementRequest(request); err != nil {
		return SignedRetirementAuthorization{}, err
	}
	if lifetimeMS <= 0 || lifetimeMS > 300000 || nowMS <= 0 || nowMS > int64(^uint64(0)>>1)-lifetimeMS {
		return SignedRetirementAuthorization{}, errors.New("invalid retirement authorization issue time or lifetime")
	}
	cp := checkpoint.Checkpoint
	pin, err := OwnerPublicFromPrivate(cp.OwnerID, edPrivate, pqPrivate)
	if err != nil {
		return SignedRetirementAuthorization{}, err
	}
	if err = VerifySignature(checkpoint, pin); err != nil {
		return SignedRetirementAuthorization{}, fmt.Errorf("offline retirement checkpoint verification: %w", err)
	}
	digest, err := CheckpointDigest(cp)
	if err != nil {
		return SignedRetirementAuthorization{}, err
	}
	if request.CheckpointGeneration != cp.Generation || request.CheckpointSHA256Hex != digest ||
		request.CheckpointIssuedAtMS != cp.IssuedAtMS || request.NodeID != cp.NodeID ||
		request.ServerAuthority != cp.ServerAuthority || request.ToEpoch != cp.KeyEpoch ||
		request.ActiveEdKeyID != cp.NodeEdKeyID || request.ActivePQKeyID != cp.NodePQKeyID ||
		request.OwnerID != cp.OwnerID || request.OwnerEdKeyID != cp.OwnerEdKeyID ||
		request.OwnerPQKeyID != cp.OwnerPQKeyID {
		return SignedRetirementAuthorization{}, errors.New("retirement request is not bound to the verified recovery checkpoint")
	}
	if nowMS < cp.IssuedAtMS {
		return SignedRetirementAuthorization{}, errors.New("retirement authorization cannot predate recovery checkpoint")
	}
	authorization := RetirementAuthorization{
		NodeID:               request.NodeID,
		ServerAuthority:      request.ServerAuthority,
		FromEpoch:            request.FromEpoch,
		ToEpoch:              request.ToEpoch,
		PriorEdKeyID:         request.PriorEdKeyID,
		PriorPQKeyID:         request.PriorPQKeyID,
		ActiveEdKeyID:        request.ActiveEdKeyID,
		ActivePQKeyID:        request.ActivePQKeyID,
		CheckpointGeneration: request.CheckpointGeneration,
		CheckpointSHA256Hex:  request.CheckpointSHA256Hex,
		IssuedAtMS:           nowMS,
		ExpiresAtMS:          nowMS + lifetimeMS,
		RequestID:            request.RequestID,
		OwnerID:              request.OwnerID,
		OwnerEdKeyID:         request.OwnerEdKeyID,
		OwnerPQKeyID:         request.OwnerPQKeyID,
	}
	return SignRetirementAuthorization(authorization, edPrivate, pqPrivate)
}
