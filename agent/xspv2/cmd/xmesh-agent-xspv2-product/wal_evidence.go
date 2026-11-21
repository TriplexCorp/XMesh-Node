package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"

	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

const walWitnessDomain = "XMESH_QUOTA_V2_OFFHOST_WAL_BIRTH_WITNESS_V1\x00"

func walWitnessMessage(payload []byte, nodeID int64) ([]byte, error) {
	var identity struct {
		SchemaVersion int    `json:"schemaVersion"`
		Kind          string `json:"kind"`
		NodeID        int64  `json:"nodeId"`
	}
	if len(payload) == 0 || len(payload) > 4096 || checkUniqueJSONKeys(payload) != nil ||
		json.Unmarshal(payload, &identity) != nil || identity.SchemaVersion != 1 ||
		identity.Kind != "xmesh.quota-v2.offhost-wal-birth-witness" ||
		nodeID <= 0 || identity.NodeID != nodeID {
		return nil, errors.New("invalid or foreign WAL witness payload")
	}
	return append([]byte(walWitnessDomain), payload...), nil
}

// Sign the specific WAL evidence domain using the enrolled product key.
// The local compatibility key must never sign product evidence.
func walEvidence(panel string, nodeID int64, payloadPath string) error {
	if err := verifyActive(panel, nodeID); err != nil {
		return err
	}
	keys, bundle, err := keyring.Open(vaultFile, masterFile)
	if err != nil {
		return err
	}
	if bundle.NodeID != nodeID || bundle.Purpose != "node_request" || len(bundle.EdPublic) != ed25519.PublicKeySize {
		return errors.New("unexpected WAL witness key identity")
	}
	receipt, err := strictFile(activationReceipt, 0o600)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(receipt)
	result := map[string]any{
		"nodeId": bundle.NodeID, "publicKey": hex.EncodeToString(bundle.EdPublic),
		"activationReceiptSha256": hex.EncodeToString(digest[:]),
	}
	if payloadPath != "" {
		payload, err := strictFile(payloadPath, 0o600)
		if err != nil {
			return err
		}
		message, err := walWitnessMessage(payload, nodeID)
		if err != nil {
			return err
		}
		signature, _, err := keys.Sign(message)
		if err != nil {
			return err
		}
		result["signature"] = hex.EncodeToString(signature)
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}
