//go:build linux

package observability

import (
	"fmt"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

const Schema = "xsp2-node-observability-1"

type KeyIDs struct {
	Ed25519 string `json:"ed25519"`
	MLDSA65 string `json:"mlDsa65"`
}

type RetainedState struct {
	Previous  bool `json:"previous"`
	Candidate bool `json:"candidate"`
}

type RetirementState struct {
	Present      bool    `json:"present"`
	FromEpoch    uint64  `json:"fromEpoch,omitempty"`
	ToEpoch      uint64  `json:"toEpoch,omitempty"`
	PriorKeyIDs  *KeyIDs `json:"priorKeyIds,omitempty"`
	ActiveKeyIDs *KeyIDs `json:"activeKeyIds,omitempty"`
}

type LocalSnapshot struct {
	Schema              string          `json:"schema"`
	NodeID              int64           `json:"nodeId"`
	KeyEpoch            uint64          `json:"keyEpoch"`
	ActiveKeyIDs        KeyIDs          `json:"activeKeyIds"`
	Retained            RetainedState   `json:"retained"`
	Retirement          RetirementState `json:"retirement"`
	ReadOnly            bool            `json:"readOnly"`
	ProductionActivated bool            `json:"productionActivated"`
	StrictPQEnabled     bool            `json:"strictPQEnabled"`
}

// Snapshot re-opens the already-existing durable Agent state and returns only
// bounded non-secret metadata. It never initializes, rotates, repairs, retires,
// rewrites or removes security state. Public-key bytes, private material,
// authorization digests and cutover journal payloads are deliberately absent.
func Snapshot(root string) (LocalSnapshot, error) {
	layout, err := state.Open(root)
	if err != nil {
		return LocalSnapshot{}, fmt.Errorf("open durable Agent state: %w", err)
	}
	current, err := state.DescribeCurrent(layout)
	if err != nil {
		return LocalSnapshot{}, fmt.Errorf("describe durable Agent state: %w", err)
	}
	record, present, err := keyring.DescribeRetirement(layout.Vault, layout.MasterKey)
	if err != nil {
		return LocalSnapshot{}, fmt.Errorf("describe retirement floor: %w", err)
	}

	result := LocalSnapshot{
		Schema:   Schema,
		NodeID:   current.NodeID,
		KeyEpoch: current.KeyEpoch,
		ActiveKeyIDs: KeyIDs{
			Ed25519: current.EdKeyID,
			MLDSA65: current.PQKeyID,
		},
		Retained: RetainedState{
			Previous:  current.PreviousRetained,
			Candidate: current.CandidateRetained,
		},
		Retirement: RetirementState{Present: present},
		ReadOnly:   true,
	}
	if present {
		result.Retirement.FromEpoch = record.FromEpoch
		result.Retirement.ToEpoch = record.ToEpoch
		result.Retirement.PriorKeyIDs = &KeyIDs{Ed25519: record.PriorEdKeyID, MLDSA65: record.PriorPQKeyID}
		result.Retirement.ActiveKeyIDs = &KeyIDs{Ed25519: record.ActiveEdKeyID, MLDSA65: record.ActivePQKeyID}
	}
	return result, nil
}
