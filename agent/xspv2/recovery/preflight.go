package recovery

import (
	"errors"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
)

// VerifyDurableAgentPreflight performs the earliest read-only P0-E3a check.
// It authenticates the owner/off-host checkpoint and compares its exact Node,
// server authority, epoch and active Ed25519/ML-DSA-65 key IDs with the real
// durable Agent vault before any receipt reload, recovery exchange or network
// operation is attempted.
//
// This function never creates, rotates, repairs or retires keys and never
// changes an epoch/replay floor. Full recovery acceptance still requires
// EvidenceFromDurableAgent plus VerifyLocal against current Nexus evidence.
func VerifyDurableAgentPreflight(signed SignedCheckpoint, pin OwnerPublic,
	layout state.Layout, serverAuthority string, minimumGeneration uint64,
) error {
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
	if serverAuthority == "" || checkpoint.ServerAuthority != serverAuthority {
		return errors.New("authenticated server authority differs from owner recovery checkpoint")
	}
	snapshot, err := state.DescribeCurrent(layout)
	if err != nil {
		return err
	}
	if snapshot.NodeID <= 0 || uint64(snapshot.NodeID) != checkpoint.NodeID ||
		snapshot.KeyEpoch != checkpoint.KeyEpoch || snapshot.EdKeyID != checkpoint.NodeEdKeyID ||
		snapshot.PQKeyID != checkpoint.NodePQKeyID || !snapshot.PreviousRetained || !snapshot.CandidateRetained {
		return errors.New("durable Agent identity is older than or different from owner recovery checkpoint")
	}
	return nil
}
