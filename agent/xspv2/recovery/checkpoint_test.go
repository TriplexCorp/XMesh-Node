package recovery

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
)

func ownerPair(t *testing.T) (ed25519.PrivateKey, *mldsa.PrivateKey, OwnerPublic) {
	t.Helper()
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqPrivate, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	pqPublic := pqPrivate.PublicKey().Bytes()
	pin := OwnerPublic{
		OwnerID:  "owner-offhost-1",
		Purpose:  ownerPurpose,
		EdKeyID:  keyID("ed-", edPublic),
		PQKeyID:  keyID("pq-", pqPublic),
		EdPublic: edPublic,
		PQPublic: pqPublic,
	}
	return edPrivate, pqPrivate, pin
}

func localEvidence(epoch uint64, requestID string, receipt []byte, edID, pqID string) LocalEvidence {
	receiptDigest := shaHex(receipt)
	return LocalEvidence{
		NodeID:          42,
		ServerAuthority: "nexus-recovery.example.invalid",
		KeyEpoch:        epoch,
		NodeEdKeyID:     edID,
		NodePQKeyID:     pqID,
		CommitRequestID: requestID,
		CommitReceipt:   append([]byte(nil), receipt...),
		Nexus: NexusState{
			NodeID:           42,
			KeyEpoch:         epoch,
			RequestID:        requestID,
			PermitState:      "ack_verified",
			ReceiptSHA256Hex: receiptDigest,
			OutboxCount:      1,
			ReplayNonceCount: epoch,
		},
	}
}

func checkpointFor(t *testing.T, generation uint64, previous string, local LocalEvidence, pin OwnerPublic) Checkpoint {
	t.Helper()
	nexusDigest, err := NexusStateDigest(local.Nexus)
	if err != nil {
		t.Fatal(err)
	}
	return Checkpoint{
		Generation:                  generation,
		PreviousCheckpointSHA256Hex: previous,
		NodeID:                      local.NodeID,
		ServerAuthority:             local.ServerAuthority,
		KeyEpoch:                    local.KeyEpoch,
		NodeEdKeyID:                 local.NodeEdKeyID,
		NodePQKeyID:                 local.NodePQKeyID,
		CommitRequestID:             local.CommitRequestID,
		CommitReceiptSHA256Hex:      shaHex(local.CommitReceipt),
		NexusStateSHA256Hex:         nexusDigest,
		IssuedAtMS:                  1793268000000 + int64(generation),
		OwnerID:                     pin.OwnerID,
		OwnerEdKeyID:                pin.EdKeyID,
		OwnerPQKeyID:                pin.PQKeyID,
	}
}

func TestOwnerRecoveryCheckpointDetectsCoordinatedRollback(t *testing.T) {
	edPrivate, pqPrivate, pin := ownerPair(t)
	oldLocal := localEvidence(1, "req-old", []byte("old-authoritative-dual-signed-receipt"), "ed-node-old", "pq-node-old")
	currentLocal := localEvidence(2, "req-current", []byte("current-authoritative-dual-signed-receipt"), "ed-node-current", "pq-node-current")

	genesis := checkpointFor(t, 1, strings.Repeat("0", 64), oldLocal, pin)
	signedGenesis, err := Sign(genesis, edPrivate, pqPrivate)
	if err != nil {
		t.Fatal(err)
	}
	genesisDigest, err := CheckpointDigest(genesis)
	if err != nil {
		t.Fatal(err)
	}
	current := checkpointFor(t, 2, genesisDigest, currentLocal, pin)
	signedCurrent, err := Sign(current, edPrivate, pqPrivate)
	if err != nil {
		t.Fatal(err)
	}

	if err = VerifySuccessor(signedGenesis, signedCurrent, pin); err != nil {
		t.Fatalf("valid monotonic checkpoint successor rejected: %v", err)
	}
	if err = VerifyLocal(signedCurrent, pin, currentLocal, 2); err != nil {
		t.Fatalf("current Agent/Nexus state rejected: %v", err)
	}
	if err = VerifyLocal(signedCurrent, pin, oldLocal, 2); err == nil {
		t.Fatal("coordinated old Agent + Nexus state accepted against newer off-host checkpoint")
	}
	if err = VerifyLocal(signedGenesis, pin, oldLocal, 2); err == nil {
		t.Fatal("rolled-back checkpoint accepted below independent generation floor")
	}

	before := string(oldLocal.CommitReceipt)
	_ = VerifyLocal(signedCurrent, pin, oldLocal, 2)
	if string(oldLocal.CommitReceipt) != before {
		t.Fatal("failed recovery verification mutated local security evidence")
	}
}

func TestOwnerRecoveryCheckpointRejectsTamperingAndCrossDomainMismatch(t *testing.T) {
	edPrivate, pqPrivate, pin := ownerPair(t)
	local := localEvidence(7, "req-7", []byte("receipt-7"), "ed-node-7", "pq-node-7")
	checkpoint := checkpointFor(t, 1, strings.Repeat("0", 64), local, pin)
	signed, err := Sign(checkpoint, edPrivate, pqPrivate)
	if err != nil {
		t.Fatal(err)
	}

	bad := signed
	bad.Checkpoint.ServerAuthority = "other.example.invalid"
	if err = VerifyLocal(bad, pin, local, 1); err == nil {
		t.Fatal("post-signature authority tampering accepted")
	}
	bad = signed
	bad.Signatures.MLDSA65 = ""
	if err = VerifySignature(bad, pin); err == nil {
		t.Fatal("missing ML-DSA-65 owner signature accepted")
	}
	badPin := pin
	badPin.Purpose = "panel_response"
	if err = VerifySignature(signed, badPin); err == nil {
		t.Fatal("wrong owner recovery key purpose accepted")
	}

	mismatch := local
	mismatch.Nexus.KeyEpoch++
	if err = VerifyLocal(signed, pin, mismatch, 1); err == nil {
		t.Fatal("Agent/Nexus epoch disagreement accepted")
	}
	mismatch = local
	mismatch.Nexus.ReceiptSHA256Hex = shaHex([]byte("different-server-receipt"))
	if err = VerifyLocal(signed, pin, mismatch, 1); err == nil {
		t.Fatal("Agent/Nexus receipt disagreement accepted")
	}
	mismatch = local
	mismatch.CommitReceipt = []byte("rolled-back-agent-receipt")
	if err = VerifyLocal(signed, pin, mismatch, 1); err == nil {
		t.Fatal("rolled-back Agent receipt accepted")
	}
}

func TestRecoveryCheckpointDecodeRejectsAmbiguity(t *testing.T) {
	edPrivate, pqPrivate, pin := ownerPair(t)
	local := localEvidence(2, "req-2", []byte("receipt-2"), "ed-node-2", "pq-node-2")
	checkpoint := checkpointFor(t, 1, strings.Repeat("0", 64), local, pin)
	signed, err := Sign(checkpoint, edPrivate, pqPrivate)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(raw)
	if err != nil {
		t.Fatalf("valid checkpoint JSON rejected: %v", err)
	}
	if err = VerifySignature(decoded, pin); err != nil {
		t.Fatalf("decoded checkpoint signature rejected: %v", err)
	}

	duplicate := strings.Replace(string(raw), `"generation":1`, `"generation":1,"generation":1`, 1)
	if _, err = Decode([]byte(duplicate)); err == nil {
		t.Fatal("duplicate checkpoint field accepted")
	}
	unknown := strings.Replace(string(raw), `"checkpoint":{`, `"checkpoint":{"unexpected":1,`, 1)
	if _, err = Decode([]byte(unknown)); err == nil {
		t.Fatal("unknown checkpoint field accepted")
	}
}

func TestEvidenceFromAgentRequiresDurableAppliedState(t *testing.T) {
	local := localEvidence(4, "req-4", []byte("receipt-4"), "ed-node-4", "pq-node-4")
	snapshot := state.SecuritySnapshot{
		NodeID:            42,
		KeyEpoch:          4,
		EdKeyID:           "ed-node-4",
		PQKeyID:           "pq-node-4",
		PreviousRetained:  true,
		CandidateRetained: true,
	}
	evidence, err := EvidenceFromAgent(snapshot, local.ServerAuthority, local.CommitRequestID, local.CommitReceipt, local.Nexus)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.NodeID != local.NodeID || evidence.KeyEpoch != local.KeyEpoch || evidence.NodeEdKeyID != local.NodeEdKeyID {
		t.Fatal("durable Agent evidence mapping changed security identity")
	}
	snapshot.CandidateRetained = false
	if _, err = EvidenceFromAgent(snapshot, local.ServerAuthority, local.CommitRequestID, local.CommitReceipt, local.Nexus); err == nil {
		t.Fatal("recovery evidence accepted without retained authenticated candidate")
	}
}
