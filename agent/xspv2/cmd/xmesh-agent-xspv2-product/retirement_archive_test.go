package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	retirement "github.com/TriplexCorp/XMesh-Node/experiments/quota-v2-retirement-attestation"
	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

func retirementJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func retirementTestEnrollment(t *testing.T) (*keyring.VolatileKeys, keyring.PublicBundle, productConfig, []byte, []byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	vault, master := filepath.Join(dir, "request.vault"), filepath.Join(dir, "request.master")
	if err := keyring.CreateMasterKey(master); err != nil {
		t.Fatal(err)
	}
	if _, err := keyring.Initialize(vault, master, 1, "node_request"); err != nil {
		t.Fatal(err)
	}
	keys, pub, err := keyring.Open(vault, master)
	if err != nil {
		t.Fatal(err)
	}
	release := releaseIdentity{Version: "control-v6.0.39", SourceRevision: strings.Repeat("a", 40),
		ArtifactSHA256: strings.Repeat("b", 64)}
	claims := retirementJSON(t, map[string]any{
		"schema": "xmesh-v6-strict-pq-activation-request-1", "nodeId": 1,
		"releaseIdentity": release, "automaticClassicalFallback": false,
	})
	requestID := strings.Repeat("c", 32)
	request, err := makeEnvelope(keys, pub, "node.product.activate", "/api/v2/product/activate", requestID,
		release.SourceRevision, claims)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(request)
	receiptClaims := activationReceiptPayload{
		Schema: "xmesh-v6-strict-pq-activation-receipt-1", NodeID: 1, KeyEpoch: 1,
		RequestBindingSHA256: hex.EncodeToString(h[:]), ProductionActivation: true,
		StrictPQEnabled: true, ActivatedAt: "2026-11-27T04:00:00Z",
	}
	receipt, cfg := signTestPanelPayload(t, time.Now().Add(-time.Hour).UnixMilli(),
		"panel.product.activation-receipt", "/api/v2/product/activate",
		requestID, release.SourceRevision, retirementJSON(t, receiptClaims))
	cfg.ReleaseIdentity = release
	parsed, err := verifySavedActivationRequest(cfg, pub, request)
	if err != nil {
		t.Fatal(err)
	}
	active, err := validateRecoveredActivationReceipt(cfg, request, parsed, receipt)
	if err != nil {
		t.Fatal(err)
	}
	return keys, pub, cfg, append(retirementJSON(t, active), '\n'), request, receipt
}

func retirementTestArchive(t *testing.T, activation string, key ed25519.PrivateKey) []byte {
	t.Helper()
	raw, err := os.ReadFile("../../../../experiments/quota-v2-retirement-attestation/testdata/python_ed25519_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Archive string `json:"archive"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal([]byte(vector.Archive), &record); err != nil {
		t.Fatal(err)
	}
	observation := record["observation"].(map[string]any)
	var outer map[string]any
	if err := json.Unmarshal([]byte(record["nexusResponse"].(string)), &outer); err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal([]byte(outer["signedEnvelope"].(string)), &envelope); err != nil {
		t.Fatal(err)
	}
	payload := envelope["payload"].(map[string]any)
	payload["nodeId"] = 1
	payload["activationReceiptSha256"] = activation
	signing := append([]byte("XMESH_QUOTA_V2_PUBLIC_TLS_WAL_HEAD_V2\x00"), retirementJSON(t, payload)...)
	envelope["signature"] = hex.EncodeToString(ed25519.Sign(key, signing))
	outer["signedEnvelope"] = string(append(retirementJSON(t, envelope), '\n'))
	response := retirementJSON(t, outer)
	h := sha256.Sum256(response)
	observation["nodeId"] = 1
	observation["signedWalReadbackSha256"] = hex.EncodeToString(h[:])
	record["nexusResponse"] = string(response)
	return append(retirementJSON(t, record), '\n')
}

func TestRetirementArchiveUsesOriginalDualSignedEnrollmentAndOpenedVault(t *testing.T) {
	keys, bundle, cfg, active, request, receipt := retirementTestEnrollment(t)
	activation, err := retirementEnrollment(cfg, bundle, active, request, receipt)
	receiptHash := sha256.Sum256(receipt)
	if err != nil || activation != hex.EncodeToString(receiptHash[:]) {
		t.Fatalf("original enrolled identity rejected: %v", err)
	}
	_, foreign, err := keyring.Generate(1, "node_request", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := retirementEnrollment(cfg, foreign, active, request, receipt); err == nil {
		t.Fatal("replacement vault for the same node accepted")
	}
	if _, err := retirementEnrollment(cfg, bundle, append(bytes.Clone(active), ' '), request, receipt); err == nil {
		t.Fatal("changed original active bytes accepted")
	}
	if _, err := retirementEnrollment(cfg, bundle, active, request, append(bytes.Clone(receipt), ' ')); err == nil {
		t.Fatal("changed signed receipt accepted")
	}
	policy, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	archive := retirementTestArchive(t, activation, secret)
	scope := retirement.Scope{NodeID: 1, ActivationReceiptSHA256: activation,
		NodePublicKey: bundle.EdPublic, NexusPublicKey: policy}
	signed := 0
	signer := func(message []byte) ([]byte, error) {
		signed++
		ed, _, err := keys.Sign(message)
		return ed, err
	}
	if _, err := signRetirementArchive(archive, strings.Repeat("f", 64), scope, signer); err == nil || signed != 0 {
		t.Fatal("wrong runtime reached the enrolled signer")
	}
	result, err := signRetirementArchive(archive, strings.Repeat("b", 64), scope, signer)
	if err != nil || signed != 1 || result.Algorithm != "Ed25519" {
		t.Fatalf("enrolled archive signature failed: %v", err)
	}
	sig, err := hex.DecodeString(result.Signature)
	if err != nil || retirement.Verify(archive, scope, sig) != nil {
		t.Fatal("exported signature does not verify against enrolled key")
	}
	message, err := retirement.Message(archive, scope)
	if err != nil || !bytes.Equal(result.Payload, message[len(retirement.Domain):]) {
		t.Fatal("exported payload differs from signed canonical claims")
	}
	scope.NexusPublicKey = foreign.EdPublic
	if _, err := signRetirementArchive(archive, strings.Repeat("b", 64), scope, signer); err == nil || signed != 1 {
		t.Fatal("foreign Nexus pin reached the enrolled signer")
	}
}

func TestRetirementPrivateReadRejectsAliasesModesAndOversize(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	dir, err := openRetirementPrivateDir(path, uid)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	f := filepath.Join(path, "record")
	if err := os.WriteFile(f, []byte("record"), 0600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readRetirementPrivate(dir, "record", 6, uid); err != nil || string(raw) != "record" {
		t.Fatalf("private bounded read failed: %v", err)
	}
	if _, err := readRetirementPrivate(dir, "record", 5, uid); err == nil {
		t.Fatal("oversized record accepted")
	}
	if err := os.Link(f, filepath.Join(path, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := readRetirementPrivate(dir, "record", 6, uid); err == nil {
		t.Fatal("hardlinked record accepted")
	}
	if err := os.Remove(filepath.Join(path, "alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f, filepath.Join(path, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := readRetirementPrivate(dir, "alias", 6, uid); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Chmod(f, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRetirementPrivate(dir, "record", 6, uid); err == nil {
		t.Fatal("world-readable file accepted")
	}
	if _, err := readRetirementPrivate(dir, "../record", 6, uid); err == nil {
		t.Fatal("path escape accepted")
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := readRetirementPrivate(dir, "record", 6, uid); err == nil {
		t.Fatal("changed directory permissions accepted")
	}
}

func TestRetirementRecordAndOriginalPinAreStrict(t *testing.T) {
	runtime := strings.Repeat("a", 64)
	if name, err := retirementRecordName(runtime); err != nil || name != "retired-"+runtime+".json" {
		t.Fatal("canonical runtime name rejected")
	}
	for _, invalid := range []string{"", "../" + runtime, strings.ToUpper(runtime), runtime + "\n"} {
		if _, err := retirementRecordName(invalid); err == nil {
			t.Fatal("noncanonical record name accepted")
		}
	}
	if _, err := retirementPolicyKey([]byte(runtime + "\n")); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{runtime, strings.ToUpper(runtime) + "\n", runtime + " \n"} {
		if _, err := retirementPolicyKey([]byte(invalid)); err == nil {
			t.Fatal("noncanonical policy pin accepted")
		}
	}
}
