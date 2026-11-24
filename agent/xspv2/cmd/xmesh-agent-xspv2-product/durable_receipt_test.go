package main

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func signedPanelEnvelopeForTest(t *testing.T, issuedAtMS int64) ([]byte, productConfig, string) {
	request := strings.Repeat("a", 32)
	raw, cfg := signTestPanelPayload(t, issuedAtMS, "panel.product.activation-receipt",
		"/api/v2/product/activate", request, strings.Repeat("b", 40), []byte(`{"schema":"test"}`))
	return raw, cfg, request
}

func signTestPanelPayload(t *testing.T, issuedAtMS int64, messageType, path, requestID, revision string,
	payload []byte) ([]byte, productConfig) {
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
	edHash := sha256.Sum256(edPublic)
	pqHash := sha256.Sum256(pqPublic)
	cfg := productConfig{
		NodeID: 1,
		PanelPin: panelPin{
			IssuerID:         "xmesh-nexus-panel",
			Ed25519KeyID:     "ed-" + hex.EncodeToString(edHash[:12]),
			MLDSA65KeyID:     "pq-" + hex.EncodeToString(pqHash[:12]),
			Ed25519PublicB64: b64.EncodeToString(edPublic),
			MLDSA65PublicB64: b64.EncodeToString(pqPublic),
		},
	}
	env := envelope{
		Protocol:     "XSP/2",
		Suite:        suite,
		Direction:    2,
		MessageType:  messageType,
		IssuerID:     cfg.PanelPin.IssuerID,
		NodeID:       cfg.NodeID,
		Method:       "POST",
		Path:         path,
		Ed25519KeyID: cfg.PanelPin.Ed25519KeyID,
		MLDSA65KeyID: cfg.PanelPin.MLDSA65KeyID,
		KeyEpoch:     1,
		IssuedAtMS:   issuedAtMS,
		ExpiresAtMS:  issuedAtMS + 120000,
		NonceHex:     strings.Repeat("0", 32),
		RequestID:    requestID,
		Revision:     revision,
		PayloadB64:   b64.EncodeToString(payload),
	}
	input, err := signingInput(env, payload)
	if err != nil {
		t.Fatal(err)
	}
	edSignature := ed25519.Sign(edPrivate, input)
	pqSignature, err := pqPrivate.Sign(nil, input, nil)
	if err != nil {
		t.Fatal(err)
	}
	env.Signatures = signatures{
		Ed25519: b64.EncodeToString(edSignature),
		MLDSA65: b64.EncodeToString(pqSignature),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return raw, cfg
}

func TestDurableActivationReceiptSurvivesNetworkFreshnessWindow(t *testing.T) {
	raw, cfg, requestID := signedPanelEnvelopeForTest(t, time.Now().Add(-10*time.Minute).UnixMilli())

	if _, err := verifyPanelEnvelope(raw, cfg, "panel.product.activation-receipt", "/api/v2/product/activate", requestID); err == nil {
		t.Fatal("historical receipt unexpectedly passed live response freshness")
	}
	if _, err := verifyDurablePanelEnvelope(raw, cfg, "panel.product.activation-receipt", "/api/v2/product/activate", requestID); err != nil {
		t.Fatalf("durable receipt should remain cryptographically verifiable: %v", err)
	}
	if _, err := verifyDurablePanelEnvelope(raw, cfg, "panel.product.activation-receipt", "/api/v2/product/activate", strings.Repeat("c", 32)); err == nil {
		t.Fatal("durable receipt accepted the wrong request binding")
	}
}

func TestLivePanelResponseStillRequiresFreshness(t *testing.T) {
	raw, cfg, requestID := signedPanelEnvelopeForTest(t, time.Now().UnixMilli())
	if _, err := verifyPanelEnvelope(raw, cfg, "panel.product.activation-receipt", "/api/v2/product/activate", requestID); err != nil {
		t.Fatalf("fresh signed panel response rejected: %v", err)
	}
}
