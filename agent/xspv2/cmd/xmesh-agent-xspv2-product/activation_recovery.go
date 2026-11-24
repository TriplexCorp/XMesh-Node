package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

const activationRecoveryPath = "/api/v1/node/agent-activation-recovery"

type activationRecoveryRequest struct {
	Schema            string `json:"schema"`
	OriginalRequestID string `json:"originalRequestId"`
	OriginalSHA256    string `json:"originalSha256"`
}

func verifySavedActivationRequest(cfg productConfig, pub keyring.PublicBundle, raw []byte) (parsedEnvelope, error) {
	parsed, err := parseEnvelope(raw, "node.product.activate", "/api/v2/product/activate", 1)
	if err != nil {
		return parsedEnvelope{}, err
	}
	if pub.Purpose != "node_request" || pub.KeyEpoch != 1 || pub.NodeID != cfg.NodeID ||
		parsed.Env.NodeID != cfg.NodeID || parsed.Env.KeyEpoch != 1 ||
		parsed.Env.IssuerID != fmt.Sprintf("xmesh-node-%d", cfg.NodeID) ||
		parsed.Env.Ed25519KeyID != pub.EdKeyID || parsed.Env.MLDSA65KeyID != pub.PQKeyID ||
		parsed.Env.Revision != cfg.ReleaseIdentity.SourceRevision ||
		len(parsed.Env.RequestID) != 32 {
		return parsedEnvelope{}, errors.New("saved activation node, key or release changed")
	}
	if _, err := hex.DecodeString(parsed.Env.RequestID); err != nil {
		return parsedEnvelope{}, errors.New("invalid saved activation request ID")
	}
	if !ed25519.Verify(pub.EdPublic, parsed.SigningInput, parsed.EdSig) {
		return parsedEnvelope{}, errors.New("saved activation Ed25519 signature rejected")
	}
	pqKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pub.PQPublic)
	if err != nil {
		return parsedEnvelope{}, err
	}
	if err := mldsa.Verify(pqKey, parsed.SigningInput, parsed.PQSig, nil); err != nil {
		return parsedEnvelope{}, errors.New("saved activation ML-DSA-65 signature rejected")
	}
	if err := checkUniqueJSONKeys(parsed.Payload); err != nil {
		return parsedEnvelope{}, err
	}
	var claim struct {
		Schema                     string          `json:"schema"`
		NodeID                     int64           `json:"nodeId"`
		ReleaseIdentity            releaseIdentity `json:"releaseIdentity"`
		AutomaticClassicalFallback bool            `json:"automaticClassicalFallback"`
	}
	d := json.NewDecoder(bytes.NewReader(parsed.Payload))
	d.DisallowUnknownFields()
	if err := d.Decode(&claim); err != nil {
		return parsedEnvelope{}, err
	}
	if d.Decode(new(any)) != io.EOF || claim.Schema != "xmesh-v6-strict-pq-activation-request-1" ||
		claim.NodeID != cfg.NodeID || claim.ReleaseIdentity != cfg.ReleaseIdentity ||
		claim.AutomaticClassicalFallback {
		return parsedEnvelope{}, errors.New("saved activation payload does not match enrolled release")
	}
	// The original envelope may now be older than its network freshness
	// window; only an independently fresh, authenticated recovery tunnel
	// can retrieve the exact receipt already committed by Nexus.
	return parsed, nil
}

func recoverActivationResponse(cfg productConfig, requestRaw []byte, parsed parsedEnvelope, responseRaw []byte) error {
	if _, err := os.Lstat(activeFile); err == nil {
		return errors.New("existing active marker cannot be replaced by recovery")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if existing, err := strictFile(activationReceipt, 0600); err == nil {
		if !bytes.Equal(existing, responseRaw) {
			return errors.New("another durable activation receipt already exists")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	active, err := validateRecoveredActivationReceipt(cfg, requestRaw, parsed, responseRaw)
	if err != nil {
		return err
	}
	if err := atomicWrite(activationReceipt, responseRaw, 0600); err != nil {
		return err
	}
	if err := atomicJSON(activeFile, active); err != nil {
		return err
	}
	return verifyActive(cfg.PanelURL, cfg.NodeID)
}

func validateRecoveredActivationReceipt(cfg productConfig, requestRaw []byte, parsed parsedEnvelope, responseRaw []byte) (activeState, error) {
	receiptEnvelope, err := verifyDurablePanelEnvelope(responseRaw, cfg,
		"panel.product.activation-receipt", "/api/v2/product/activate", parsed.Env.RequestID)
	if err != nil {
		return activeState{}, err
	}
	// Nexus persists json.Marshal(envelope), with no padding or alternate
	// encoding. A byte-wise recovery must refuse modified outer JSON even
	// if its structured signed claims still verify (e.g. appended space).
	canonical, err := json.Marshal(receiptEnvelope.Env)
	if err != nil || !bytes.Equal(canonical, responseRaw) {
		return activeState{}, errors.New("recovered activation receipt bytes are not canonical")
	}
	if err := checkUniqueJSONKeys(receiptEnvelope.Payload); err != nil {
		return activeState{}, err
	}
	var receipt activationReceiptPayload
	d := json.NewDecoder(bytes.NewReader(receiptEnvelope.Payload))
	d.DisallowUnknownFields()
	if err := d.Decode(&receipt); err != nil {
		return activeState{}, err
	}
	if d.Decode(new(any)) != io.EOF {
		return activeState{}, errors.New("trailing recovered activation receipt")
	}
	requestHash := sha256.Sum256(requestRaw)
	if receipt.Schema != "xmesh-v6-strict-pq-activation-receipt-1" ||
		receipt.NodeID != cfg.NodeID || receipt.KeyEpoch != 1 ||
		!receipt.ProductionActivation || !receipt.StrictPQEnabled ||
		receipt.AutomaticClassicalFallback ||
		receipt.RequestBindingSHA256 != hex.EncodeToString(requestHash[:]) || receipt.ActivatedAt == "" {
		return activeState{}, errors.New("recovered receipt does not bind the original activation request")
	}
	receiptHash := sha256.Sum256(responseRaw)
	active := activeState{
		Schema: "xmesh-v6-strict-pq-active-1", NodeID: cfg.NodeID,
		KeyEpoch: 1, RequestID: parsed.Env.RequestID,
		RequestBindingSHA256: hex.EncodeToString(requestHash[:]),
		ReceiptSHA256:        hex.EncodeToString(receiptHash[:]),
		ProductionActivation: true, StrictPQEnabled: true,
		AutomaticClassicalFallback: false, ReleaseIdentity: cfg.ReleaseIdentity,
		ActivatedAt: receipt.ActivatedAt,
	}
	return active, nil
}

func recoverLostActivation() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	running, err := identity()
	if err != nil || running != cfg.ReleaseIdentity {
		return errors.New("installed Agent release differs from enrollment")
	}
	if _, err := os.Lstat(activeFile); err == nil {
		// An already-active Agent is verified, not silently rewritten.
		return verifyActive(cfg.PanelURL, cfg.NodeID)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	requestRaw, err := strictFile(activationRequest, 0600)
	if err != nil {
		return err
	}
	_, public, err := keyring.Open(vaultFile, masterFile)
	if err != nil {
		return err
	}
	saved, err := verifySavedActivationRequest(cfg, public, requestRaw)
	if err != nil {
		return err
	}
	// If Nexus's signed receipt reached the disk but SIGKILL occurred before
	// active.json was fsynced, finish locally. The old receipt is sufficient
	// cryptographic evidence even when Nexus is offline. A corrupt or foreign
	// receipt must fail closed; never silently replace it over the network.
	if cached, err := strictFile(activationReceipt, 0600); err == nil {
		return recoverActivationResponse(cfg, requestRaw, saved, cached)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	client, err := hybridClient(cfg)
	if err != nil {
		return err
	}
	// First retry the exact signed request: if the initial enrollment was
	// merely delayed and still fresh, Nexus can commit it once. No new
	// request ID, key or activation claim is ever generated here.
	response, status, directErr := postJSON(client,
		"https://"+cfg.EndpointAddress+"/api/v2/product/activate", requestRaw)
	if directErr == nil && status == http.StatusOK {
		return recoverActivationResponse(cfg, requestRaw, saved, response)
	}
	binding := sha256.Sum256(requestRaw)
	query, err := json.Marshal(activationRecoveryRequest{
		Schema:            "xmesh-product-activation-recovery-v1",
		OriginalRequestID: saved.Env.RequestID,
		OriginalSHA256:    hex.EncodeToString(binding[:]),
	})
	if err != nil {
		return err
	}
	response, status, err = tunnelRequest(cfg, activationRecoveryPath, query)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("original activation is not recoverable: HTTP %d", status)
	}
	return recoverActivationResponse(cfg, requestRaw, saved, response)
}
