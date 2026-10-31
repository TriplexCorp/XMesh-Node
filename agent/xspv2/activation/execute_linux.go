//go:build linux

// Package activation is the narrow production execution boundary for an
// already-approved XSP-v2 strict-PQ cutover. It does not issue permits, rotate
// keys, bootstrap trust, or provide a legacy fallback.
package activation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/runtime"
	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
	cutover "github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/cutover"
	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

const schema = "xsp2-kvm-vps-node-activation-config-1"
const approvalSchema = "xsp2-kvm-vps-strict-pq-activation-approval-1"

type Mode string

const (
	ModeActivate Mode = "activate"
	ModeRecover  Mode = "recover"
)

type Config struct {
	Schema         string         `json:"schema"`
	StateRoot      string         `json:"stateRoot"`
	ApprovalFile   string         `json:"approvalFile"`
	ApprovalSHA256 string         `json:"approvalSha256"`
	Endpoint       EndpointConfig `json:"endpoint"`
	TLS            TLSConfig      `json:"tls"`
	PanelPin       PanelPinConfig `json:"panelPin"`
	ExpectedPermit ExpectedPermit `json:"expectedPermit"`
}

type EndpointConfig struct {
	Address    string `json:"address"`
	ServerName string `json:"serverName"`
}

type TLSConfig struct {
	RootCAFile          string `json:"rootCaFile"`
	ClientCertificate  string `json:"clientCertificateFile"`
	ClientPrivateKey   string `json:"clientPrivateKeyFile"`
}

type PanelPinConfig struct {
	IssuerID        string `json:"issuerId"`
	Ed25519KeyID    string `json:"ed25519KeyId"`
	MLDSA65KeyID    string `json:"mldsa65KeyId"`
	Ed25519Public   string `json:"ed25519PublicB64"`
	MLDSA65Public   string `json:"mldsa65PublicB64"`
}

type ExpectedPermit struct {
	NodeID              uint64 `json:"nodeId"`
	FromEpoch           uint64 `json:"fromEpoch"`
	ToEpoch             uint64 `json:"toEpoch"`
	RequestID           string `json:"requestId"`
	FromEdKeyID         string `json:"fromEdKeyId"`
	FromPQKeyID         string `json:"fromPQKeyId"`
	ToEdKeyID           string `json:"toEdKeyId"`
	ToPQKeyID           string `json:"toPQKeyId"`
	CandidateSHA256Hex  string `json:"candidateSha256Hex"`
}

type approvalDocument struct {
	Schema          string `json:"schema"`
	DeploymentClass string `json:"deploymentClass"`
	ReleaseCandidate struct {
		NexusRuntimeRevision string `json:"nexusRuntimeRevision"`
		NodeRevision         string `json:"nodeRevision"`
		NexusImageSHA256     string `json:"nexusImageSha256"`
		AgentArtifactSHA256  string `json:"agentArtifactSha256"`
	} `json:"releaseCandidate"`
	Evidence struct {
		IndependentSecurityReviewAccepted       bool `json:"independentSecurityReviewAccepted"`
		KVMVPSDurabilityQualificationAccepted  bool `json:"kvmVpsDurabilityQualificationAccepted"`
		ProviderStorageRiskAccepted             bool `json:"providerStorageRiskAccepted"`
		FinalCanaryPassed                       bool `json:"finalCanaryPassed"`
		RolloutPlanReviewed                     bool `json:"rolloutPlanReviewed"`
		IndependentSecurityReviewResultSHA256   string `json:"independentSecurityReviewResultSha256"`
		KVMVPSDurabilityResultSHA256            string `json:"kvmVpsDurabilityResultSha256"`
		FinalCanaryResultSHA256                 string `json:"finalCanaryResultSha256"`
		RolloutPlanSHA256                       string `json:"rolloutPlanSha256"`
		RolloutPlanReviewSHA256                 string `json:"rolloutPlanReviewSha256"`
	} `json:"evidence"`
	Scope struct {
		Mode       string   `json:"mode"`
		Nodes      []string `json:"nodes"`
		ValidFrom  string   `json:"validFrom"`
		ValidUntil string   `json:"validUntil"`
	} `json:"scope"`
	TransportPolicy struct {
		TLSProtocols              []string `json:"tlsProtocols"`
		KeyExchange               string   `json:"keyExchange"`
		ClientIdentity            string   `json:"clientIdentity"`
		CriticalMessageSignatures []string `json:"criticalMessageSignatures"`
		AutomaticFallback         bool     `json:"automaticFallback"`
		ClassicalOnlyAllowed      bool     `json:"classicalOnlyAllowed"`
	} `json:"transportPolicy"`
	Decision struct {
		StrictPQAction      string `json:"strictPqAction"`
		LegacyXMESH1Action string `json:"legacyXMESH1Action"`
	} `json:"decision"`
	Approval struct {
		Authority  string `json:"authority"`
		ApprovedBy string `json:"approvedBy"`
		ApprovedAt string `json:"approvedAt"`
		Statement  string `json:"statement"`
	} `json:"approval"`
	Claims struct {
		ProductionActivation       bool `json:"productionActivation"`
		StrictPQEnabled            bool `json:"strictPQEnabled"`
		LegacyXMESH1Retired        bool `json:"legacyXMESH1Retired"`
		PhysicalPowerLossQualified bool `json:"physicalPowerLossQualified"`
	} `json:"claims"`
}

type Result struct {
	Status             string `json:"status"`
	Mode               Mode   `json:"mode"`
	NodeID             uint64 `json:"nodeId"`
	ApprovalSHA256     string `json:"approvalSha256"`
	ReceiptSHA256      string `json:"receiptSha256"`
	MinimumEpoch       uint64 `json:"minimumEpoch"`
	StrictPQEnabled    bool   `json:"strictPQEnabled"`
	LegacyXMESH1Retired bool  `json:"legacyXMESH1Retired"`
}

func decodeStrict(path string, limit int64, out any) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil { return nil, err }
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("activation input must be a bounded, non-writable regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil { return nil, err }
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(out); err != nil { return nil, err }
	if err = decoder.Decode(new(any)); err != io.EOF { return nil, errors.New("trailing JSON data") }
	return raw, nil
}

func shaHex(raw []byte) string {
	d := sha256.Sum256(raw)
	return hex.EncodeToString(d[:])
}

func canonicalSHA(value string) bool {
	if len(value) != 64 || strings.Trim(value, "0") == "" { return false }
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func canonicalRevision(value string) bool {
	if len(value) != 40 { return false }
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil { return time.Time{}, err }
	return parsed.UTC(), nil
}

func containsNode(nodes []string, nodeID uint64) bool {
	want := fmt.Sprintf("%d", nodeID)
	for _, node := range nodes {
		if node == want || node == "node-"+want { return true }
	}
	return false
}

func validateApproval(raw []byte, value approvalDocument, expectedSHA, sourceRevision, artifactSHA string, nodeID uint64, now time.Time) error {
	if value.Schema != approvalSchema || value.DeploymentClass != "kvm-vps" {
		return errors.New("approval schema/deployment class mismatch")
	}
	if !canonicalSHA(expectedSHA) || shaHex(raw) != expectedSHA {
		return errors.New("approval SHA-256 mismatch")
	}
	if !canonicalRevision(sourceRevision) || value.ReleaseCandidate.NodeRevision != sourceRevision {
		return errors.New("approval Node revision does not match embedded Agent source revision")
	}
	if !canonicalSHA(artifactSHA) || value.ReleaseCandidate.AgentArtifactSHA256 != artifactSHA {
		return errors.New("approval Agent artifact SHA-256 does not match executing binary")
	}
	if !canonicalRevision(value.ReleaseCandidate.NexusRuntimeRevision) || !strings.HasPrefix(value.ReleaseCandidate.NexusImageSHA256, "sha256:") || !canonicalSHA(strings.TrimPrefix(value.ReleaseCandidate.NexusImageSHA256, "sha256:")) {
		return errors.New("approval release-candidate binding invalid")
	}
	if !(value.Evidence.IndependentSecurityReviewAccepted && value.Evidence.KVMVPSDurabilityQualificationAccepted && value.Evidence.ProviderStorageRiskAccepted && value.Evidence.FinalCanaryPassed && value.Evidence.RolloutPlanReviewed) {
		return errors.New("approval evidence is incomplete")
	}
	for _, digest := range []string{value.Evidence.IndependentSecurityReviewResultSHA256, value.Evidence.KVMVPSDurabilityResultSHA256, value.Evidence.FinalCanaryResultSHA256, value.Evidence.RolloutPlanSHA256, value.Evidence.RolloutPlanReviewSHA256} {
		if !canonicalSHA(digest) { return errors.New("approval evidence digest invalid") }
	}
	if value.Scope.Mode != "limited-canary" && value.Scope.Mode != "phased" { return errors.New("approval scope mode invalid") }
	if len(value.Scope.Nodes) == 0 || len(value.Scope.Nodes) > 50 || !containsNode(value.Scope.Nodes, nodeID) { return errors.New("Node is outside approval scope") }
	start, err := parseTime(value.Scope.ValidFrom); if err != nil { return errors.New("approval validFrom invalid") }
	end, err := parseTime(value.Scope.ValidUntil); if err != nil { return errors.New("approval validUntil invalid") }
	if !end.After(start) || end.Sub(start) > 24*time.Hour || now.Before(start) || now.After(end) { return errors.New("approval is outside its bounded validity window") }
	if len(value.TransportPolicy.TLSProtocols) != 1 || value.TransportPolicy.TLSProtocols[0] != "TLSv1.3" || value.TransportPolicy.KeyExchange != "X25519MLKEM768" || value.TransportPolicy.ClientIdentity != "ML-DSA-65" || len(value.TransportPolicy.CriticalMessageSignatures) != 2 || value.TransportPolicy.CriticalMessageSignatures[0] != "Ed25519" || value.TransportPolicy.CriticalMessageSignatures[1] != "ML-DSA-65" || value.TransportPolicy.AutomaticFallback || value.TransportPolicy.ClassicalOnlyAllowed {
		return errors.New("approval transport policy weakened")
	}
	if value.Decision.StrictPQAction != "enable" || value.Decision.LegacyXMESH1Action != "retain" || value.Approval.Authority != "release-owner" || value.Approval.ApprovedBy == "" || value.Approval.Statement == "" {
		return errors.New("approval decision/authority invalid")
	}
	approvedAt, err := parseTime(value.Approval.ApprovedAt); if err != nil || approvedAt.Before(start) || approvedAt.After(end) { return errors.New("approval timestamp invalid") }
	if value.Claims.ProductionActivation || value.Claims.StrictPQEnabled || value.Claims.LegacyXMESH1Retired || value.Claims.PhysicalPowerLossQualified {
		return errors.New("approval pre-execution claims must remain false")
	}
	return nil
}

func decodeCanonicalB64(value string, exact int) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != exact || base64.StdEncoding.EncodeToString(raw) != value { return nil, errors.New("noncanonical public key") }
	return raw, nil
}

func panelPin(value PanelPinConfig, nodeID uint64) (runtime.Pin, error) {
	ed, err := decodeCanonicalB64(value.Ed25519Public, 32); if err != nil { return runtime.Pin{}, err }
	pq, err := decodeCanonicalB64(value.MLDSA65Public, 1952); if err != nil { return runtime.Pin{}, err }
	if value.IssuerID == "" || value.Ed25519KeyID == "" || value.MLDSA65KeyID == "" { return runtime.Pin{}, errors.New("panel pin identity missing") }
	return runtime.Pin{IssuerID:value.IssuerID, Purpose:"panel_response", NodeID:nodeID, EdKeyID:value.Ed25519KeyID, PQKeyID:value.MLDSA65KeyID, EdPublic:ed, PQPublic:pq}, nil
}

func expectedPermit(value ExpectedPermit) cutover.ExpectedPermit {
	return cutover.ExpectedPermit{NodeID:value.NodeID, FromEpoch:value.FromEpoch, ToEpoch:value.ToEpoch, RequestID:value.RequestID, FromEdKeyID:value.FromEdKeyID, FromPQKeyID:value.FromPQKeyID, ToEdKeyID:value.ToEdKeyID, ToPQKeyID:value.ToPQKeyID, CandidateSHA256Hex:value.CandidateSHA256Hex}
}

func activePin(layout state.Layout) (runtime.Pin, uint64, error) {
	pub, err := keyring.Description(layout.Vault, layout.MasterKey)
	if err != nil { return runtime.Pin{}, 0, err }
	if pub.NodeID <= 0 || pub.KeyEpoch == 0 { return runtime.Pin{}, 0, errors.New("invalid active Node key identity") }
	return runtime.Pin{IssuerID:fmt.Sprintf("node-%d", pub.NodeID), Purpose:pub.Purpose, NodeID:uint64(pub.NodeID), EdKeyID:pub.EdKeyID, PQKeyID:pub.PQKeyID, EdPublic:append([]byte(nil), pub.EdPublic...), PQPublic:append([]byte(nil), pub.PQPublic...)}, pub.KeyEpoch, nil
}

func loadTLS(value TLSConfig) (*x509.CertPool, tls.Certificate, error) {
	ca, err := os.ReadFile(filepath.Clean(value.RootCAFile)); if err != nil { return nil, tls.Certificate{}, err }
	roots := x509.NewCertPool(); if !roots.AppendCertsFromPEM(ca) { return nil, tls.Certificate{}, errors.New("root CA file contained no certificates") }
	cert, err := tls.LoadX509KeyPair(filepath.Clean(value.ClientCertificate), filepath.Clean(value.ClientPrivateKey)); if err != nil { return nil, tls.Certificate{}, err }
	return roots, cert, nil
}

// Execute performs only the final signed-ACK/receipt exchange for a Node whose
// durable key rotation has already been applied. The release approval and the
// exact executing Agent artifact are re-bound before any network I/O.
func Execute(ctx context.Context, mode Mode, configPath, sourceRevision, artifactSHA string, now time.Time) (Result, error) {
	var empty Result
	if ctx == nil || (mode != ModeActivate && mode != ModeRecover) { return empty, errors.New("invalid activation mode/context") }
	var cfg Config
	_, err := decodeStrict(configPath, 128*1024, &cfg); if err != nil { return empty, fmt.Errorf("activation config: %w", err) }
	if cfg.Schema != schema || cfg.StateRoot == "" || cfg.ApprovalFile == "" { return empty, errors.New("activation config schema/paths invalid") }
	layout, err := state.Open(cfg.StateRoot); if err != nil { return empty, err }
	next, minimumEpoch, err := activePin(layout); if err != nil { return empty, err }
	if cfg.ExpectedPermit.NodeID != next.NodeID || cfg.ExpectedPermit.ToEpoch != minimumEpoch || cfg.ExpectedPermit.ToEdKeyID != next.EdKeyID || cfg.ExpectedPermit.ToPQKeyID != next.PQKeyID { return empty, errors.New("approved permit candidate does not match durable active Node state") }
	var approval approvalDocument
	approvalRaw, err := decodeStrict(cfg.ApprovalFile, 256*1024, &approval); if err != nil { return empty, fmt.Errorf("approval: %w", err) }
	if err = validateApproval(approvalRaw, approval, cfg.ApprovalSHA256, sourceRevision, artifactSHA, next.NodeID, now.UTC()); err != nil { return empty, err }
	panel, err := panelPin(cfg.PanelPin, next.NodeID); if err != nil { return empty, err }
	want := expectedPermit(cfg.ExpectedPermit)
	var permit cutover.VerifiedPermit
	if mode == ModeActivate {
		permit, err = cutover.ReloadVerifiedPermit(layout.Journal, panel, want, now.UnixMilli())
	} else {
		permit, err = cutover.ReloadVerifiedPermitForReceiptRecovery(layout.Journal, panel, want, next)
	}
	if err != nil { return empty, fmt.Errorf("verified permit reload: %w", err) }
	roots, clientCertificate, err := loadTLS(cfg.TLS); if err != nil { return empty, err }
	endpoint := runtime.Endpoint{Address:cfg.Endpoint.Address, ServerName:cfg.Endpoint.ServerName}
	var receipt cutover.VerifiedCommitReceipt
	if mode == ModeActivate {
		receipt, err = runtime.Exchange(ctx, endpoint, roots, clientCertificate, layout, panel, permit, next, minimumEpoch, now.UnixMilli())
	} else {
		receipt, err = runtime.Recover(ctx, endpoint, roots, clientCertificate, layout, panel, permit, next, minimumEpoch, now.UnixMilli())
	}
	if err != nil { return empty, err }
	rawReceipt := receipt.Raw()
	return Result{Status:"strict-pq-node-cutover-receipt-verified", Mode:mode, NodeID:next.NodeID, ApprovalSHA256:cfg.ApprovalSHA256, ReceiptSHA256:shaHex(rawReceipt), MinimumEpoch:minimumEpoch, StrictPQEnabled:true, LegacyXMESH1Retired:false}, nil
}
