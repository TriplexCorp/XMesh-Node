//go:build linux

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
	RootCAFile        string `json:"rootCaFile"`
	ClientCertificate string `json:"clientCertificateFile"`
	ClientPrivateKey  string `json:"clientPrivateKeyFile"`
}

type PanelPinConfig struct {
	IssuerID      string `json:"issuerId"`
	Ed25519KeyID  string `json:"ed25519KeyId"`
	MLDSA65KeyID  string `json:"mldsa65KeyId"`
	Ed25519Public string `json:"ed25519PublicB64"`
	MLDSA65Public string `json:"mldsa65PublicB64"`
}

type ExpectedPermit struct {
	NodeID             uint64 `json:"nodeId"`
	FromEpoch          uint64 `json:"fromEpoch"`
	ToEpoch            uint64 `json:"toEpoch"`
	RequestID          string `json:"requestId"`
	FromEdKeyID        string `json:"fromEdKeyId"`
	FromPQKeyID        string `json:"fromPQKeyId"`
	ToEdKeyID          string `json:"toEdKeyId"`
	ToPQKeyID          string `json:"toPQKeyId"`
	CandidateSHA256Hex string `json:"candidateSha256Hex"`
}

type approvalDocument struct {
	Schema           string `json:"schema"`
	DeploymentClass  string `json:"deploymentClass"`
	ReleaseCandidate struct {
		NexusRuntimeRevision string `json:"nexusRuntimeRevision"`
		NodeRevision         string `json:"nodeRevision"`
		NexusImageSHA256     string `json:"nexusImageSha256"`
		AgentArtifactSHA256  string `json:"agentArtifactSha256"`
	} `json:"releaseCandidate"`
	Evidence struct {
		IndependentSecurityReviewAccepted     bool   `json:"independentSecurityReviewAccepted"`
		IndependentSecurityReviewResultSHA256 string `json:"independentSecurityReviewResultSha256"`
		KVMVPSDurabilityQualificationAccepted bool   `json:"kvmVpsDurabilityQualificationAccepted"`
		KVMVPSDurabilityResultSHA256          string `json:"kvmVpsDurabilityResultSha256"`
		ProviderStorageRiskAccepted           bool   `json:"providerStorageRiskAccepted"`
		FinalCanaryPassed                     bool   `json:"finalCanaryPassed"`
		FinalCanaryResultSHA256               string `json:"finalCanaryResultSha256"`
		RolloutPlanReviewed                   bool   `json:"rolloutPlanReviewed"`
		RolloutPlanSHA256                     string `json:"rolloutPlanSha256"`
		RolloutPlanReviewSHA256               string `json:"rolloutPlanReviewSha256"`
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
		StrictPQAction     string `json:"strictPqAction"`
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
	Status               string `json:"status"`
	Mode                 Mode   `json:"mode"`
	NodeID               uint64 `json:"nodeId"`
	ApprovalSHA256       string `json:"approvalSha256"`
	ReceiptBindingSHA256 string `json:"receiptBindingSha256"`
	MinimumEpoch         uint64 `json:"minimumEpoch"`
	StrictPQEnabled      bool   `json:"strictPQEnabled"`
	LegacyXMESH1Retired  bool   `json:"legacyXMESH1Retired"`
}

func decodeStrict(path string, limit int64, out any) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("activation input must be a bounded, non-writable regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(out); err != nil {
		return nil, err
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing JSON data")
	}
	return raw, nil
}

func shaHex(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func canonicalSHA(v string) bool {
	if len(v) != 64 || strings.Trim(v, "0") == "" || strings.ToLower(v) != v {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}
func canonicalRevision(v string) bool {
	if len(v) != 40 || strings.ToLower(v) != v {
		return false
	}
	_, e := hex.DecodeString(v)
	return e == nil
}
func parseTime(v string) (time.Time, error) {
	p, e := time.Parse(time.RFC3339, v)
	if e != nil {
		return time.Time{}, e
	}
	return p.UTC(), nil
}
func containsNode(nodes []string, nodeID uint64) bool {
	want := fmt.Sprintf("%d", nodeID)
	for _, v := range nodes {
		if v == want || v == "node-"+want {
			return true
		}
	}
	return false
}

func validateApproval(raw []byte, a approvalDocument, expectedSHA, sourceRevision, artifactSHA string, nodeID uint64, now time.Time) error {
	if a.Schema != approvalSchema || a.DeploymentClass != "kvm-vps" {
		return errors.New("approval schema/deployment class mismatch")
	}
	if !canonicalSHA(expectedSHA) || shaHex(raw) != expectedSHA {
		return errors.New("approval SHA-256 mismatch")
	}
	if !canonicalRevision(sourceRevision) || a.ReleaseCandidate.NodeRevision != sourceRevision {
		return errors.New("approval Node revision does not match embedded Agent source revision")
	}
	if !canonicalSHA(artifactSHA) || a.ReleaseCandidate.AgentArtifactSHA256 != artifactSHA {
		return errors.New("approval Agent artifact SHA-256 does not match executing binary")
	}
	if !canonicalRevision(a.ReleaseCandidate.NexusRuntimeRevision) || !strings.HasPrefix(a.ReleaseCandidate.NexusImageSHA256, "sha256:") || !canonicalSHA(strings.TrimPrefix(a.ReleaseCandidate.NexusImageSHA256, "sha256:")) {
		return errors.New("approval release-candidate binding invalid")
	}
	if !(a.Evidence.IndependentSecurityReviewAccepted && a.Evidence.KVMVPSDurabilityQualificationAccepted && a.Evidence.ProviderStorageRiskAccepted && a.Evidence.FinalCanaryPassed && a.Evidence.RolloutPlanReviewed) {
		return errors.New("approval evidence is incomplete")
	}
	for _, d := range []string{a.Evidence.IndependentSecurityReviewResultSHA256, a.Evidence.KVMVPSDurabilityResultSHA256, a.Evidence.FinalCanaryResultSHA256, a.Evidence.RolloutPlanSHA256, a.Evidence.RolloutPlanReviewSHA256} {
		if !canonicalSHA(d) {
			return errors.New("approval evidence digest invalid")
		}
	}
	if a.Scope.Mode != "limited-canary" && a.Scope.Mode != "phased" {
		return errors.New("approval scope mode invalid")
	}
	if len(a.Scope.Nodes) == 0 || len(a.Scope.Nodes) > 50 || !containsNode(a.Scope.Nodes, nodeID) {
		return errors.New("Node is outside approval scope")
	}
	start, e := parseTime(a.Scope.ValidFrom)
	if e != nil {
		return errors.New("approval validFrom invalid")
	}
	end, e := parseTime(a.Scope.ValidUntil)
	if e != nil {
		return errors.New("approval validUntil invalid")
	}
	if !end.After(start) || end.Sub(start) > 24*time.Hour || now.Before(start) || now.After(end) {
		return errors.New("approval is outside its bounded validity window")
	}
	p := a.TransportPolicy
	if len(p.TLSProtocols) != 1 || p.TLSProtocols[0] != "TLSv1.3" || p.KeyExchange != "X25519MLKEM768" || p.ClientIdentity != "ML-DSA-65" || len(p.CriticalMessageSignatures) != 2 || p.CriticalMessageSignatures[0] != "Ed25519" || p.CriticalMessageSignatures[1] != "ML-DSA-65" || p.AutomaticFallback || p.ClassicalOnlyAllowed {
		return errors.New("approval transport policy weakened")
	}
	if a.Decision.StrictPQAction != "enable" || a.Decision.LegacyXMESH1Action != "retain" || a.Approval.Authority != "release-owner" || a.Approval.ApprovedBy == "" || a.Approval.Statement == "" {
		return errors.New("approval decision/authority invalid")
	}
	approved, e := parseTime(a.Approval.ApprovedAt)
	if e != nil || approved.Before(start) || approved.After(end) {
		return errors.New("approval timestamp invalid")
	}
	if a.Claims.ProductionActivation || a.Claims.StrictPQEnabled || a.Claims.LegacyXMESH1Retired || a.Claims.PhysicalPowerLossQualified {
		return errors.New("approval pre-execution claims must remain false")
	}
	return nil
}

func decodeB64(v string, n int) ([]byte, error) {
	raw, e := base64.StdEncoding.Strict().DecodeString(v)
	if e != nil || len(raw) != n || base64.StdEncoding.EncodeToString(raw) != v {
		return nil, errors.New("noncanonical public key")
	}
	return raw, nil
}
func panelPin(v PanelPinConfig, nodeID uint64) (runtime.Pin, error) {
	ed, e := decodeB64(v.Ed25519Public, 32)
	if e != nil {
		return runtime.Pin{}, e
	}
	pq, e := decodeB64(v.MLDSA65Public, 1952)
	if e != nil {
		return runtime.Pin{}, e
	}
	if v.IssuerID == "" || v.Ed25519KeyID == "" || v.MLDSA65KeyID == "" {
		return runtime.Pin{}, errors.New("panel pin identity missing")
	}
	return runtime.Pin{IssuerID: v.IssuerID, Purpose: "panel_response", NodeID: nodeID, EdKeyID: v.Ed25519KeyID, PQKeyID: v.MLDSA65KeyID, EdPublic: ed, PQPublic: pq}, nil
}
func wantPermit(v ExpectedPermit) cutover.ExpectedPermit {
	return cutover.ExpectedPermit{NodeID: v.NodeID, FromEpoch: v.FromEpoch, ToEpoch: v.ToEpoch, RequestID: v.RequestID, FromEdKeyID: v.FromEdKeyID, FromPQKeyID: v.FromPQKeyID, ToEdKeyID: v.ToEdKeyID, ToPQKeyID: v.ToPQKeyID, CandidateSHA256Hex: v.CandidateSHA256Hex}
}
func activePin(layout state.Layout) (runtime.Pin, uint64, error) {
	pub, e := keyring.Description(layout.Vault, layout.MasterKey)
	if e != nil {
		return runtime.Pin{}, 0, e
	}
	if pub.NodeID <= 0 || pub.KeyEpoch == 0 {
		return runtime.Pin{}, 0, errors.New("invalid active Node key identity")
	}
	return runtime.Pin{IssuerID: fmt.Sprintf("node-%d", pub.NodeID), Purpose: pub.Purpose, NodeID: uint64(pub.NodeID), EdKeyID: pub.EdKeyID, PQKeyID: pub.PQKeyID, EdPublic: append([]byte(nil), pub.EdPublic...), PQPublic: append([]byte(nil), pub.PQPublic...)}, pub.KeyEpoch, nil
}
func loadTLS(v TLSConfig) (*x509.CertPool, tls.Certificate, error) {
	ca, e := os.ReadFile(filepath.Clean(v.RootCAFile))
	if e != nil {
		return nil, tls.Certificate{}, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, tls.Certificate{}, errors.New("root CA file contained no certificates")
	}
	cert, e := tls.LoadX509KeyPair(filepath.Clean(v.ClientCertificate), filepath.Clean(v.ClientPrivateKey))
	if e != nil {
		return nil, tls.Certificate{}, e
	}
	return roots, cert, nil
}

func Execute(ctx context.Context, mode Mode, configPath, sourceRevision, artifactSHA string, now time.Time) (Result, error) {
	var empty Result
	if ctx == nil || (mode != ModeActivate && mode != ModeRecover) {
		return empty, errors.New("invalid activation mode/context")
	}
	var cfg Config
	_, e := decodeStrict(configPath, 128*1024, &cfg)
	if e != nil {
		return empty, fmt.Errorf("activation config: %w", e)
	}
	if cfg.Schema != schema || cfg.StateRoot == "" || cfg.ApprovalFile == "" {
		return empty, errors.New("activation config schema/paths invalid")
	}
	layout, e := state.Open(cfg.StateRoot)
	if e != nil {
		return empty, e
	}
	next, minimumEpoch, e := activePin(layout)
	if e != nil {
		return empty, e
	}
	if cfg.ExpectedPermit.NodeID != next.NodeID || cfg.ExpectedPermit.ToEpoch != minimumEpoch || cfg.ExpectedPermit.ToEdKeyID != next.EdKeyID || cfg.ExpectedPermit.ToPQKeyID != next.PQKeyID {
		return empty, errors.New("approved permit candidate does not match durable active Node state")
	}
	var approval approvalDocument
	approvalRaw, e := decodeStrict(cfg.ApprovalFile, 256*1024, &approval)
	if e != nil {
		return empty, fmt.Errorf("approval: %w", e)
	}
	if e = validateApproval(approvalRaw, approval, cfg.ApprovalSHA256, sourceRevision, artifactSHA, next.NodeID, now.UTC()); e != nil {
		return empty, e
	}
	panel, e := panelPin(cfg.PanelPin, next.NodeID)
	if e != nil {
		return empty, e
	}
	want := wantPermit(cfg.ExpectedPermit)
	var permit cutover.VerifiedPermit
	if mode == ModeActivate {
		permit, e = cutover.ReloadVerifiedPermit(layout.Journal, panel, want, now.UnixMilli())
	} else {
		permit, e = cutover.ReloadVerifiedPermitForReceiptRecovery(layout.Journal, panel, want, next)
	}
	if e != nil {
		return empty, fmt.Errorf("verified permit reload: %w", e)
	}
	roots, clientCert, e := loadTLS(cfg.TLS)
	if e != nil {
		return empty, e
	}
	endpoint := runtime.Endpoint{Address: cfg.Endpoint.Address, ServerName: cfg.Endpoint.ServerName}
	var receipt cutover.VerifiedCommitReceipt
	if mode == ModeActivate {
		receipt, e = runtime.Exchange(ctx, endpoint, roots, clientCert, layout, panel, permit, next, minimumEpoch, now.UnixMilli())
	} else {
		receipt, e = runtime.Recover(ctx, endpoint, roots, clientCert, layout, panel, permit, next, minimumEpoch, now.UnixMilli())
	}
	if e != nil {
		return empty, e
	}
	bindingRaw, e := json.Marshal(receipt)
	if e != nil {
		return empty, e
	}
	return Result{Status: "strict-pq-node-cutover-receipt-verified", Mode: mode, NodeID: next.NodeID, ApprovalSHA256: cfg.ApprovalSHA256, ReceiptBindingSHA256: shaHex(bindingRaw), MinimumEpoch: minimumEpoch, StrictPQEnabled: true, LegacyXMESH1Retired: false}, nil
}
