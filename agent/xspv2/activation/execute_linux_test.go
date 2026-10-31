//go:build linux

package activation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func validApproval(t *testing.T) (approvalDocument, []byte, time.Time, string, string) {
	t.Helper()
	var a approvalDocument
	a.Schema = approvalSchema
	a.DeploymentClass = "kvm-vps"
	revision := strings.Repeat("a", 40)
	artifact := strings.Repeat("b", 64)
	a.ReleaseCandidate.NexusRuntimeRevision = strings.Repeat("c", 40)
	a.ReleaseCandidate.NodeRevision = revision
	a.ReleaseCandidate.NexusImageSHA256 = "sha256:" + strings.Repeat("d", 64)
	a.ReleaseCandidate.AgentArtifactSHA256 = artifact
	a.Evidence.AIAssistedSecurityReviewAccepted = true
	a.Evidence.KVMVPSDurabilityQualificationAccepted = true
	a.Evidence.ProviderStorageRiskAccepted = true
	a.Evidence.FinalCanaryPassed = true
	a.Evidence.RolloutPlanReviewed = true
	a.Evidence.AIAssistedSecurityReviewResultSHA256 = strings.Repeat("1", 64)
	a.Evidence.KVMVPSDurabilityResultSHA256 = strings.Repeat("2", 64)
	a.Evidence.ProviderStorageRiskAcceptanceSHA256 = strings.Repeat("6", 64)
	a.Evidence.FinalCanaryResultSHA256 = strings.Repeat("3", 64)
	a.Evidence.RolloutPlanSHA256 = strings.Repeat("4", 64)
	a.Evidence.RolloutPlanReviewSHA256 = strings.Repeat("5", 64)
	a.Scope.Mode = "limited-canary"
	a.Scope.Nodes = []string{"node-13"}
	a.Scope.ValidFrom = "2026-10-31T08:00:00Z"
	a.Scope.ValidUntil = "2026-10-31T09:00:00Z"
	a.TransportPolicy.TLSProtocols = []string{"TLSv1.3"}
	a.TransportPolicy.KeyExchange = "X25519MLKEM768"
	a.TransportPolicy.ClientIdentity = "ML-DSA-65"
	a.TransportPolicy.CriticalMessageSignatures = []string{"Ed25519", "ML-DSA-65"}
	a.Decision.StrictPQAction = "enable"
	a.Decision.LegacyXMESH1Action = "retain"
	a.Approval.Authority = "release-owner"
	a.Approval.ApprovedBy = "Triplex"
	a.Approval.ApprovedAt = "2026-10-31T08:05:00Z"
	a.Approval.Statement = "bounded Node 13 strict-PQ activation"
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 31, 8, 30, 0, 0, time.UTC)
	return a, raw, now, revision, artifact
}

func TestApprovalBindsArtifactNodeWindowAndNoFallback(t *testing.T) {
	a, raw, now, revision, artifact := validApproval(t)
	if err := validateApproval(raw, a, shaHex(raw), revision, artifact, 13, now); err != nil {
		t.Fatalf("valid approval rejected: %v", err)
	}
	bad := a
	bad.ReleaseCandidate.AgentArtifactSHA256 = strings.Repeat("e", 64)
	if err := validateApproval(raw, bad, shaHex(raw), revision, artifact, 13, now); err == nil {
		t.Fatal("substituted Agent artifact accepted")
	}
	if err := validateApproval(raw, a, shaHex(raw), revision, artifact, 99, now); err == nil {
		t.Fatal("out-of-scope Node accepted")
	}
	if err := validateApproval(raw, a, shaHex(raw), revision, artifact, 13, now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired approval accepted")
	}
	bad = a
	bad.TransportPolicy.ClassicalOnlyAllowed = true
	if err := validateApproval(raw, bad, shaHex(raw), revision, artifact, 13, now); err == nil {
		t.Fatal("classical fallback accepted")
	}
	bad = a
	bad.Evidence.AIAssistedSecurityReviewAccepted = false
	if err := validateApproval(raw, bad, shaHex(raw), revision, artifact, 13, now); err == nil {
		t.Fatal("missing AI-assisted security review accepted")
	}
	bad = a
	bad.Evidence.ProviderStorageRiskAcceptanceSHA256 = ""
	if err := validateApproval(raw, bad, shaHex(raw), revision, artifact, 13, now); err == nil {
		t.Fatal("missing provider-storage acceptance digest accepted")
	}
}
