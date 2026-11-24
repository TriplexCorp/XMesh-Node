package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReleasePlanBindsSignedTransitionAndExpires(t *testing.T) {
	current := releaseIdentity{"control-v6.0.24", strings.Repeat("a", 40), strings.Repeat("b", 64)}
	target := releaseIdentity{"control-v6.0.27", strings.Repeat("c", 40), strings.Repeat("d", 64)}
	activated := strings.Repeat("e", 64)
	now := time.Now()
	plan := releasePlan{Schema: "xmesh-product-agent-release-plan-v1", NodeID: 1,
		KeyEpoch: 1, CommandID: 42, ActivationSHA256: activated,
		ExpiresAtMS: now.Add(time.Minute).UnixMilli(), Current: current, Target: target}
	sign := func(plan releasePlan, issued time.Time) ([]byte, productConfig) {
		raw, err := json.Marshal(plan)
		if err != nil {
			t.Fatal(err)
		}
		doc, cfg := signTestPanelPayload(t, issued.UnixMilli(), "panel.product.release-plan",
			releasePlanPath, "42", target.SourceRevision, raw)
		cfg.ReleaseIdentity = current
		return doc, cfg
	}
	// The durable plan can be retrieved with a fresh outer tunnel envelope
	// even after the normal 120-second response window.
	raw, cfg := sign(plan, now.Add(-3*time.Minute))
	if got, err := verifyReleasePlan(raw, cfg, 42, activated); err != nil || got != plan {
		t.Fatalf("valid plan rejected: %v", err)
	}
	if _, err := verifyReleasePlan(raw, cfg, 43, activated); err == nil {
		t.Fatal("wrong command accepted")
	}
	if _, err := verifyReleasePlan(raw, cfg, 42, strings.Repeat("f", 64)); err == nil {
		t.Fatal("wrong activation accepted")
	}
	cfg.ReleaseIdentity.ArtifactSHA256 = strings.Repeat("f", 64)
	if _, err := verifyReleasePlan(raw, cfg, 42, activated); err == nil {
		t.Fatal("changed current binary accepted")
	}
	plan.ExpiresAtMS = now.Add(-time.Minute).UnixMilli()
	raw, cfg = sign(plan, now.Add(-3*time.Minute))
	if _, err := verifyReleasePlan(raw, cfg, 42, activated); err == nil {
		t.Fatal("expired plan accepted")
	}
}

func TestStagedArtifactRequiresExactPrivateBytes(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires a root-owned artifact")
	}
	dir := t.TempDir()
	candidate := filepath.Join(dir, "candidate")
	payload := []byte("candidate executable")
	hash := sha256.Sum256(payload)
	digest := hex.EncodeToString(hash[:])
	if err := os.WriteFile(candidate, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyCandidateBytes(candidate, digest, 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifyCandidateBytes(candidate, strings.Repeat("a", 64), 0600); err == nil {
		t.Fatal("unapproved candidate bytes accepted")
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(candidate, alias); err != nil {
		t.Fatal(err)
	}
	if err := verifyCandidateBytes(alias, digest, 0600); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Link(candidate, filepath.Join(dir, "hard-link")); err != nil {
		t.Fatal(err)
	}
	if err := verifyCandidateBytes(candidate, digest, 0600); err == nil {
		t.Fatal("candidate with a second hard link accepted")
	}
}
