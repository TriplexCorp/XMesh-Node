package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestForwardProductReleaseVersions(t *testing.T) {
	for _, tc := range []struct {
		from, to string
		want     bool
	}{
		{"control-v6.0.24", "control-v6.0.27", true},
		{"control-v6.0.27", "control-v6.0.28", true},
		{"control-v6.0.99", "control-v6.1.0", true},
		{"control-v6.1.9", "control-v6.1.10", true},
		{"control-v6.0.27", "control-v6.0.27", false},
		{"control-v6.0.27", "control-v6.0.26", false},
		{"control-v6.1.0", "control-v6.0.999", false},
		{"control-v6.0.27", "control-v7.0.0", false},
		{"control-v6.0.27", "control-v6.00.28", false},
		{"control-v6.0.27", "control-v6.0.028", false},
		{"control-v6.0.27", "control-v6.0.4294967296", false},
		{"control-v6.0.27", "control-v6.0.28-rc1", false},
		{"control-v6.0.27", " control-v6.0.28", false},
		{"control-v6.0.27", "control-v6.0.+28", false},
	} {
		if got := forwardReleaseVersion(tc.from, tc.to); got != tc.want {
			t.Errorf("%s -> %s: got %v, want %v", tc.from, tc.to, got, tc.want)
		}
	}
}

func TestSignedFirstReleaseSuccessorAndRollbackRefusal(t *testing.T) {
	current := releaseIdentity{"control-v6.0.27", strings.Repeat("a", 40), strings.Repeat("b", 64)}
	target := releaseIdentity{"control-v6.0.28", strings.Repeat("c", 40), strings.Repeat("d", 64)}
	activation := strings.Repeat("e", 64)
	for _, tc := range []struct {
		name   string
		next   releaseIdentity
		accept bool
	}{
		{"successor", target, true},
		{"downgrade", releaseIdentity{"control-v6.0.26", target.SourceRevision, target.ArtifactSHA256}, false},
		{"same-version-rebuild", releaseIdentity{current.Version, target.SourceRevision, target.ArtifactSHA256}, false},
		{"same-source", releaseIdentity{target.Version, current.SourceRevision, target.ArtifactSHA256}, false},
		{"same-artifact", releaseIdentity{target.Version, target.SourceRevision, current.ArtifactSHA256}, false},
		{"upper-case-digest", releaseIdentity{target.Version, target.SourceRevision, strings.ToUpper(target.ArtifactSHA256)}, false},
		{"foreign-major", releaseIdentity{"control-v7.0.0", target.SourceRevision, target.ArtifactSHA256}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now()
			plan := releasePlan{Schema: "xmesh-product-agent-release-plan-v1", NodeID: 1,
				KeyEpoch: 1, CommandID: 42, ActivationSHA256: activation,
				ExpiresAtMS: now.Add(time.Minute).UnixMilli(), Current: current, Target: tc.next}
			body, err := json.Marshal(plan)
			if err != nil {
				t.Fatal(err)
			}
			raw, cfg := signTestPanelPayload(t, now.UnixMilli(), "panel.product.release-plan",
				releasePlanPath, "42", tc.next.SourceRevision, body)
			cfg.ReleaseIdentity = current
			if _, err := verifyReleasePlan(raw, cfg, 42, activation); (err == nil) != tc.accept {
				t.Fatalf("signed plan acceptance mismatch: %v", err)
			}
			claims := releaseCommitReceipt{"xmesh-product-agent-release-commit-v1", 1, 42,
				activation, strings.Repeat("f", 64), tc.next}
			body, err = json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			raw, cfg = signTestPanelPayload(t, now.UnixMilli(), "panel.product.release-commit",
				releaseCommitPath, "42", tc.next.SourceRevision, body)
			cfg.ReleaseIdentity = current
			if _, err := verifyReleaseCommit(raw, cfg, activation, tc.next); (err == nil) != tc.accept {
				t.Fatalf("signed commit acceptance mismatch: %v", err)
			}
			// A signed abort of an eligible forward transition remains valid.
			// This does not make an arbitrary downgrade a valid update plan.
			claims.Schema = "xmesh-product-agent-release-abort-v1"
			body, err = json.Marshal(claims)
			if err != nil {
				t.Fatal(err)
			}
			raw, cfg = signTestPanelPayload(t, now.UnixMilli(), "panel.product.release-abort",
				releaseAbortPath, "42", tc.next.SourceRevision, body)
			cfg.ReleaseIdentity = current
			if _, err := verifyReleaseOutcome(raw, cfg, activation, tc.next, "abort", releaseAbortPath); (err == nil) != tc.accept {
				t.Fatalf("signed abort acceptance mismatch: %v", err)
			}
		})
	}
}
