package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestReleaseCommitRequiresExactMeasuredRelease(t *testing.T) {
	activation := strings.Repeat("a", 64)
	current := releaseIdentity{"control-v6.0.24", strings.Repeat("a", 40), strings.Repeat("b", 64)}
	target := releaseIdentity{"control-v6.0.27", strings.Repeat("c", 40), strings.Repeat("d", 64)}
	claims := releaseCommitReceipt{"xmesh-product-agent-release-commit-v1", 1, 42,
		activation, strings.Repeat("f", 64), target}
	sign := func(claims releaseCommitReceipt, command, revision string) ([]byte, productConfig) {
		t.Helper()
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		raw, cfg := signTestPanelPayload(t, time.Now().Add(-time.Hour).UnixMilli(),
			"panel.product.release-commit", releaseCommitPath, command, revision, payload)
		cfg.ReleaseIdentity = current
		return raw, cfg
	}
	raw, cfg := sign(claims, "42", target.SourceRevision)
	if got, err := verifyReleaseCommit(raw, cfg, activation, target); err != nil || got != claims {
		t.Fatalf("durable signed commit rejected: %v", err)
	}
	wrong := target
	wrong.ArtifactSHA256 = strings.Repeat("e", 64)
	if _, err := verifyReleaseCommit(raw, cfg, activation, wrong); err == nil {
		t.Fatal("substituted executable accepted")
	}
	if _, err := verifyReleaseCommit(raw, cfg, activation, current); err == nil {
		t.Fatal("superseded executable accepted")
	}
	if _, err := verifyReleaseCommit(raw, cfg, strings.Repeat("b", 64), target); err == nil {
		t.Fatal("foreign activation accepted")
	}
	wrongCommand, wrongConfig := sign(claims, "43", target.SourceRevision)
	if _, err := verifyReleaseCommit(wrongCommand, wrongConfig, activation, target); err == nil {
		t.Fatal("receipt envelope from another command accepted")
	}
	_, foreign := sign(claims, "42", target.SourceRevision)
	if _, err := verifyReleaseCommit(raw, foreign, activation, target); err == nil {
		t.Fatal("foreign signing authority accepted")
	}
}
