package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestImmutableReleasePreflightRejectsMutationAndSurvivesRetry(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only durable preflight")
	}
	dir := filepath.Join(t.TempDir(), "release-candidates")
	payload := bytes.Repeat([]byte("same tested binary"), 100)
	digest := sha256.Sum256(payload)
	plan := releasePlan{
		NodeID: 7, CommandID: 42,
		Current:          releaseIdentity{Version: "control-v6.0.24", SourceRevision: "a", ArtifactSHA256: "b"},
		Target:           releaseIdentity{Version: "control-v6.0.27", SourceRevision: "c", ArtifactSHA256: hex.EncodeToString(digest[:])},
		ActivationSHA256: "d", ExpiresAtMS: time.Now().Add(time.Minute).UnixMilli(),
	}
	signed := []byte("real call verifies signed plan first")
	if err := privateReleaseDirectory(dir); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(dir, candidateFileName(plan))
	if err := os.WriteFile(candidate, payload, 0600); err != nil {
		t.Fatal(err)
	}
	if err := persistReleasePreflight(dir, plan, signed); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(dir, "prepared-release.json")
	first, err := os.Lstat(record)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := strictFile(record, 0600)
	if err != nil {
		t.Fatal(err)
	}
	var proof preparedRelease
	if err := json.Unmarshal(encoded, &proof); err != nil {
		t.Fatal(err)
	}
	planHash := sha256.Sum256(signed)
	if proof.RuntimeSwitched || proof.ProductionActivationAuthorized || !proof.PreflightOnly ||
		proof.SignedPlanSHA256 != hex.EncodeToString(planHash[:]) ||
		proof.ArtifactFile != candidateFileName(plan) || proof.CommandID != plan.CommandID {
		t.Fatal("preflight record is not bound to the signed candidate")
	}
	if err := persistReleasePreflight(dir, plan, signed); err != nil {
		t.Fatal(err)
	}
	second, err := os.Lstat(record)
	if err != nil || !os.SameFile(first, second) {
		t.Fatal("idempotent preflight replaced durable proof")
	}
	if err := persistReleasePreflight(dir, plan, []byte("different signed response")); err == nil {
		t.Fatal("conflicting signed plan replaced preflight")
	}
	if err := os.WriteFile(candidate, []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := persistReleasePreflight(dir, plan, signed); err == nil {
		t.Fatal("preflight accepted altered candidate on retry")
	}
	if newer, err := strictFile(record, 0600); err != nil || !bytes.Equal(encoded, newer) {
		t.Fatal("failed preflight damaged existing evidence")
	}
}

func TestReleasePreflightPreservesExistingSymlinkAndExpiredRecord(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only durable preflight")
	}
	dir := filepath.Join(t.TempDir(), "release-candidates")
	if err := privateReleaseDirectory(dir); err != nil {
		t.Fatal(err)
	}
	payload := []byte("verified bytes")
	digest := sha256.Sum256(payload)
	plan := releasePlan{NodeID: 1, CommandID: 1, Target: releaseIdentity{ArtifactSHA256: hex.EncodeToString(digest[:])},
		ExpiresAtMS: time.Now().Add(time.Minute).UnixMilli()}
	if err := os.WriteFile(filepath.Join(dir, candidateFileName(plan)), payload, 0600); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "external")
	if err := os.WriteFile(external, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "prepared-release.json")
	if err := os.Symlink(external, link); err != nil {
		t.Fatal(err)
	}
	if err := persistReleasePreflight(dir, plan, []byte("signed")); err == nil {
		t.Fatal("symlink preflight marker accepted")
	}
	if content, err := os.ReadFile(external); err != nil || string(content) != "preserve" {
		t.Fatal("rejected preflight modified external data")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	plan.ExpiresAtMS = time.Now().Add(-time.Second).UnixMilli()
	if err := persistReleasePreflight(dir, plan, []byte("signed")); err == nil {
		t.Fatal("expired preflight signed plan accepted")
	}
}

func TestPreparedReleaseCrashRecoveryAfterPublish(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned release directory")
	}
	dir := filepath.Join(t.TempDir(), "release-candidates")
	if err := privateReleaseDirectory(dir); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(dir, "prepared-release.json")
	tmp, err := os.CreateTemp(dir, ".partial-")
	if err != nil {
		t.Fatal(err)
	}
	original := []byte("{\"preflightOnly\":true,\"runtimeSwitched\":false}\n")
	if _, err := tmp.Write(original); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(tmp.Name(), record); err != nil {
		t.Fatal(err)
	}
	// A dead process leaves two links. Reentry must reclaim only the
	// partial without changing the immutable published preflight.
	lock, err := lockReleaseDirectory(dir)
	if err != nil {
		t.Fatalf("preflight publication cannot recover after SIGKILL: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(tmp.Name()); !os.IsNotExist(err) {
		t.Fatalf("partial preflight survived recovery: %v", err)
	}
	after, err := strictFile(record, 0600)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatalf("published preflight changed during recovery: %v", err)
	}
}
