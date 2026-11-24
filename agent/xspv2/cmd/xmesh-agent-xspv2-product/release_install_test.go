package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProductReplacementBindsBytesAndPreservesPreviousImage(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned filesystem images")
	}
	dir := t.TempDir()
	binary := filepath.Join(t.TempDir(), "product")
	old, target := []byte("previous product"), []byte("target product")
	plan := releasePlan{
		CommandID:   42,
		Current:     releaseIdentity{ArtifactSHA256: fmt.Sprintf("%x", sha256.Sum256(old))},
		Target:      releaseIdentity{ArtifactSHA256: fmt.Sprintf("%x", sha256.Sum256(target))},
		ExpiresAtMS: time.Now().Add(time.Minute).UnixMilli(),
	}
	stage := filepath.Join(dir, candidateFileName(plan))
	write := func(path string, bytes []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, bytes, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(binary, old, 0755)
	write(stage, []byte("tampered"), 0600)
	if err := replacePreparedProduct(dir, binary, plan); err == nil {
		t.Fatal("replaced executable with unapproved bytes")
	}
	write(stage, target, 0600)
	backup := productReleaseBackup(dir, plan)
	write(backup, []byte("tampered backup"), 0600)
	if err := replacePreparedProduct(dir, binary, plan); err == nil {
		t.Fatal("replaced executable without a valid backup")
	}
	if err := verifyCandidateBytes(binary, plan.Current.ArtifactSHA256, 0755); err != nil {
		t.Fatal(err)
	}
	write(backup, old, 0600)
	expired := plan
	expired.ExpiresAtMS = time.Now().Add(-time.Second).UnixMilli()
	if err := replacePreparedProduct(dir, binary, expired); err == nil {
		t.Fatal("expired authorization changed executable")
	}
	priorInode, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	defer priorInode.Close()
	if err := replacePreparedProduct(dir, binary, plan); err != nil {
		t.Fatal(err)
	}
	for file, identity := range map[string]releaseIdentity{binary: plan.Target, backup: plan.Current} {
		mode := os.FileMode(0600)
		if file == binary {
			mode = 0755
		}
		if err := verifyCandidateBytes(file, identity.ArtifactSHA256, mode); err != nil {
			t.Fatal(err)
		}
	}
	raw := make([]byte, len(old))
	if _, err := priorInode.ReadAt(raw, 0); err != nil || string(raw) != string(old) {
		t.Fatal("installation overwrote the previous inode in place")
	}
	if err := restorePreviousProduct(dir, binary, plan); err != nil {
		t.Fatal(err)
	}
	if err := verifyCandidateBytes(binary, plan.Current.ArtifactSHA256, 0755); err != nil {
		t.Fatal(err)
	}
	if err := restorePreviousProduct(dir, binary, plan); err != nil {
		t.Fatalf("interrupted rollback did not resume idempotently: %v", err)
	}

}
