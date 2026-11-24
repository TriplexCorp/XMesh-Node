package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectReleaseArtifact(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned staging directory")
	}
	data := bytes.Repeat([]byte("a"), releaseChunkBytes+17)
	digest := sha256.Sum256(data)
	rawPlan := []byte("verified signed plan")
	planDigest := sha256.Sum256(rawPlan)
	plan := releasePlan{CommandID: 42, ExpiresAtMS: time.Now().Add(time.Minute).UnixMilli(),
		Target: releaseIdentity{ArtifactSHA256: hex.EncodeToString(digest[:])}}
	for _, scenario := range []string{"success", "wrong-data", "wrong-offset", "changed-size", "revoked", "wrong-plan"} {
		t.Run(scenario, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "stage")
			calls := 0
			err := collectReleaseArtifact(dir, plan, rawPlan, func(raw []byte) ([]byte, int, error) {
				var request releaseArtifactRequest
				if err := json.Unmarshal(raw, &request); err != nil {
					t.Fatal(err)
				}
				if request.CommandID != plan.CommandID || request.PlanSHA256 != hex.EncodeToString(planDigest[:]) {
					t.Fatal("request not bound to plan")
				}
				calls++
				end := min(request.Offset+releaseChunkBytes, int64(len(data)))
				part := append([]byte(nil), data[request.Offset:end]...)
				chunk := releaseArtifactChunk{PlanSHA256: request.PlanSHA256, ArtifactSHA256: plan.Target.ArtifactSHA256,
					Offset: request.Offset, TotalBytes: int64(len(data)), DataB64: b64.EncodeToString(part)}
				if calls == 2 {
					switch scenario {
					case "wrong-data":
						part[0] ^= 1
						chunk.DataB64 = b64.EncodeToString(part)
					case "wrong-offset":
						chunk.Offset = 0
					case "changed-size":
						chunk.TotalBytes++
					case "wrong-plan":
						chunk.PlanSHA256 = ""
					case "revoked":
						return nil, http.StatusConflict, nil
					}
				}
				body, err := json.Marshal(chunk)
				return body, http.StatusOK, err
			})
			entries, readErr := os.ReadDir(dir)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if scenario != "success" {
				if err == nil || len(entries) != 0 {
					t.Fatalf("failed candidate published: %v, %v", err, entries)
				}
				return
			}
			if err != nil || len(entries) != 1 || calls != 2 {
				t.Fatalf("candidate rejected: %v, %v, %d", err, entries, calls)
			}
			file := filepath.Join(dir, entries[0].Name())
			if err := verifyCandidateBytes(file, plan.Target.ArtifactSHA256, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReleaseTransferLockAndCrashCleanup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned staging directory")
	}
	dir := filepath.Join(t.TempDir(), "stage")
	if err := privateReleaseDirectory(dir); err != nil {
		t.Fatal(err)
	}
	lock, err := lockReleaseDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	tmp, err := os.CreateTemp(dir, ".partial-")
	if err != nil {
		t.Fatal(err)
	}
	partial := tmp.Name()
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	verified := filepath.Join(dir, "42-verified.bin")
	if err := os.WriteFile(verified, []byte("preserve until safe"), 0600); err != nil {
		t.Fatal(err)
	}
	if second, err := lockReleaseDirectory(dir); err == nil {
		second.Close()
		t.Fatal("concurrent transfer accepted")
	}
	if _, err := os.Stat(partial); err != nil {
		t.Fatal("active transfer's partial removed")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	recovery, err := lockReleaseDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	recovery.Close()
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Fatal("abandoned partial not removed")
	}
	if _, err := os.Stat(verified); err != nil {
		t.Fatal("verified candidate removed")
	}
	if err := os.Symlink(verified, partial); err != nil {
		t.Fatal(err)
	}
	if unsafe, err := lockReleaseDirectory(dir); err == nil {
		unsafe.Close()
		t.Fatal("unsafe partial symlink accepted")
	}
	if _, err := os.Stat(verified); err != nil {
		t.Fatal("unsafe cleanup removed verified target")
	}
}

func TestReleaseVerifiedCandidateRetryDoesNotOverwriteOrRefetch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned staging directory")
	}
	dir := filepath.Join(t.TempDir(), "stage")
	data := bytes.Repeat([]byte("v"), releaseChunkBytes+7)
	digest := sha256.Sum256(data)
	plan := releasePlan{
		CommandID: 99, ExpiresAtMS: time.Now().Add(time.Minute).UnixMilli(),
		Target: releaseIdentity{ArtifactSHA256: hex.EncodeToString(digest[:])},
	}
	rawPlan := []byte("identical signed release plan")
	planHash := sha256.Sum256(rawPlan)
	count := 0
	download := func(raw []byte) ([]byte, int, error) {
		count++
		var req releaseArtifactRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			t.Fatal(err)
		}
		end := min(req.Offset+releaseChunkBytes, int64(len(data)))
		chunk := releaseArtifactChunk{
			PlanSHA256:     hex.EncodeToString(planHash[:]),
			ArtifactSHA256: plan.Target.ArtifactSHA256,
			Offset:         req.Offset, TotalBytes: int64(len(data)),
			DataB64: b64.EncodeToString(data[req.Offset:end]),
		}
		reply, err := json.Marshal(chunk)
		return reply, http.StatusOK, err
	}
	if err := collectReleaseArtifact(dir, plan, rawPlan, download); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("unexpected transfer count: %d", count)
	}
	final := filepath.Join(dir, "99-"+plan.Target.ArtifactSHA256+".bin")
	before, err := os.Lstat(final)
	if err != nil {
		t.Fatal(err)
	}
	if err := collectReleaseArtifact(dir, plan, rawPlan, func([]byte) ([]byte, int, error) {
		t.Fatal("verified retry contacted gateway")
		return nil, http.StatusConflict, nil
	}); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(final)
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("verified candidate was replaced: %v", err)
	}
	if err := os.WriteFile(final, []byte("corrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := collectReleaseArtifact(dir, plan, rawPlan, func([]byte) ([]byte, int, error) {
		t.Fatal("corrupted existing candidate should fail before network")
		return nil, http.StatusConflict, nil
	}); err == nil {
		t.Fatal("corrupted candidate accepted as idempotent retry")
	}
}
