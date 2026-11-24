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
