package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const (
	releaseArtifactPath = "/api/v1/node/agent-release-artifact"
	releaseChunkBytes = 128 * 1024
	maxReleaseArtifactBytes = 64 * 1024 * 1024
)

type releaseArtifactRequest struct {
	CommandID int64 `json:"commandId"`
	Current releaseIdentity `json:"current"`
	PlanSHA256 string `json:"planSha256"`
	Offset int64 `json:"offset"`
}

type releaseArtifactChunk struct {
	PlanSHA256 string `json:"planSha256"`
	ArtifactSHA256 string `json:"artifactSha256"`
	Offset int64 `json:"offset"`
	TotalBytes int64 `json:"totalBytes"`
	DataB64 string `json:"dataB64"`
}

func decodeReleaseChunk(raw []byte, planSHA, digest string, offset, total int64) ([]byte, int64, error) {
	var chunk releaseArtifactChunk
	if len(raw) > 2*releaseChunkBytes || checkUniqueJSONKeys(raw) != nil {
		return nil, 0, errors.New("invalid artifact chunk JSON")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&chunk); err != nil {
		return nil, 0, err
	}
	if d.Decode(new(any)) != io.EOF || chunk.PlanSHA256 != planSHA ||
		chunk.ArtifactSHA256 != digest || chunk.Offset != offset ||
		chunk.TotalBytes <= offset || chunk.TotalBytes > maxReleaseArtifactBytes ||
		(total != 0 && total != chunk.TotalBytes) {
		return nil, 0, errors.New("artifact chunk binding or size mismatch")
	}
	expected := min(int64(releaseChunkBytes), chunk.TotalBytes-offset)
	data, err := strictB64(chunk.DataB64, int(expected), releaseChunkBytes)
	if err != nil {
		return nil, 0, err
	}
	return data, chunk.TotalBytes, nil
}

func privateReleaseDirectory(path string) error {
	if err := os.Mkdir(path, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("unsafe release staging directory")
	}
	return nil
}

// Stage non-executable bytes only; never touch the enrolled binary, keys,
// receipt, WAL, or services. A failed/incomplete transfer publishes nothing.
func collectReleaseArtifact(dir string, plan releasePlan, rawPlan []byte, fetch func([]byte) ([]byte, int, error)) error {
	if plan.CommandID <= 0 || plan.ExpiresAtMS <= time.Now().UnixMilli() {
		return errors.New("release plan expired")
	}
	if err := privateReleaseDirectory(dir); err != nil {
		return err
	}
	planHash := sha256.Sum256(rawPlan)
	planSHA := hex.EncodeToString(planHash[:])
	tmp, err := os.CreateTemp(dir, ".partial-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	hash := sha256.New()
	var offset, total int64
	for {
		if plan.ExpiresAtMS <= time.Now().UnixMilli() {
			return errors.New("release plan expired during transfer")
		}
		body, err := json.Marshal(releaseArtifactRequest{
			CommandID: plan.CommandID, Current: plan.Current, PlanSHA256: planSHA, Offset: offset,
		})
		if err != nil {
			return err
		}
		raw, status, err := fetch(body)
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("release chunk unavailable: HTTP %d", status)
		}
		data, nextTotal, err := decodeReleaseChunk(raw, planSHA, plan.Target.ArtifactSHA256, offset, total)
		if err != nil {
			return err
		}
		total = nextTotal
		if _, err := io.MultiWriter(tmp, hash).Write(data); err != nil {
			return err
		}
		offset += int64(len(data))
		if offset == total {
			break
		}
	}
	if hex.EncodeToString(hash.Sum(nil)) != plan.Target.ArtifactSHA256 ||
		plan.ExpiresAtMS <= time.Now().UnixMilli() {
		return errors.New("complete artifact digest or plan expiry mismatch")
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := verifyCandidateBytes(tmp.Name(), plan.Target.ArtifactSHA256, 0600); err != nil {
		return err
	}
	final := filepath.Join(dir, strconv.FormatInt(plan.CommandID, 10)+"-"+plan.Target.ArtifactSHA256+".bin")
	if err := os.Rename(tmp.Name(), final); err != nil {
		return err
	}
	return syncParent(final)
}

func downloadStagedRelease(command int64, planPath string) error {
	cfg, activation, err := installedReleaseEnrollment()
	if err != nil {
		return err
	}
	raw, err := strictFile(planPath, 0600)
	if err != nil {
		return err
	}
	plan, err := verifyReleasePlan(raw, cfg, command, activation)
	if err != nil {
		return err
	}
	return collectReleaseArtifact(stateRoot+"/release-candidates", plan, raw, func(body []byte) ([]byte, int, error) {
		return tunnelRequest(cfg, releaseArtifactPath, body)
	})
}
