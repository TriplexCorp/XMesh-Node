package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// A durable evidence checkpoint, NOT an authority to execute or promote
// the downloaded binary. Its current identity is deliberately immutable.
type preparedRelease struct {
	Schema                         string          `json:"schema"`
	NodeID                         int64           `json:"nodeId"`
	CommandID                      int64           `json:"commandId"`
	Current                        releaseIdentity `json:"current"`
	Target                         releaseIdentity `json:"target"`
	ActivationSHA256               string          `json:"activationSha256"`
	SignedPlanSHA256               string          `json:"signedPlanSha256"`
	ArtifactFile                   string          `json:"artifactFile"`
	PreflightOnly                  bool            `json:"preflightOnly"`
	RuntimeSwitched                bool            `json:"runtimeSwitched"`
	ProductionActivationAuthorized bool            `json:"productionActivationAuthorized"`
}

func candidateFileName(plan releasePlan) string {
	return strconv.FormatInt(plan.CommandID, 10) + "-" + plan.Target.ArtifactSHA256 + ".bin"
}

func preflightRecord(plan releasePlan, signed []byte) preparedRelease {
	planDigest := sha256.Sum256(signed)
	return preparedRelease{
		Schema: "xmesh-product-release-preflight-v1",
		NodeID: plan.NodeID, CommandID: plan.CommandID,
		Current: plan.Current, Target: plan.Target,
		ActivationSHA256: plan.ActivationSHA256,
		SignedPlanSHA256: hex.EncodeToString(planDigest[:]),
		ArtifactFile:     candidateFileName(plan),
		PreflightOnly:    true, RuntimeSwitched: false,
		ProductionActivationAuthorized: false,
	}
}

// The caller has already verified the dual-signed plan and its freshness.
// The same private directory lock serializes download and preflight. A crash
// leaves either the old record, the new complete record or one removable
// private partial; never a replacement binary or changed WAL identity.
func persistReleasePreflight(dir string, plan releasePlan, signed []byte) error {
	if plan.CommandID <= 0 || plan.NodeID <= 0 ||
		plan.ExpiresAtMS <= time.Now().UnixMilli() || len(signed) == 0 || len(signed) > 16384 {
		return errors.New("invalid or expired preflight plan")
	}
	if err := privateReleaseDirectory(dir); err != nil {
		return err
	}
	lock, err := lockReleaseDirectory(dir)
	if err != nil {
		return err
	}
	defer lock.Close()

	candidate := filepath.Join(dir, candidateFileName(plan))
	if err := verifyCandidateBytes(candidate, plan.Target.ArtifactSHA256, 0600); err != nil {
		return fmt.Errorf("release candidate must remain unchanged: %w", err)
	}
	record := preflightRecord(plan, signed)
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	const recordFile = "prepared-release.json"
	destination := filepath.Join(dir, recordFile)
	if old, err := strictFile(destination, 0600); err == nil {
		if !bytes.Equal(old, data) {
			return errors.New("another immutable release preflight exists")
		}
		// Recover the directory fsync boundary after a SIGKILL between
		// publishing the immutable preflight and syncing its parent.
		return syncParent(destination)
	} else if !errors.Is(err, os.ErrNotExist) {
		return errors.New("unsafe or unreadable prior release preflight")
	}
	tmp, err := os.CreateTemp(dir, ".partial-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// No concurrent cooperating writer can replace the destination under
	// lock. Refuse even a dangling symlink planted by a privileged actor.
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("release preflight appeared during preparation")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return publishImmutableReleaseFile(tmp.Name(), destination)
}

// Re-check the exact immutable plan over the current authenticated XSP/2
// tunnel. Neither a cached signature nor a correctly staged candidate
// authorizes the next transition after a command is revoked.
func revalidateReleasePlan(cfg productConfig, command int64, activation string, signed []byte,
	fetch func([]byte) ([]byte, int, error)) error {
	body, err := json.Marshal(releasePlanRequestForPreflight{
		CommandID: command, Current: cfg.ReleaseIdentity,
	})
	if err != nil {
		return err
	}
	fresh, status, err := fetch(body)
	if err != nil {
		return err
	}
	if status != http.StatusOK || !bytes.Equal(fresh, signed) {
		return errors.New("release authorization changed, expired or revoked")
	}
	if _, err := verifyReleasePlan(fresh, cfg, command, activation); err != nil {
		return err
	}
	return nil
}

func prepareReleaseCutover(command int64, planPath string) error {
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
	// The old signed plan is NOT sufficient after revocation. A fresh
	// authenticated request must return the exact same immutable receipt.
	if err := revalidateReleasePlan(cfg, command, activation, raw,
		func(body []byte) ([]byte, int, error) {
			return tunnelRequest(cfg, releasePlanPath, body)
		}); err != nil {
		return err
	}
	return persistReleasePreflight(stateRoot+"/release-candidates", plan, raw)
}

type releasePlanRequestForPreflight struct {
	CommandID int64           `json:"commandId"`
	Current   releaseIdentity `json:"current"`
}
