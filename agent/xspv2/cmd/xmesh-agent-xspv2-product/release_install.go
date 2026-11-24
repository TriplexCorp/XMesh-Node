package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const releaseInstallPath = "/api/v1/node/agent-release-install"

func readExactReleaseImage(path, expected string, mode os.FileMode) ([]byte, error) {
	file, expectedSize, err := openPrivateReleaseImage(path, mode)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxReleaseArtifactBytes+1))
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(contents)
	if int64(len(contents)) != expectedSize || hex.EncodeToString(digest[:]) != expected {
		return nil, errors.New("Agent image bytes differ from the signed identity")
	}
	return contents, nil
}

func productReleaseBackup(dir string, plan releasePlan) string {
	old := plan
	old.Target = plan.Current
	return filepath.Join(dir, candidateFileName(old))
}

// The caller holds the private release lock and has fresh authorization.
// Journal and active enrollment files are outside the replacement boundary.
func replacePreparedProduct(dir, installed string, plan releasePlan) error {
	if plan.ExpiresAtMS <= time.Now().UnixMilli() {
		return errors.New("release authorization expired before replacement")
	}
	stage, err := readExactReleaseImage(filepath.Join(dir, candidateFileName(plan)), plan.Target.ArtifactSHA256, 0600)
	if err != nil {
		return err
	}
	oldBytes, err := readExactReleaseImage(installed, plan.Current.ArtifactSHA256, 0755)
	if err != nil {
		return err
	}
	backup := productReleaseBackup(dir, plan)
	if err := verifyCandidateBytes(backup, plan.Current.ArtifactSHA256, 0600); errors.Is(err, os.ErrNotExist) {
		if err := atomicWrite(backup, oldBytes, 0600); err != nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("existing Agent backup was altered: %w", err)
	} else if err := syncParent(backup); err != nil {
		return err
	}
	if plan.ExpiresAtMS <= time.Now().UnixMilli() {
		return errors.New("release authorization expired after writing backup")
	}
	return atomicWrite(installed, stage, 0755)
}

// A supervisor restarts the installed target to confirm the exact running
// image. Replacement never executes a child process or uses a deadline to
// infer a remote abort.
func switchPreparedRelease(command int64) error {
	cfg, plan, planBytes, err := loadPreparedProduct(command)
	if err != nil {
		return err
	}
	return publishPreparedProduct(cfg, plan.ActivationSHA256, plan, planBytes)
}

func rollbackPreparedRelease(command int64) error {
	cfg, plan, planBytes, err := loadPreparedProduct(command)
	if err != nil {
		return err
	}
	return abortPreparedProduct(cfg, plan, planBytes)
}

func loadPreparedProduct(command int64) (productConfig, releasePlan, []byte, error) {
	if command <= 0 || os.Geteuid() != 0 {
		return productConfig{}, releasePlan{}, nil, errors.New("release operation requires root and a command ID")
	}
	cfg, err := loadConfig()
	if err != nil {
		return cfg, releasePlan{}, nil, err
	}
	if err := verifyEnrolledRelease(cfg, cfg.ReleaseIdentity); err != nil {
		return cfg, releasePlan{}, nil, err
	}
	activation, err := originalActivationDigest()
	if err != nil {
		return cfg, releasePlan{}, nil, err
	}
	raw, err := preparedReleasePlan(releaseCandidateDir, command)
	if err != nil {
		return cfg, releasePlan{}, nil, err
	}
	plan, err := decodeReleasePlan(raw, cfg, command, activation, false)
	return cfg, plan, raw, err
}

func abortPreparedProduct(cfg productConfig, plan releasePlan, signedPlan []byte) error {
	lock, err := lockReleaseDirectory(releaseCandidateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	planHash := sha256.Sum256(signedPlan)
	planSHA := hex.EncodeToString(planHash[:])
	body, err := json.Marshal(releaseCommitRequest{CommandID: plan.CommandID, PlanSHA256: planSHA, Installed: plan.Target})
	if err != nil {
		return err
	}
	reply, status, err := tunnelRequest(cfg, releaseAbortPath, body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("Nexus did not authorize rollback: HTTP %d", status)
	}
	outcome, err := verifyReleaseOutcome(reply, cfg, plan.ActivationSHA256, plan.Target, "abort", releaseAbortPath)
	if err != nil || outcome.CommandID != plan.CommandID || outcome.PlanSHA256 != planSHA {
		return errors.New("rollback authorization does not match the prepared update")
	}

	return restorePreviousProduct(releaseCandidateDir, installedProduct, plan)
}

// Only call after verifying the signed terminal abort and with the release lock held.
func restorePreviousProduct(dir, installed string, plan releasePlan) error {
	if verifyCandidateBytes(installed, plan.Current.ArtifactSHA256, 0755) == nil {
		return syncParent(installed)
	}
	if err := verifyCandidateBytes(installed, plan.Target.ArtifactSHA256, 0755); err != nil {
		return err
	}
	previous, err := readExactReleaseImage(productReleaseBackup(dir, plan), plan.Current.ArtifactSHA256, 0600)
	if err != nil {
		return err
	}
	return atomicWrite(installed, previous, 0755)
}

func publishPreparedProduct(cfg productConfig, activation string, plan releasePlan, planBytes []byte) error {
	lock, err := lockReleaseDirectory(releaseCandidateDir)
	if err != nil {
		return err
	}
	defer lock.Close()
	if verifyCandidateBytes(installedProduct, plan.Target.ArtifactSHA256, 0755) == nil {
		if err := verifyCandidateBytes(productReleaseBackup(releaseCandidateDir, plan), plan.Current.ArtifactSHA256, 0600); err != nil {
			return fmt.Errorf("cannot recover replacement without the original Agent image: %w", err)
		}
		return syncParent(installedProduct)
	}
	if err := verifyCandidateBytes(installedProduct, plan.Current.ArtifactSHA256, 0755); err != nil {
		return err
	}
	if err := revalidateReleasePlan(cfg, plan.CommandID, activation, planBytes,
		func(body []byte) ([]byte, int, error) {
			return tunnelRequest(cfg, releaseInstallPath, body)
		}); err != nil {
		return err
	}
	return replacePreparedProduct(releaseCandidateDir, installedProduct, plan)
}
