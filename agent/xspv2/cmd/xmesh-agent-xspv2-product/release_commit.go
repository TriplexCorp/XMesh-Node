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
	"strconv"
)

const (
	releaseCommitPath = "/api/v1/node/agent-release-commit"
	releaseAbortPath  = "/api/v1/node/agent-release-abort"
	releaseCommitFile = stateRoot + "/release-commit.json"
	installedProduct  = "/usr/local/bin/xmesh-agent-xspv2-product"
)

type releaseCommitRequest struct {
	CommandID  int64           `json:"commandId"`
	PlanSHA256 string          `json:"planSha256"`
	Installed  releaseIdentity `json:"installed"`
}

type releaseCommitReceipt struct {
	Schema           string          `json:"schema"`
	NodeID           int64           `json:"nodeId"`
	CommandID        int64           `json:"commandId"`
	ActivationSHA256 string          `json:"activationSha256"`
	PlanSHA256       string          `json:"planSha256"`
	Installed        releaseIdentity `json:"installed"`
}

func verifyReleaseCommit(raw []byte, cfg productConfig, activation string, running releaseIdentity) (releaseCommitReceipt, error) {
	return verifyReleaseOutcome(raw, cfg, activation, running, "commit", releaseCommitPath)
}

func verifyReleaseOutcome(raw []byte, cfg productConfig, activation string, running releaseIdentity, operation, path string) (releaseCommitReceipt, error) {
	var receipt releaseCommitReceipt
	message := "panel.product.release-" + operation
	parsed, err := parseEnvelope(raw, message, path, 2)
	if err != nil || checkUniqueJSONKeys(parsed.Payload) != nil {
		return receipt, errors.New("invalid release commit envelope")
	}
	d := json.NewDecoder(bytes.NewReader(parsed.Payload))
	d.DisallowUnknownFields()
	if d.Decode(&receipt) != nil || d.Decode(new(any)) != io.EOF ||
		receipt.Schema != "xmesh-product-agent-release-"+operation+"-v1" || receipt.NodeID != cfg.NodeID ||
		receipt.CommandID <= 0 || receipt.ActivationSHA256 != activation || receipt.Installed != running ||
		!validForwardProductRelease(cfg.ReleaseIdentity, running) ||
		parsed.Env.Revision != running.SourceRevision {
		return releaseCommitReceipt{}, errors.New("release commit does not identify this activation and executable")
	}
	planDigest, err := hex.DecodeString(receipt.PlanSHA256)
	if err != nil || len(planDigest) != sha256.Size || hex.EncodeToString(planDigest) != receipt.PlanSHA256 {
		return releaseCommitReceipt{}, errors.New("invalid release commit plan digest")
	}
	if _, err := verifyDurablePanelEnvelope(raw, cfg, message, path,
		strconv.FormatInt(receipt.CommandID, 10)); err != nil {
		return releaseCommitReceipt{}, err
	}
	return receipt, nil
}

func originalActivationDigest() (string, error) {
	raw, err := strictFile(activationReceipt, 0600)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func verifyInstalledTarget(running releaseIdentity) error {
	return verifyCandidateBytes(installedProduct, running.ArtifactSHA256, 0755)
}

// Only the installed target can send the confirmation. No script or
// heartbeat can supply an asserted identity as a CLI argument.
func confirmInstalledRelease(command int64) error {
	if command <= 0 || os.Geteuid() != 0 {
		return errors.New("release confirmation requires the installed root Agent and a command ID")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := verifyEnrolledRelease(cfg, cfg.ReleaseIdentity); err != nil {
		return err
	}
	activation, err := originalActivationDigest()
	if err != nil {
		return err
	}
	running, err := identity()
	if err != nil {
		return err
	}
	if err := verifyInstalledTarget(running); err != nil {
		return err
	}
	planBytes, err := preparedReleasePlan(releaseCandidateDir, command)
	if err != nil {
		return err
	}
	// An expired plan can identify a previous commit for recovery. Nexus
	// enforces the signed deadline before recording any new commit.
	plan, err := decodeReleasePlan(planBytes, cfg, command, activation, false)
	if err != nil || plan.Target != running {
		return errors.New("the prepared plan does not cover the installed executable")
	}
	planHash := sha256.Sum256(planBytes)
	planSHA := hex.EncodeToString(planHash[:])
	body, err := json.Marshal(releaseCommitRequest{CommandID: command, PlanSHA256: planSHA, Installed: running})
	if err != nil {
		return err
	}
	cfgTarget := cfg
	cfgTarget.ReleaseIdentity = running
	reply, status, err := tunnelRequest(cfgTarget, releaseCommitPath, body)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("Nexus did not confirm installed release: HTTP %d", status)
	}
	receipt, err := verifyReleaseCommit(reply, cfg, activation, running)
	if err != nil || receipt.CommandID != command || receipt.PlanSHA256 != planSHA {
		return errors.New("Nexus release confirmation does not match the prepared command")
	}
	return atomicWrite(releaseCommitFile, reply, 0600)
}

// Preserve the original activation's digest and cryptographic evidence;
// only the revision used for subsequent authenticated requests changes.
func checkOperationalRelease(cfg productConfig, running releaseIdentity) error {
	raw, err := strictFile(releaseCommitFile, 0600)
	if errors.Is(err, os.ErrNotExist) {
		if running == cfg.ReleaseIdentity {
			return nil
		}
		return errors.New("running strict-PQ Agent differs from enrolled release identity: signed release commit required")
	}
	if err != nil {
		return err
	}
	activation, err := originalActivationDigest()
	if err != nil {
		return err
	}
	if _, err := verifyReleaseCommit(raw, cfg, activation, running); err != nil {
		return err
	}
	return verifyInstalledTarget(running)
}
