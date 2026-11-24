package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"
)

const releasePlanPath = "/api/v1/node/agent-release-plan"

type releasePlan struct {
	Schema           string          `json:"schema"`
	NodeID           int64           `json:"nodeId"`
	KeyEpoch         int64           `json:"keyEpoch"`
	CommandID        int64           `json:"commandId"`
	ExpiresAtMS      int64           `json:"expiresAtMs"`
	ActivationSHA256 string          `json:"activationSha256"`
	Current          releaseIdentity `json:"current"`
	Target           releaseIdentity `json:"target"`
}

func verifyReleasePlan(raw []byte, cfg productConfig, command int64, activation string) (releasePlan, error) {
	return decodeReleasePlan(raw, cfg, command, activation, true)
}

func decodeReleasePlan(raw []byte, cfg productConfig, command int64, activation string, requireLive bool) (releasePlan, error) {
	var plan releasePlan
	if command <= 0 {
		return plan, errors.New("invalid release command")
	}
	parsed, err := verifyDurablePanelEnvelope(raw, cfg, "panel.product.release-plan", releasePlanPath,
		strconv.FormatInt(command, 10))
	if err != nil {
		return plan, err
	}
	if err := checkUniqueJSONKeys(parsed.Payload); err != nil {
		return plan, err
	}
	decoder := json.NewDecoder(bytes.NewReader(parsed.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return plan, err
	}
	digest, digestErr := hex.DecodeString(plan.Target.ArtifactSHA256)
	revision, revisionErr := hex.DecodeString(plan.Target.SourceRevision)
	now := time.Now().UnixMilli()
	if decoder.Decode(new(any)) != io.EOF ||
		plan.Schema != "xmesh-product-agent-release-plan-v1" || plan.NodeID != cfg.NodeID ||
		plan.CommandID != command || plan.KeyEpoch != parsed.Env.KeyEpoch ||
		plan.ActivationSHA256 != activation || plan.Current != cfg.ReleaseIdentity ||
		!validForwardProductRelease(plan.Current, plan.Target) ||
		digestErr != nil || len(digest) != sha256.Size ||
		revisionErr != nil || len(revision) != 20 ||
		parsed.Env.Revision != plan.Target.SourceRevision ||
		parsed.Env.IssuedAtMS > now || plan.ExpiresAtMS <= parsed.Env.IssuedAtMS ||
		(requireLive && plan.ExpiresAtMS <= now) ||
		plan.ExpiresAtMS-parsed.Env.IssuedAtMS > 15*60*1000 {
		return releasePlan{}, errors.New("release plan does not match the enrolled transition")
	}
	return plan, nil
}

func openPrivateReleaseImage(path string, mode os.FileMode) (*os.File, int64, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	source := os.NewFile(uintptr(fd), path)
	info, err := source.Stat()
	if err != nil {
		source.Close()
		return nil, 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Size() <= 0 || info.Size() > maxReleaseArtifactBytes {
		source.Close()
		return nil, 0, errors.New("unsafe staged Agent artifact")
	}
	return source, info.Size(), nil
}

func verifyCandidateBytes(path, expected string, mode os.FileMode) error {
	source, expectedSize, err := openPrivateReleaseImage(path, mode)
	if err != nil {
		return err
	}
	defer source.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(source, maxReleaseArtifactBytes+1))
	if err != nil || size != expectedSize || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("staged Agent bytes do not match the signed target")
	}
	return nil
}

func installedReleaseEnrollment() (productConfig, string, error) {
	if os.Geteuid() != 0 {
		return productConfig{}, "", errors.New("release verification requires the installed root Agent")
	}
	cfg, err := loadConfig()
	if err != nil {
		return cfg, "", err
	}
	if err := verifyEnrolledRelease(cfg, cfg.ReleaseIdentity); err != nil {
		return cfg, "", err
	}
	if err := verifyCandidateBytes(installedProduct,
		cfg.ReleaseIdentity.ArtifactSHA256, 0755); err != nil {
		return cfg, "", err
	}
	receipt, err := strictFile(activationReceipt, 0600)
	if err != nil {
		return cfg, "", err
	}
	activation := sha256.Sum256(receipt)
	return cfg, hex.EncodeToString(activation[:]), nil
}

func verifyStagedRelease(command int64, planPath, artifactPath string) error {
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
	return verifyCandidateBytes(artifactPath, plan.Target.ArtifactSHA256, 0600)
}

func fetchStagedRelease(command int64, output string) error {
	if command <= 0 || output == "" {
		return errors.New("release command and output file required")
	}
	cfg, activation, err := installedReleaseEnrollment()
	if err != nil {
		return err
	}
	body, err := json.Marshal(struct {
		CommandID int64           `json:"commandId"`
		Current   releaseIdentity `json:"current"`
	}{command, cfg.ReleaseIdentity})
	if err != nil {
		return err
	}
	raw, status, err := tunnelRequest(cfg, releasePlanPath, body)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("release plan unavailable: HTTP %d", status)
	}
	if _, err := verifyReleasePlan(raw, cfg, command, activation); err != nil {
		return err
	}
	return atomicWrite(output, raw, 0600)
}
