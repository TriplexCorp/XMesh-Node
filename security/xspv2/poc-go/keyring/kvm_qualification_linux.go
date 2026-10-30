//go:build linux && xspv2_powercut_qualification && !xspv2_crash_test

package keyring

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// KVMQualificationPlan describes one isolated manual KVM durability run.
// It is lab-only and is never compiled into the normal Agent artifact.
type KVMQualificationPlan struct {
	Checkpoint string       `json:"checkpoint"`
	StateDir   string       `json:"stateDir"`
	Vault      string       `json:"vault"`
	Master     string       `json:"master"`
	Original   PublicBundle `json:"original"`
	Candidate  PublicBundle `json:"candidate"`
}

var kvmQualificationPoints = map[string]struct{}{
	"after-previous":        {},
	"after-floor":           {},
	"after-active":          {},
	"after-recovery-abort":  {},
	"after-recovery-active": {},
}

func ensureFreshQualificationDir(root string) error {
	if root == "" || !filepath.IsAbs(root) {
		return errors.New("qualification state directory must be an absolute path")
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errors.New("qualification state directory already exists; use a fresh directory for every run")
		}
		return err
	}
	return nil
}

// PrepareKVMQualification creates a fresh isolated keyring and the exact state
// required to enter one durability checkpoint. The returned state is not the
// production Agent keyring and does not enable strict-pq.
func PrepareKVMQualification(root string, nodeID int64, checkpoint string) (KVMQualificationPlan, error) {
	var empty KVMQualificationPlan
	if nodeID <= 0 {
		return empty, errors.New("node ID must be positive")
	}
	if _, ok := kvmQualificationPoints[checkpoint]; !ok {
		return empty, errors.New("unsupported KVM qualification checkpoint")
	}
	if err := ensureFreshQualificationDir(root); err != nil {
		return empty, err
	}
	master := filepath.Join(root, "wrapping.key")
	vault := filepath.Join(root, "private.json")
	if err := CreateMasterKey(master); err != nil {
		return empty, fmt.Errorf("create qualification master key: %w", err)
	}
	original, err := Initialize(vault, master, nodeID, "node_request")
	if err != nil {
		return empty, fmt.Errorf("initialize qualification vault: %w", err)
	}
	candidate, err := PrepareRotation(vault, master, original.KeyEpoch)
	if err != nil {
		return empty, fmt.Errorf("prepare qualification rotation: %w", err)
	}

	// Recovery checkpoints need the exact crash-recovery precondition that the
	// production recovery routine expects. These are the same durable state
	// shapes used by the existing lab-operation tests, but persisted in a
	// caller-selected directory that survives a VPS hard stop.
	if checkpoint == "after-recovery-abort" || checkpoint == "after-recovery-active" {
		activeRaw, readErr := os.ReadFile(vault)
		if readErr != nil {
			return empty, readErr
		}
		if err = atomicFile(previousPath(vault), activeRaw); err != nil {
			return empty, err
		}
		if checkpoint == "after-recovery-active" {
			if err = updateFloor(vault, candidate.KeyEpoch); err != nil {
				return empty, err
			}
		}
	}

	return KVMQualificationPlan{
		Checkpoint: checkpoint,
		StateDir:   root,
		Vault:      vault,
		Master:     master,
		Original:   original,
		Candidate:  candidate,
	}, nil
}

// ExecuteKVMQualification enters the real keyring operation and never returns
// after reaching the selected checkpoint. The existing lab hook emits ARMED to
// signalFD and then sleeps until the VPS is stopped externally.
func ExecuteKVMQualification(plan KVMQualificationPlan, runID string, signalFD int) error {
	if _, ok := kvmQualificationPoints[plan.Checkpoint]; !ok {
		return errors.New("invalid qualification plan checkpoint")
	}
	if !validPowercutToken(runID) {
		return errors.New("invalid qualification run ID")
	}
	if signalFD < 3 || signalFD > 1024 {
		return errors.New("invalid qualification signal file descriptor")
	}
	if err := os.Setenv(powercutPointEnv, plan.Checkpoint); err != nil {
		return err
	}
	if err := os.Setenv(powercutArmEnv, powercutArmValue); err != nil {
		return err
	}
	if err := os.Setenv(powercutRunIDEnv, runID); err != nil {
		return err
	}
	if err := os.Setenv(powercutSignalFDEnv, strconv.Itoa(signalFD)); err != nil {
		return err
	}

	switch plan.Checkpoint {
	case "after-previous", "after-floor", "after-active":
		_, err := ActivatePreparedRotation(
			plan.Vault,
			plan.Master,
			plan.Original.KeyEpoch,
			plan.Candidate.EdKeyID,
			plan.Candidate.PQKeyID,
		)
		return err
	case "after-recovery-abort", "after-recovery-active":
		_, err := RecoverRotation(plan.Vault, plan.Master)
		return err
	default:
		return errors.New("unsupported qualification checkpoint")
	}
}

// InspectKVMQualification validates and, where required, completes recovery
// after the guest boots again. It returns only a complete old or new identity;
// any torn or inconsistent state fails closed.
func InspectKVMQualification(plan KVMQualificationPlan) (string, PublicBundle, error) {
	var empty PublicBundle
	var current PublicBundle
	var err error

	switch plan.Checkpoint {
	case "after-recovery-abort":
		// The recovery-abort checkpoint is emitted only after the old .previous
		// snapshot has been removed durably. There is intentionally nothing left
		// for RecoverRotation to consume; the original identity must simply open.
		current, err = Description(plan.Vault, plan.Master)
	case "after-previous", "after-floor", "after-active", "after-recovery-active":
		current, err = RecoverRotation(plan.Vault, plan.Master)
	default:
		return "", empty, errors.New("unsupported qualification checkpoint")
	}
	if err != nil {
		return "", empty, err
	}

	if current.KeyEpoch == plan.Original.KeyEpoch &&
		current.EdKeyID == plan.Original.EdKeyID && current.PQKeyID == plan.Original.PQKeyID {
		if plan.Checkpoint != "after-previous" && plan.Checkpoint != "after-recovery-abort" {
			return "", empty, errors.New("unexpected previous identity after checkpoint")
		}
		return "previous-complete", current, nil
	}
	if current.KeyEpoch == plan.Candidate.KeyEpoch &&
		current.EdKeyID == plan.Candidate.EdKeyID && current.PQKeyID == plan.Candidate.PQKeyID {
		if plan.Checkpoint == "after-previous" || plan.Checkpoint == "after-recovery-abort" {
			return "", empty, errors.New("unexpected next identity after checkpoint")
		}
		return "next-complete", current, nil
	}
	return "", empty, errors.New("post-boot identity is neither complete previous nor complete next state")
}
