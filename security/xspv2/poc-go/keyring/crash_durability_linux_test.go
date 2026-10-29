//go:build linux && xspv2_crash_test

package keyring

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
)

const (
	crashHelperModeEnv = "XMESH_XSPV2_CRASH_HELPER"
	crashVaultEnv      = "XMESH_XSPV2_CRASH_VAULT"
	crashMasterEnv     = "XMESH_XSPV2_CRASH_MASTER"
	crashOldEpochEnv   = "XMESH_XSPV2_CRASH_OLD_EPOCH"
	crashEdIDEnv       = "XMESH_XSPV2_CRASH_ED_ID"
	crashPQIDEnv       = "XMESH_XSPV2_CRASH_PQ_ID"
)

func expectCrashExit(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 86 {
		t.Fatalf("expected durability crash exit 86, got %v", err)
	}
}

func crashCommand(mode, point, vault, master string, oldEpoch uint64, candidate PublicBundle) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashDurabilityHelper$")
	cmd.Env = append(os.Environ(),
		crashHelperModeEnv+"="+mode,
		crashPointEnv+"="+point,
		crashVaultEnv+"="+vault,
		crashMasterEnv+"="+master,
		crashOldEpochEnv+"="+strconv.FormatUint(oldEpoch, 10),
		crashEdIDEnv+"="+candidate.EdKeyID,
		crashPQIDEnv+"="+candidate.PQKeyID,
	)
	return cmd
}

func requireRetainedSnapshot(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("retained snapshot is not a private regular file: %s", path)
	}
}

func TestActivatePreparedRotationCrashMatrix(t *testing.T) {
	for _, point := range []string{"after-previous", "after-floor", "after-active"} {
		t.Run(point, func(t *testing.T) {
			vault, master, original := rotationFixture(t)
			candidate, err := PrepareRotation(vault, master, original.KeyEpoch)
			if err != nil {
				t.Fatal(err)
			}
			expectCrashExit(t, crashCommand("activate", point, vault, master, original.KeyEpoch, candidate))

			requireRetainedSnapshot(t, previousPath(vault))
			requireRetainedSnapshot(t, stagedPath(vault))

			switch point {
			case "after-previous":
				floor, err := readFloor(vault)
				if err != nil || floor != original.KeyEpoch {
					t.Fatalf("floor advanced before its durable step: floor=%d err=%v", floor, err)
				}
				current, err := Description(vault, master)
				if err != nil || current.KeyEpoch != original.KeyEpoch || current.EdKeyID != original.EdKeyID {
					t.Fatalf("pre-floor crash changed active identity: %+v err=%v", current, err)
				}
				recovered, err := RecoverRotation(vault, master)
				if err != nil || recovered.KeyEpoch != original.KeyEpoch {
					t.Fatalf("pre-floor recovery did not return to prepared state: %+v err=%v", recovered, err)
				}
				if _, err := os.Lstat(previousPath(vault)); !os.IsNotExist(err) {
					t.Fatal("pre-floor recovery retained a blocking previous snapshot")
				}
				if err := AbortPreparedRotation(vault, master, original.KeyEpoch); err != nil {
					t.Fatalf("prepared candidate could not be explicitly aborted after recovery: %v", err)
				}
			case "after-floor":
				floor, err := readFloor(vault)
				if err != nil || floor != candidate.KeyEpoch {
					t.Fatalf("new floor was not durable: floor=%d err=%v", floor, err)
				}
				if _, err := Description(vault, master); err == nil {
					t.Fatal("old active identity was accepted after the epoch floor advanced")
				}
				recovered, err := RecoverRotation(vault, master)
				if err != nil || recovered.KeyEpoch != candidate.KeyEpoch {
					t.Fatalf("post-floor crash did not recover forward: %+v err=%v", recovered, err)
				}
				current, err := Description(vault, master)
				if err != nil || current.KeyEpoch != candidate.KeyEpoch || current.EdKeyID != candidate.EdKeyID {
					t.Fatalf("forward-recovered identity is not active: %+v err=%v", current, err)
				}
			case "after-active":
				current, err := Description(vault, master)
				if err != nil || current.KeyEpoch != candidate.KeyEpoch || current.EdKeyID != candidate.EdKeyID {
					t.Fatalf("durably swapped identity was not readable after crash: %+v err=%v", current, err)
				}
				recovered, err := RecoverRotation(vault, master)
				if err != nil || recovered.KeyEpoch != candidate.KeyEpoch {
					t.Fatalf("post-swap recovery was not idempotent: %+v err=%v", recovered, err)
				}
			}
		})
	}
}

func TestRecoverRotationCrashMatrix(t *testing.T) {
	t.Run("abort-pre-floor", func(t *testing.T) {
		vault, master, original := rotationFixture(t)
		candidate, err := PrepareRotation(vault, master, original.KeyEpoch)
		if err != nil {
			t.Fatal(err)
		}
		activeRaw, err := os.ReadFile(vault)
		if err != nil {
			t.Fatal(err)
		}
		if err := atomicFile(previousPath(vault), activeRaw); err != nil {
			t.Fatal(err)
		}

		expectCrashExit(t, crashCommand("recover", "after-recovery-abort", vault, master, original.KeyEpoch, candidate))
		current, err := Description(vault, master)
		if err != nil || current.KeyEpoch != original.KeyEpoch || current.EdKeyID != original.EdKeyID {
			t.Fatalf("recovery crash before cutover changed active identity: %+v err=%v", current, err)
		}
		if _, err := os.Lstat(previousPath(vault)); !os.IsNotExist(err) {
			t.Fatal("completed pre-floor recovery was not durable before crash")
		}
		if err := AbortPreparedRotation(vault, master, original.KeyEpoch); err != nil {
			t.Fatalf("candidate was not safely abortable after recovery crash: %v", err)
		}
	})

	t.Run("forward-post-floor", func(t *testing.T) {
		vault, master, original := rotationFixture(t)
		candidate, err := PrepareRotation(vault, master, original.KeyEpoch)
		if err != nil {
			t.Fatal(err)
		}
		activeRaw, err := os.ReadFile(vault)
		if err != nil {
			t.Fatal(err)
		}
		if err := atomicFile(previousPath(vault), activeRaw); err != nil {
			t.Fatal(err)
		}
		if err := updateFloor(vault, candidate.KeyEpoch); err != nil {
			t.Fatal(err)
		}

		expectCrashExit(t, crashCommand("recover", "after-recovery-active", vault, master, original.KeyEpoch, candidate))
		current, err := Description(vault, master)
		if err != nil || current.KeyEpoch != candidate.KeyEpoch || current.EdKeyID != candidate.EdKeyID {
			t.Fatalf("forward recovery was not durable before crash: %+v err=%v", current, err)
		}
		requireRetainedSnapshot(t, previousPath(vault))
		requireRetainedSnapshot(t, stagedPath(vault))
		again, err := RecoverRotation(vault, master)
		if err != nil || again.KeyEpoch != candidate.KeyEpoch {
			t.Fatalf("forward recovery was not idempotent after restart: %+v err=%v", again, err)
		}
	})
}

func TestCrashDurabilityHelper(t *testing.T) {
	mode := os.Getenv(crashHelperModeEnv)
	if mode == "" {
		return
	}
	vault := os.Getenv(crashVaultEnv)
	master := os.Getenv(crashMasterEnv)
	oldEpoch, err := strconv.ParseUint(os.Getenv(crashOldEpochEnv), 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(87)
	}

	switch mode {
	case "activate":
		_, err = ActivatePreparedRotation(vault, master, oldEpoch, os.Getenv(crashEdIDEnv), os.Getenv(crashPQIDEnv))
	case "recover":
		_, err = RecoverRotation(vault, master)
	default:
		err = fmt.Errorf("unknown crash helper mode %q", mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(88)
	}
	os.Exit(0)
}
