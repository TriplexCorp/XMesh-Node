//go:build linux && xspv2_powercut_qualification && !xspv2_crash_test

package keyring

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"
)

const (
	powercutLabModeEnv     = "XMESH_XSPV2_POWERCUT_LAB_OPERATION"
	powercutLabVaultEnv    = "XMESH_XSPV2_POWERCUT_LAB_VAULT"
	powercutLabMasterEnv   = "XMESH_XSPV2_POWERCUT_LAB_MASTER"
	powercutLabOldEpochEnv = "XMESH_XSPV2_POWERCUT_LAB_OLD_EPOCH"
	powercutLabEdIDEnv     = "XMESH_XSPV2_POWERCUT_LAB_ED_ID"
	powercutLabPQIDEnv     = "XMESH_XSPV2_POWERCUT_LAB_PQ_ID"
)

func requirePowercutLabSnapshot(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("lab rotation snapshot is not a private regular file: %s", path)
	}
}

func powercutLabCommand(
	mode, point, runID, vault, master string,
	oldEpoch uint64,
	candidate PublicBundle,
	writer *os.File,
) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestPowercutLabOperationHelper$")
	cmd.ExtraFiles = []*os.File{writer}
	cmd.Env = append(os.Environ(),
		powercutLabModeEnv+"="+mode,
		powercutLabVaultEnv+"="+vault,
		powercutLabMasterEnv+"="+master,
		powercutLabOldEpochEnv+"="+strconv.FormatUint(oldEpoch, 10),
		powercutLabEdIDEnv+"="+candidate.EdKeyID,
		powercutLabPQIDEnv+"="+candidate.PQKeyID,
		powercutPointEnv+"="+point,
		powercutArmEnv+"="+powercutArmValue,
		powercutRunIDEnv+"="+runID,
		powercutSignalFDEnv+"=3",
	)
	return cmd
}

func runPowercutLabOperation(
	t *testing.T,
	mode, point, vault, master string,
	oldEpoch uint64,
	candidate PublicBundle,
) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	runID := "p0e4a5-" + point
	cmd := powercutLabCommand(mode, point, runID, vault, master, oldEpoch, candidate, writer)
	if err = cmd.Start(); err != nil {
		_ = writer.Close()
		t.Fatal(err)
	}
	_ = writer.Close()
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()

	lineCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(reader)
		if scanner.Scan() {
			lineCh <- scanner.Text()
			return
		}
		if scanErr := scanner.Err(); scanErr != nil {
			errCh <- scanErr
			return
		}
		errCh <- errors.New("lab operation closed signal FD before arming")
	}()

	want := fmt.Sprintf("XSP2-POWERCUT-ARMED-V1 run=%s point=%s", runID, point)
	select {
	case line := <-lineCh:
		if line != want {
			t.Fatalf("wrong lab-operation arm marker: got=%q want=%q", line, want)
		}
	case readErr := <-errCh:
		t.Fatal(readErr)
	case <-time.After(3 * time.Second):
		t.Fatal("real keyring lab operation did not reach selected power-cut checkpoint")
	}

	// CI terminates the blocked child only to prove source/operation reachability.
	// This process kill is explicitly NOT physical power-loss evidence.
	if err = cmd.Process.Kill(); err != nil {
		t.Fatalf("terminate blocked CI lab child: %v", err)
	}
	if err = cmd.Wait(); err == nil {
		t.Fatal("blocked lab child unexpectedly exited cleanly")
	}
	cmd.Process = nil
}

func TestPowercutLabOperationActivationMatrix(t *testing.T) {
	for _, point := range []string{"after-previous", "after-floor", "after-active"} {
		t.Run(point, func(t *testing.T) {
			vault, master, original := rotationFixture(t)
			candidate, err := PrepareRotation(vault, master, original.KeyEpoch)
			if err != nil {
				t.Fatal(err)
			}

			runPowercutLabOperation(t, "activate", point, vault, master, original.KeyEpoch, candidate)
			requirePowercutLabSnapshot(t, previousPath(vault))
			requirePowercutLabSnapshot(t, stagedPath(vault))

			switch point {
			case "after-previous":
				floor, floorErr := readFloor(vault)
				if floorErr != nil || floor != original.KeyEpoch {
					t.Fatalf("after-previous marker did not preserve old floor: floor=%d err=%v", floor, floorErr)
				}
				current, currentErr := Description(vault, master)
				if currentErr != nil || current.KeyEpoch != original.KeyEpoch || current.EdKeyID != original.EdKeyID {
					t.Fatalf("after-previous marker changed active identity: %+v err=%v", current, currentErr)
				}
			case "after-floor":
				floor, floorErr := readFloor(vault)
				if floorErr != nil || floor != candidate.KeyEpoch {
					t.Fatalf("after-floor marker did not persist new floor: floor=%d err=%v", floor, floorErr)
				}
				if _, currentErr := Description(vault, master); currentErr == nil {
					t.Fatal("after-floor marker still accepted the old active vault")
				}
			case "after-active":
				current, currentErr := Description(vault, master)
				if currentErr != nil || current.KeyEpoch != candidate.KeyEpoch || current.EdKeyID != candidate.EdKeyID || current.PQKeyID != candidate.PQKeyID {
					t.Fatalf("after-active marker did not expose complete candidate identity: %+v err=%v", current, currentErr)
				}
			default:
				t.Fatalf("unexpected activation checkpoint %q", point)
			}
		})
	}
}

func TestPowercutLabOperationRecoveryMatrix(t *testing.T) {
	t.Run("after-recovery-abort", func(t *testing.T) {
		vault, master, original := rotationFixture(t)
		candidate, err := PrepareRotation(vault, master, original.KeyEpoch)
		if err != nil {
			t.Fatal(err)
		}
		activeRaw, err := os.ReadFile(vault)
		if err != nil {
			t.Fatal(err)
		}
		if err = atomicFile(previousPath(vault), activeRaw); err != nil {
			t.Fatal(err)
		}

		runPowercutLabOperation(t, "recover", "after-recovery-abort", vault, master, original.KeyEpoch, candidate)
		current, err := Description(vault, master)
		if err != nil || current.KeyEpoch != original.KeyEpoch || current.EdKeyID != original.EdKeyID {
			t.Fatalf("recovery-abort marker did not retain previous identity: %+v err=%v", current, err)
		}
		if _, err = os.Lstat(previousPath(vault)); !os.IsNotExist(err) {
			t.Fatal("recovery-abort marker was emitted before previous snapshot removal became durable")
		}
		requirePowercutLabSnapshot(t, stagedPath(vault))
	})

	t.Run("after-recovery-active", func(t *testing.T) {
		vault, master, original := rotationFixture(t)
		candidate, err := PrepareRotation(vault, master, original.KeyEpoch)
		if err != nil {
			t.Fatal(err)
		}
		activeRaw, err := os.ReadFile(vault)
		if err != nil {
			t.Fatal(err)
		}
		if err = atomicFile(previousPath(vault), activeRaw); err != nil {
			t.Fatal(err)
		}
		if err = updateFloor(vault, candidate.KeyEpoch); err != nil {
			t.Fatal(err)
		}

		runPowercutLabOperation(t, "recover", "after-recovery-active", vault, master, original.KeyEpoch, candidate)
		current, err := Description(vault, master)
		if err != nil || current.KeyEpoch != candidate.KeyEpoch || current.EdKeyID != candidate.EdKeyID || current.PQKeyID != candidate.PQKeyID {
			t.Fatalf("recovery-active marker did not expose complete candidate identity: %+v err=%v", current, err)
		}
		requirePowercutLabSnapshot(t, previousPath(vault))
		requirePowercutLabSnapshot(t, stagedPath(vault))
	})
}

func TestPowercutLabOperationHelper(t *testing.T) {
	mode := os.Getenv(powercutLabModeEnv)
	if mode == "" {
		return
	}
	oldEpoch, err := strconv.ParseUint(os.Getenv(powercutLabOldEpochEnv), 10, 64)
	if err != nil || oldEpoch == 0 {
		fmt.Fprintln(os.Stderr, "invalid lab-operation old epoch")
		os.Exit(90)
	}
	vault := os.Getenv(powercutLabVaultEnv)
	master := os.Getenv(powercutLabMasterEnv)
	if vault == "" || master == "" {
		fmt.Fprintln(os.Stderr, "lab-operation vault/master missing")
		os.Exit(91)
	}

	switch mode {
	case "activate":
		_, err = ActivatePreparedRotation(
			vault,
			master,
			oldEpoch,
			os.Getenv(powercutLabEdIDEnv),
			os.Getenv(powercutLabPQIDEnv),
		)
	case "recover":
		_, err = RecoverRotation(vault, master)
	default:
		err = fmt.Errorf("unknown lab-operation mode %q", mode)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(92)
	}

	// With a correctly selected checkpoint the lab hook never returns. Reaching
	// this line means the requested physical cut point did not belong to the
	// actual operation and the run must fail closed rather than claim evidence.
	fmt.Fprintln(os.Stderr, "lab operation completed without reaching selected power-cut checkpoint")
	os.Exit(93)
}
