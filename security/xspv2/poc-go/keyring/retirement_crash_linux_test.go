//go:build linux && xspv2_crash_test

package keyring

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

const (
	retireCrashHelperEnv = "XMESH_XSPV2_RETIRE_CRASH_HELPER"
	retireVaultEnv       = "XMESH_XSPV2_RETIRE_VAULT"
	retireMasterEnv      = "XMESH_XSPV2_RETIRE_MASTER"
	retireNodeIDEnv      = "XMESH_XSPV2_RETIRE_NODE_ID"
	retireFromEpochEnv   = "XMESH_XSPV2_RETIRE_FROM_EPOCH"
	retireToEpochEnv     = "XMESH_XSPV2_RETIRE_TO_EPOCH"
	retirePriorEdEnv     = "XMESH_XSPV2_RETIRE_PRIOR_ED"
	retirePriorPQEnv     = "XMESH_XSPV2_RETIRE_PRIOR_PQ"
	retireActiveEdEnv    = "XMESH_XSPV2_RETIRE_ACTIVE_ED"
	retireActivePQEnv    = "XMESH_XSPV2_RETIRE_ACTIVE_PQ"
	retireDigestEnv      = "XMESH_XSPV2_RETIRE_DIGEST"
)

func retirementCrashCommand(point, vault, master string, previous, candidate PublicBundle, digest string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestRetirementCrashHelper$")
	cmd.Env = append(os.Environ(),
		retireCrashHelperEnv+"=1",
		crashPointEnv+"="+point,
		retireVaultEnv+"="+vault,
		retireMasterEnv+"="+master,
		retireNodeIDEnv+"="+strconv.FormatInt(previous.NodeID, 10),
		retireFromEpochEnv+"="+strconv.FormatUint(previous.KeyEpoch, 10),
		retireToEpochEnv+"="+strconv.FormatUint(candidate.KeyEpoch, 10),
		retirePriorEdEnv+"="+previous.EdKeyID,
		retirePriorPQEnv+"="+previous.PQKeyID,
		retireActiveEdEnv+"="+candidate.EdKeyID,
		retireActivePQEnv+"="+candidate.PQKeyID,
		retireDigestEnv+"="+digest,
	)
	return cmd
}

func TestRetireAppliedRotationCrashMatrix(t *testing.T) {
	for _, point := range []string{"after-retirement-intent", "after-retirement-previous", "after-retirement-next"} {
		t.Run(point, func(t *testing.T) {
			vault, master, previous, candidate, _, _ := appliedRetirementFixture(t)
			digest := strings.Repeat("7a", 32)
			cmd := retirementCrashCommand(point, vault, master, previous, candidate, digest)
			err := cmd.Run()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 86 {
				t.Fatalf("expected retirement durability crash exit 86, got %v", err)
			}

			record, ok, err := DescribeRetirement(vault, master)
			if err != nil || !ok || record.AuthorizationSHA256 != digest {
				t.Fatalf("durable retirement intent missing after crash: %+v ok=%v err=%v", record, ok, err)
			}
			floor, err := readFloor(vault)
			if err != nil || floor != candidate.KeyEpoch {
				t.Fatalf("retirement crash changed epoch floor: %d err=%v", floor, err)
			}
			current, err := Description(vault, master)
			if err != nil || current.KeyEpoch != candidate.KeyEpoch || current.EdKeyID != candidate.EdKeyID {
				t.Fatalf("retirement crash changed active identity: %+v err=%v", current, err)
			}

			switch point {
			case "after-retirement-intent":
				requireRetainedSnapshot(t, previousPath(vault))
				requireRetainedSnapshot(t, stagedPath(vault))
			case "after-retirement-previous":
				if _, statErr := os.Lstat(previousPath(vault)); !os.IsNotExist(statErr) {
					t.Fatal("previous snapshot was not durably removed before crash")
				}
				requireRetainedSnapshot(t, stagedPath(vault))
			case "after-retirement-next":
				for _, path := range []string{previousPath(vault), stagedPath(vault)} {
					if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
						t.Fatalf("retired snapshot survived completed retirement crash: %s", path)
					}
				}
			}

			// Restart/retry must finish deterministically using the authenticated
			// intent even when .previous was already durably removed.
			active, err := RetireAppliedRotation(vault, master, previous.NodeID, previous.KeyEpoch, candidate.KeyEpoch,
				previous.EdKeyID, previous.PQKeyID, candidate.EdKeyID, candidate.PQKeyID, digest)
			if err != nil || active.KeyEpoch != candidate.KeyEpoch {
				t.Fatalf("retirement retry did not converge after %s: %+v err=%v", point, active, err)
			}
			for _, path := range []string{previousPath(vault), stagedPath(vault)} {
				if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
					t.Fatalf("retirement retry left old material after %s: %s", point, path)
				}
			}
		})
	}
}

func TestRetirementCrashHelper(t *testing.T) {
	if os.Getenv(retireCrashHelperEnv) == "" {
		return
	}
	nodeID, err := strconv.ParseInt(os.Getenv(retireNodeIDEnv), 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(87)
	}
	fromEpoch, err := strconv.ParseUint(os.Getenv(retireFromEpochEnv), 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(87)
	}
	toEpoch, err := strconv.ParseUint(os.Getenv(retireToEpochEnv), 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(87)
	}
	_, err = RetireAppliedRotation(
		os.Getenv(retireVaultEnv),
		os.Getenv(retireMasterEnv),
		nodeID,
		fromEpoch,
		toEpoch,
		os.Getenv(retirePriorEdEnv),
		os.Getenv(retirePriorPQEnv),
		os.Getenv(retireActiveEdEnv),
		os.Getenv(retireActivePQEnv),
		os.Getenv(retireDigestEnv),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(88)
	}
	os.Exit(0)
}
