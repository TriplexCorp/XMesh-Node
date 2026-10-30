//go:build linux && xspv2_crash_test

package recovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

const (
	retirementRecoveryCrashHelper = "XMESH_XSPV2_RETIRE_RECOVERY_HELPER"
	retirementRecoveryStateRoot   = "XMESH_XSPV2_RETIRE_RECOVERY_STATE_ROOT"
	retirementRecoveryAuthPath    = "XMESH_XSPV2_RETIRE_RECOVERY_AUTH"
	retirementRecoveryCPPath      = "XMESH_XSPV2_RETIRE_RECOVERY_CHECKPOINT"
	retirementRecoveryPinPath     = "XMESH_XSPV2_RETIRE_RECOVERY_PIN"
	retirementRecoveryNow         = "XMESH_XSPV2_RETIRE_RECOVERY_NOW"
)

func writeCrashJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRetireAuthorizedPreviousResumesAfterDurableIntentPastExpiry(t *testing.T) {
	signed, pin, checkpoint, layout := retirementFixture(t)
	dir := t.TempDir()
	authPath := filepath.Join(dir, "authorization.json")
	checkpointPath := filepath.Join(dir, "checkpoint.json")
	pinPath := filepath.Join(dir, "pin.json")
	writeCrashJSON(t, authPath, signed)
	writeCrashJSON(t, checkpointPath, checkpoint)
	writeCrashJSON(t, pinPath, pin)

	now := signed.Authorization.IssuedAtMS + 1
	cmd := exec.Command(os.Args[0], "-test.run=^TestRetireAuthorizedPreviousCrashHelper$")
	cmd.Env = append(os.Environ(),
		retirementRecoveryCrashHelper+"=1",
		"XMESH_XSPV2_CRASH_POINT=after-retirement-intent",
		retirementRecoveryStateRoot+"="+layout.Root,
		retirementRecoveryAuthPath+"="+authPath,
		retirementRecoveryCPPath+"="+checkpointPath,
		retirementRecoveryPinPath+"="+pinPath,
		retirementRecoveryNow+"="+strconv.FormatInt(now, 10),
	)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 86 {
		t.Fatalf("expected crash after durable retirement intent, got %v", err)
	}

	digest, err := RetirementAuthorizationDigest(signed)
	if err != nil {
		t.Fatal(err)
	}
	record, ok, err := keyring.DescribeRetirement(layout.Vault, layout.MasterKey)
	if err != nil || !ok || record.AuthorizationSHA256 != digest {
		t.Fatalf("retirement intent was not durable after crash: %+v ok=%v err=%v", record, ok, err)
	}
	for _, path := range []string{layout.Vault + ".previous", layout.Vault + ".next"} {
		if _, statErr := os.Lstat(path); statErr != nil {
			t.Fatalf("intent crash removed material before checkpoint: %s: %v", path, statErr)
		}
	}

	// The authorization is now expired and the owner/off-host generation floor
	// has advanced. Because the exact authenticated intent already existed before
	// the crash, this is a continuation of that deletion, not a new command.
	snapshot, err := RetireAuthorizedPrevious(signed, pin, checkpoint, checkpoint.Checkpoint.Generation+100,
		layout, signed.Authorization.ExpiresAtMS+60_000)
	if err != nil {
		t.Fatalf("durable intent could not resume after expiry/floor advance: %v", err)
	}
	if snapshot.KeyEpoch != signed.Authorization.ToEpoch || snapshot.PreviousRetained || snapshot.CandidateRetained {
		t.Fatalf("retirement resume did not converge: %+v", snapshot)
	}
}

func TestRetireAuthorizedPreviousCrashHelper(t *testing.T) {
	if os.Getenv(retirementRecoveryCrashHelper) == "" {
		return
	}
	read := func(path string, target any) error {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, target)
	}
	var signed SignedRetirementAuthorization
	if err := read(os.Getenv(retirementRecoveryAuthPath), &signed); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(87)
	}
	var checkpoint SignedCheckpoint
	if err := read(os.Getenv(retirementRecoveryCPPath), &checkpoint); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(87)
	}
	var pin OwnerPublic
	if err := read(os.Getenv(retirementRecoveryPinPath), &pin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(87)
	}
	now, err := strconv.ParseInt(os.Getenv(retirementRecoveryNow), 10, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(87)
	}
	layout, err := state.Open(os.Getenv(retirementRecoveryStateRoot))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(87)
	}
	_, err = RetireAuthorizedPrevious(signed, pin, checkpoint, checkpoint.Checkpoint.Generation, layout, now)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(88)
	}
	os.Exit(0)
}
