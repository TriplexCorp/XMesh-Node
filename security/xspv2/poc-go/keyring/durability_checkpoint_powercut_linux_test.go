//go:build linux && xspv2_powercut_qualification && !xspv2_crash_test

package keyring

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const powercutHelperEnv = "XMESH_XSPV2_POWERCUT_HELPER"

func TestPowercutQualificationConfigRejectsAmbiguousInputs(t *testing.T) {
	if _, err := parsePowercutConfig("after-floor", powercutArmValue, "run-2026-10-29", "3"); err != nil {
		t.Fatalf("valid qualification config rejected: %v", err)
	}
	for name, input := range map[string][4]string{
		"unknown-point": {"after-db", powercutArmValue, "run-2026-10-29", "3"},
		"not-armed":     {"after-floor", "yes", "run-2026-10-29", "3"},
		"short-run":     {"after-floor", powercutArmValue, "tiny", "3"},
		"unsafe-run":    {"after-floor", powercutArmValue, "run with spaces", "3"},
		"stdio-fd":      {"after-floor", powercutArmValue, "run-2026-10-29", "1"},
		"bad-fd":        {"after-floor", powercutArmValue, "run-2026-10-29", "not-a-fd"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parsePowercutConfig(input[0], input[1], input[2], input[3]); err == nil {
				t.Fatal("unsafe power-cut qualification configuration accepted")
			}
		})
	}
}

func TestPowercutQualificationUnsetTargetIsNoop(t *testing.T) {
	t.Setenv(powercutPointEnv, "")
	rotationDurabilityCheckpoint("after-previous")
}

func TestPowercutQualificationArmsExternalControllerThenStops(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestPowercutQualificationHelper$")
	cmd.ExtraFiles = []*os.File{writer}
	cmd.Env = append(os.Environ(),
		powercutHelperEnv+"=1",
		powercutPointEnv+"=after-previous",
		powercutArmEnv+"="+powercutArmValue,
		powercutRunIDEnv+"=p0e4a-lab-run-0001",
		powercutSignalFDEnv+"=3",
	)
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
		errCh <- errors.New("power-cut helper closed signal channel without arming marker")
	}()

	select {
	case line := <-lineCh:
		want := "XSP2-POWERCUT-ARMED-V1 run=p0e4a-lab-run-0001 point=after-previous"
		if line != want {
			t.Fatalf("wrong external controller marker: %q", line)
		}
	case readErr := <-errCh:
		t.Fatal(readErr)
	case <-time.After(3 * time.Second):
		t.Fatal("lab hook did not arm external controller")
	}

	// Give the child a short opportunity to fail incorrectly. A correct lab
	// hook remains blocked until the independent controller removes power.
	time.Sleep(100 * time.Millisecond)
	if err = cmd.Process.Kill(); err != nil {
		t.Fatalf("armed qualification helper exited before external cut: %v", err)
	}
	if err = cmd.Wait(); err == nil {
		t.Fatal("expected parent to terminate blocked qualification helper")
	}
	cmd.Process = nil
}

func TestPowercutQualificationHelper(t *testing.T) {
	if os.Getenv(powercutHelperEnv) != "1" {
		return
	}
	rotationDurabilityCheckpoint("after-previous")
	t.Fatal("power-cut qualification hook returned after selected checkpoint")
}

func TestPowercutQualificationRunTokenGrammar(t *testing.T) {
	for _, good := range []string{"run-0001", "P0E4A_2026.10.29", strings.Repeat("a", 64)} {
		if !validPowercutToken(good) {
			t.Fatalf("valid run token rejected: %q", good)
		}
	}
	for _, bad := range []string{"short", "contains space", "slash/value", strings.Repeat("a", 65)} {
		if validPowercutToken(bad) {
			t.Fatalf("invalid run token accepted: %q", bad)
		}
	}
}
