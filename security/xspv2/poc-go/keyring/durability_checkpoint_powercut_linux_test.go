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
		writer.Close()
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

	// A correctly armed helper must still be alive and blocked. If it exited,
	// the evidence would describe a local process crash instead of a point where
	// an independent controller can remove physical power.
	if err = cmd.Process.Signal(os.Signal(syscallSignalZero{})); err == nil {
		return
	}
	// os.Process.Signal cannot portably express signal 0 without syscall. Keep
	// the assertion simple: a non-blocking Wait must not complete immediately.
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	select {
	case waitErr := <-waitCh:
		t.Fatalf("armed qualification helper exited before external cut: %v", waitErr)
	case <-time.After(100 * time.Millisecond):
	}
	cmd.Process = nil
}

// syscallSignalZero deliberately implements os.Signal without importing
// platform-specific syscall constants. Signal(0) is not portable through the
// os package, so the test falls back to the Wait timeout when unsupported.
type syscallSignalZero struct{}

func (syscallSignalZero) String() string { return "signal 0" }
func (syscallSignalZero) Signal()        {}

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
