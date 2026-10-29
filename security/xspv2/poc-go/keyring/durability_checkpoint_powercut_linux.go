//go:build linux && xspv2_powercut_qualification && !xspv2_crash_test

package keyring

// Lab-only external power-cut arming hook.
//
// This file is never compiled into a normal Agent artifact. When the dedicated
// qualification build reaches the selected, already-existing durability
// checkpoint, it writes one bounded marker to an inherited file descriptor and
// then stops making progress. A physically independent lab controller must
// observe that marker and remove host/device power. This code cannot reboot,
// power off, invoke a command, open a network connection, or claim that a power
// loss was actually performed.

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	powercutPointEnv    = "XMESH_XSPV2_POWERCUT_POINT"
	powercutArmEnv      = "XMESH_XSPV2_POWERCUT_ARM"
	powercutRunIDEnv    = "XMESH_XSPV2_POWERCUT_RUN_ID"
	powercutSignalFDEnv = "XMESH_XSPV2_POWERCUT_SIGNAL_FD"
	powercutArmValue    = "EXTERNAL_POWER_CUT_LAB_ONLY"
)

var powercutPoints = map[string]struct{}{
	"after-previous":       {},
	"after-floor":          {},
	"after-active":         {},
	"after-recovery-abort": {},
	"after-recovery-active": {},
}

type powercutConfig struct {
	point string
	runID string
	fd    int
}

func validPowercutToken(value string) bool {
	if len(value) < 8 || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

func parsePowercutConfig(point, arm, runID, fdRaw string) (powercutConfig, error) {
	var empty powercutConfig
	if point == "" {
		return empty, nil
	}
	if _, ok := powercutPoints[point]; !ok {
		return empty, errors.New("unrecognized power-cut durability checkpoint")
	}
	if arm != powercutArmValue {
		return empty, errors.New("physical power-cut lab build is not explicitly armed")
	}
	if !validPowercutToken(runID) {
		return empty, errors.New("invalid physical power-cut qualification run ID")
	}
	fd, err := strconv.Atoi(fdRaw)
	if err != nil || fd < 3 || fd > 1024 {
		return empty, errors.New("invalid external power-cut signal file descriptor")
	}
	return powercutConfig{point: point, runID: runID, fd: fd}, nil
}

func powercutFatal(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "XSP2-POWERCUT-ARM-ERROR: %v\n", err)
	os.Exit(89)
}

func rotationDurabilityCheckpoint(point string) {
	cfg, err := parsePowercutConfig(
		strings.TrimSpace(os.Getenv(powercutPointEnv)),
		os.Getenv(powercutArmEnv),
		strings.TrimSpace(os.Getenv(powercutRunIDEnv)),
		strings.TrimSpace(os.Getenv(powercutSignalFDEnv)),
	)
	if err != nil {
		powercutFatal(err)
	}
	if cfg.point == "" || cfg.point != point {
		return
	}

	signal := os.NewFile(uintptr(cfg.fd), "xspv2-powercut-controller")
	if signal == nil {
		powercutFatal(errors.New("external power-cut signal descriptor unavailable"))
	}
	marker := fmt.Sprintf("XSP2-POWERCUT-ARMED-V1 run=%s point=%s\n", cfg.runID, point)
	if _, err = signal.WriteString(marker); err != nil {
		powercutFatal(fmt.Errorf("external power-cut marker write failed: %w", err))
	}

	// Do not continue the security transition after the selected boundary.
	// The controller must remove power externally. Sleeping instead of using a
	// deadlocking select prevents the Go runtime from terminating the process as
	// a local deadlock, which would be process-crash evidence rather than a real
	// external power-loss experiment.
	for {
		time.Sleep(24 * time.Hour)
	}
}
