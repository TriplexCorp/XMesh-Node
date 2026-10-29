//go:build xspv2_crash_test

package keyring

import "os"

const crashPointEnv = "XMESH_XSPV2_CRASH_POINT"

// rotationDurabilityCheckpoint is compiled only for the dedicated P0-E crash
// test build. Normal Agent artifacts compile durability_checkpoint.go instead
// and therefore have no environment-controlled crash path.
func rotationDurabilityCheckpoint(point string) {
	if os.Getenv(crashPointEnv) == point {
		os.Exit(86)
	}
}
