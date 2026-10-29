//go:build !xspv2_crash_test && !xspv2_powercut_qualification

package keyring

// rotationDurabilityCheckpoint is compiled as a no-op in normal builds.
// Dedicated test/lab build tags replace it with bounded crash or external
// power-cut qualification hooks. Production Agent artifacts contain neither.
func rotationDurabilityCheckpoint(string) {}
