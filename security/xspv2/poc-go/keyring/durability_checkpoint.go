//go:build !xspv2_crash_test

package keyring

// rotationDurabilityCheckpoint is compiled as a no-op in normal builds.
// The xspv2_crash_test build tag replaces it with a subprocess hard-exit
// injector used only by the P0-E crash-consistency proof.
func rotationDurabilityCheckpoint(string) {}
