//go:build linux

package cutover

// ReloadVerifiedPermitForReceiptRecovery re-verifies an expired, already
// journaled permit only for immutable receipt recovery after the exact applied
// ACK is already durably present. It does not create an ACK, advance an epoch,
// accept a new command, retire keys, or relax any signature/key binding.
//
// This is the production-facing name for the previously package-private
// recovery verifier used by the proven lost-response/restart path.
func ReloadVerifiedPermitForReceiptRecovery(
	dir string,
	pin PinnedPublic,
	want ExpectedPermit,
	next PinnedPublic,
) (VerifiedPermit, error) {
	return reloadVerifiedPermitForReceiptRetry(dir, pin, want, next)
}
