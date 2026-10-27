package keyring

import "errors"

// ProvePreparedRotation proves control of BOTH private keys in a locally
// prepared next keyset WITHOUT activating it or advancing the epoch floor.
//
// This is a research-only proof for a future owner-approved two-phase Nexus
// rotation protocol. Do not send it to the old initial-enrollment claim route:
// that route is not a signed or crash-safe rotation acknowledgement.
func ProvePreparedRotation(
    vault, master string,
    expectedOldEpoch uint64,
    challengeHex string,
) (EnrollmentProof, error) {
    var zero EnrollmentProof
    lock, key, err := masterLocked(master, false)
    if err != nil { return zero, err }
    defer lock.Close()
    defer clear(key)
    if err = mustBeAbsent(previousPath(vault)); err != nil { return zero, err }
    _, active, err := openWithMaster(vault, key)
    if err != nil { return zero, err }
    nextKeys, next, err := openWithMaster(stagedPath(vault), key)
    if err != nil { return zero, err }
    floor, err := readFloor(vault)
    if err != nil { return zero, err }
    if expectedOldEpoch == 0 || expectedOldEpoch == ^uint64(0) ||
        floor != expectedOldEpoch || active.KeyEpoch != expectedOldEpoch ||
        next.KeyEpoch != expectedOldEpoch+1 ||
        next.NodeID != active.NodeID || next.Purpose != "node_request" ||
        active.Purpose != "node_request" {
        return zero, errors.New("prepared keyset is not the approved next Node identity")
    }
    return BuildEnrollmentProof(nextKeys, next, challengeHex)
}
