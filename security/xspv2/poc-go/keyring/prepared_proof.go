package keyring

import (
 "encoding/base64"
 "encoding/hex"
 "errors"
)

// RotationProof is not a signed ACK or authorization to retire the prior key.
// It only proves control of both newly prepared private keys to a staging API.
type RotationProof struct {
 NodeID int64 `json:"nodeId"`
 Purpose string `json:"purpose"`
 FromEpoch uint64 `json:"fromEpoch"`
 KeyEpoch uint64 `json:"keyEpoch"`
 ChallengeHex string `json:"challengeHex"`
 Ed25519SignatureB64 string `json:"ed25519SignatureB64"`
 MLDSA65SignatureB64 string `json:"mldsa65SignatureB64"`
}

// ProvePreparedRotation signs the owner challenge in a rotation-specific
// domain without changing active keys or advancing the local epoch floor.
func ProvePreparedRotation(
    vault, master string, expectedOldEpoch uint64, challengeHex string,
) (RotationProof, error) {
    var zero RotationProof
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
    if len(challengeHex)!=64 {return zero,errors.New("invalid prepared challenge length")}
    challenge,err:=hex.DecodeString(challengeHex)
    if err!=nil||hex.EncodeToString(challenge)!=challengeHex {
      return zero,errors.New("noncanonical rotation challenge")
    }
    input,err:=RotationSigningInput(next,expectedOldEpoch,challenge)
    if err!=nil {return zero,err}
    ed,pq,err:=nextKeys.Sign(input)
    if err!=nil{return zero,err}
    return RotationProof{
       NodeID:next.NodeID,Purpose:next.Purpose,
       FromEpoch:expectedOldEpoch,KeyEpoch:next.KeyEpoch,
       ChallengeHex:challengeHex,
       Ed25519SignatureB64:base64.StdEncoding.EncodeToString(ed),
       MLDSA65SignatureB64:base64.StdEncoding.EncodeToString(pq),
    },nil
}
