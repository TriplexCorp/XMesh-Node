package keyring

import (
    "crypto/ed25519"
    "crypto/mldsa"
    "encoding/base64"
    "os"
    "strings"
    "testing"
)

func TestPreparedRotationProvesDualKeysWithoutChangingActive(t *testing.T) {
    vault, master, active := rotationFixture(t)
    next, err := PrepareRotation(vault, master, 1)
    if err != nil { t.Fatal(err) }

    challengeHex := strings.Repeat("09", 32)
    proof, err := ProvePreparedRotation(vault, master, 1, challengeHex)
    if err != nil { t.Fatal(err) }
    if proof.NodeID != next.NodeID || proof.FromEpoch != 1 || proof.KeyEpoch != 2 ||
        proof.Purpose != "node_request" || proof.ChallengeHex != challengeHex {
        t.Fatal("incorrect prepared key identity or challenge")
    }
    challenge := make([]byte, 32)
    for i := range challenge { challenge[i] = 9 }
    signed, err := RotationSigningInput(next, 1, challenge)
    if err != nil { t.Fatal(err) }
    edSig, err := base64.StdEncoding.DecodeString(proof.Ed25519SignatureB64)
    if err != nil { t.Fatal(err) }
    pqSig, err := base64.StdEncoding.DecodeString(proof.MLDSA65SignatureB64)
    if err != nil { t.Fatal(err) }
    pqKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), next.PQPublic)
    if err != nil { t.Fatal(err) }
    if !ed25519.Verify(next.EdPublic, signed, edSig) ||
        mldsa.Verify(pqKey, signed, pqSig, nil) != nil {
        t.Fatal("prepared private key proof did not verify with both next public keys")
    }
    enrollmentSigned, err := EnrollmentSigningInput(next, challenge)
    if err != nil { t.Fatal(err) }
    if ed25519.Verify(next.EdPublic, enrollmentSigned, edSig) ||
        mldsa.Verify(pqKey, enrollmentSigned, pqSig, nil) == nil {
        t.Fatal("rotation signatures were accepted for initial enrollment domain")
    }
    current, err := Description(vault, master)
    if err != nil || current.KeyEpoch != 1 || current.EdKeyID != active.EdKeyID {
        t.Fatal("preparing/proving changed live signing identity", err)
    }
    if _, err = ProvePreparedRotation(vault, master, 2, challengeHex); err == nil {
        t.Fatal("accepted proof with incorrect current epoch")
    }
    if _, err = ProvePreparedRotation(vault, master, 1, strings.Repeat("AA", 32)); err == nil {
        t.Fatal("accepted noncanonical proof challenge")
    }
    if _, err = ActivatePreparedRotation(vault, master, 1, next.EdKeyID, next.PQKeyID); err != nil {
        t.Fatal(err)
    }
    if _, err = ProvePreparedRotation(vault, master, 1, challengeHex); err == nil {
        t.Fatal("prepared-only proof accepted after activation")
    }
}

func TestPreparedRotationProofRejectsTamperingAndAbort(t *testing.T) {
    vault, master, _ := rotationFixture(t)
    if _, err := ProvePreparedRotation(vault, master, 1, strings.Repeat("09", 32)); err == nil {
        t.Fatal("signed unprepared key material")
    }
    if _, err := PrepareRotation(vault, master, 1); err != nil { t.Fatal(err) }
    if err := os.WriteFile(stagedPath(vault), []byte("corrupt ciphertext"), 0600); err != nil {
        t.Fatal(err)
    }
    if _, err := ProvePreparedRotation(vault, master, 1, strings.Repeat("09", 32)); err == nil {
        t.Fatal("signed tampered prepared keys")
    }
}
