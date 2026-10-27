// Package envelope contains laboratory-only protocol primitives.
//
// This verifier authenticates a staged Nexus desired-config response against
// an independently provisioned, pinned panel_response public keyset. It does
// not persist anti-replay state, authorize policy application, or change the
// production Go 1.23 XMesh Node. Callers must implement durable monotonic
// revision/nonce checks and atomic application acknowledgements separately.
package envelope

import (
    "crypto/ed25519"
    "crypto/mldsa"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
)

// PanelResponsePin must originate from a trusted owner/bootstrap channel,
// NEVER from the response being verified.
type PanelResponsePin struct {
    IssuerID string
    NodeID int64
    Purpose string
    KeyEpoch int64
    Ed25519KeyID string
    MLDSA65KeyID string
    Ed25519Public []byte
    MLDSA65Public []byte
}

// VerifiedStagingReply means BOTH signatures and request binding verified.
// It does NOT mean that the message is fresh against durable replay state,
// authorized to change Xray, or successfully applied by a production agent.
type VerifiedStagingReply struct {
    Payload []byte
    Revision string
    RequestID string
    NonceHex string
    KeyEpoch int64
}

func publicKeyID(prefix string, pub []byte) string {
    digest := sha256.Sum256(pub)
    return prefix + hex.EncodeToString(digest[:12])
}

// VerifyStagingPanelDesiredConfigResponse verifies both signatures on the exact
// canonical bytes of a response, with a trusted panel keyset and outstanding
// request ID. No key is learned from unverified network data. Anti-replay and
// apply/ACK state transitions remain explicitly OUT OF SCOPE for this PoC.
func VerifyStagingPanelDesiredConfigResponse(
    raw []byte,
    pin PanelResponsePin,
    expectedRequestID string,
    nowMS int64,
) (VerifiedStagingReply, error) {
    var zero VerifiedStagingReply
    if expectedRequestID == "" || nowMS <= 0 {
        return zero, errors.New("missing pending request or time")
    }
    parsed, err := DecodeUntrustedEnvelope(raw)
    if err != nil {
        return zero, fmt.Errorf("invalid staged reply: %w", err)
    }
    metadata := parsed.Metadata
    if pin.Purpose != "panel_response" ||
        pin.NodeID <= 0 || pin.NodeID != metadata.NodeID ||
        pin.KeyEpoch <= 0 || pin.KeyEpoch != metadata.KeyEpoch ||
        pin.IssuerID == "" || pin.IssuerID != metadata.IssuerID ||
        metadata.Direction != 2 || metadata.MessageType != "node.desired-config.response" ||
        metadata.RequestID != expectedRequestID ||
        pin.Ed25519KeyID != metadata.Ed25519KeyID ||
        pin.MLDSA65KeyID != metadata.MLDSA65KeyID {
        return zero, errors.New("untrusted panel identity or response binding")
    }
    if len(pin.Ed25519Public) != ed25519.PublicKeySize ||
        len(pin.MLDSA65Public) != mldsa.MLDSA65PublicKeySize ||
        pin.Ed25519KeyID != publicKeyID("ed-", pin.Ed25519Public) ||
        pin.MLDSA65KeyID != publicKeyID("pq-", pin.MLDSA65Public) {
        return zero, errors.New("invalid pinned panel keyset")
    }
    if nowMS > metadata.ExpiresAtMS ||
        (metadata.IssuedAtMS > nowMS && metadata.IssuedAtMS-nowMS > 120000) ||
        (nowMS >= metadata.IssuedAtMS && nowMS-metadata.IssuedAtMS > 120000) {
        return zero, errors.New("stale or future panel response")
    }
    if !ed25519.Verify(pin.Ed25519Public, parsed.SigningInput, parsed.Ed25519Signature) {
        return zero, errors.New("invalid Ed25519 panel signature")
    }
    pqKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pin.MLDSA65Public)
    if err != nil {
        return zero, errors.New("invalid ML-DSA-65 panel public key")
    }
    if err := mldsa.Verify(pqKey, parsed.SigningInput, parsed.MLDSA65Signature, nil); err != nil {
        return zero, errors.New("invalid ML-DSA-65 panel signature")
    }
    return VerifiedStagingReply{
        Payload: append([]byte(nil), parsed.Payload...),
        Revision: metadata.Revision,
        RequestID: metadata.RequestID,
        NonceHex: metadata.NonceHex,
        KeyEpoch: metadata.KeyEpoch,
    }, nil
}
