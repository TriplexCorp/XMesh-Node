package envelope

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "strings"
    "testing"

    "github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

func TestStagingPanelReplyRequiresPinnedEd25519ANDMLDSA65(t *testing.T) {
    private, public, err := keyring.Generate(42, "panel_response", 1)
    if err != nil {
        t.Fatal(err)
    }
    pin := PanelResponsePin{
        IssuerID: "nexus-primary",
        NodeID: 42,
        Purpose: "panel_response",
        KeyEpoch: 1,
        Ed25519KeyID: public.EdKeyID,
        MLDSA65KeyID: public.PQKeyID,
        Ed25519Public: public.EdPublic,
        MLDSA65Public: public.PQPublic,
    }
    const issuedAt int64 = 1800000000000
    const pendingRequest = "req-node-0001"
    payload := []byte("{\"desired\":\"demo\"}")
    original := Envelope{
        Protocol: "XSP/2",
        Suite: "Ed25519+ML-DSA-65",
        Direction: 2,
        MessageType: "node.desired-config.response",
        IssuerID: pin.IssuerID,
        NodeID: pin.NodeID,
        Method: "POST",
        Path: "/api/v2/node/desired-config",
        Ed25519KeyID: pin.Ed25519KeyID,
        MLDSA65KeyID: pin.MLDSA65KeyID,
        KeyEpoch: pin.KeyEpoch,
        IssuedAtMS: issuedAt,
        ExpiresAtMS: issuedAt + 60000,
        NonceHex: strings.Repeat("a", 32),
        RequestID: pendingRequest,
        Revision: "rev-17",
        PayloadB64: base64.StdEncoding.EncodeToString(payload),
        Signatures: Signatures{
            Ed25519: base64.StdEncoding.EncodeToString(make([]byte, 64)),
            MLDSA65: base64.StdEncoding.EncodeToString(make([]byte, 3309)),
        },
    }
    encode := func(e Envelope) []byte {
        t.Helper()
        encoded, err := json.Marshal(e)
        if err != nil {
            t.Fatal(err)
        }
        return encoded
    }
    base := encode(original)
    untrusted, err := DecodeUntrustedEnvelope(base)
    if err != nil {
        t.Fatal(err)
    }
    edSig, pqSig, err := private.Sign(untrusted.SigningInput)
    if err != nil {
        t.Fatal(err)
    }
    original.Signatures = Signatures{
        Ed25519: base64.StdEncoding.EncodeToString(edSig),
        MLDSA65: base64.StdEncoding.EncodeToString(pqSig),
    }
    signed := encode(original)
    verified, err := VerifyStagingPanelDesiredConfigResponse(signed, pin, pendingRequest, issuedAt)
    if err != nil {
        t.Fatalf("both signatures were valid: %v", err)
    }
    if !bytes.Equal(verified.Payload, payload) || verified.Revision != "rev-17" ||
        verified.RequestID != pendingRequest || verified.KeyEpoch != 1 {
        t.Fatal("verified payload or response correlation changed")
    }

    tampered := original
    tampered.PayloadB64 = base64.StdEncoding.EncodeToString([]byte("{\"desired\":\"forged\"}"))
    wrongEd := original
    wrongEd.Signatures.Ed25519 = base64.StdEncoding.EncodeToString(make([]byte, 64))
    wrongPQ := original
    wrongPQ.Signatures.MLDSA65 = base64.StdEncoding.EncodeToString(make([]byte, 3309))
    wrongRequest := original
    wrongRequest.RequestID = "request-substitution"
    missingPQ := original
    missingPQ.Signatures.MLDSA65 = ""
    differentPin := pin
    differentPin.IssuerID = "untrusted-panel"
    wrongPurpose := pin
    wrongPurpose.Purpose = "node_request"
    wrongEpoch := pin
    wrongEpoch.KeyEpoch = 2
    wrongPublic := pin
    wrongPublic.Ed25519Public = bytes.Repeat([]byte{7}, 32)

    cases := []struct {
        name string
        raw []byte
        pinned PanelResponsePin
        requestID string
        now int64
    }{
        {"forged payload", encode(tampered), pin, pendingRequest, issuedAt},
        {"missing Ed25519 proof", encode(wrongEd), pin, pendingRequest, issuedAt},
        {"missing ML-DSA-65 proof", encode(missingPQ), pin, pendingRequest, issuedAt},
        {"bad ML-DSA-65 proof", encode(wrongPQ), pin, pendingRequest, issuedAt},
        {"wrong request ID in metadata", encode(wrongRequest), pin, pendingRequest, issuedAt},
        {"wrong pending request", signed, pin, "another-request", issuedAt},
        {"untrusted issuer", signed, differentPin, pendingRequest, issuedAt},
        {"wrong key purpose", signed, wrongPurpose, pendingRequest, issuedAt},
        {"stale key epoch", signed, wrongEpoch, pendingRequest, issuedAt},
        {"changed pinned public key", signed, wrongPublic, pendingRequest, issuedAt},
        {"expired response", signed, pin, pendingRequest, issuedAt + 60001},
        {"future-issued response", signed, pin, pendingRequest, issuedAt - 120001},
        {"missing pending request", signed, pin, "", issuedAt},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            if _, err := VerifyStagingPanelDesiredConfigResponse(tc.raw, tc.pinned, tc.requestID, tc.now); err == nil {
                t.Fatal("accepted untrusted staged Nexus response")
            }
        })
    }
}
