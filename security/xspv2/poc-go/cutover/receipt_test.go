package cutover

import (
    "bytes"
    "crypto/ed25519"
    "crypto/mldsa"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "os"
    "path/filepath"
    "strings"
    "testing"
)
type receiptGolden struct {
    Schema string `json:"schema"`
    Message CommitReceipt `json:"message"`
    SigningInputHex string `json:"signing_input_hex"`
    SigningInputSHA256Hex string `json:"signing_input_sha256_hex"`
}
func TestCommitReceiptSharedCanonicalGolden(t *testing.T) {
    raw,err:=os.ReadFile(filepath.Join("..","..","..","..","docs","XSP_V2_COMMIT_RECEIPT_VECTORS.json"))
    if err!=nil{t.Fatal(err)}
    var f receiptGolden
    if err=json.Unmarshal(raw,&f);err!=nil{t.Fatal(err)}
    if f.Schema!="xsp2-commit-receipt-1"{t.Fatal("wrong shared fixture")}
    input,err:=CommitReceiptCanonical(f.Message)
    if err!=nil{t.Fatal(err)}
    if hex.EncodeToString(input)!=f.SigningInputHex||sha(input)!=f.SigningInputSHA256Hex{
        t.Fatal("Go and Rust canonical committed ACK receipt divergence")
    }
    for _,mutate:=range []func(*CommitReceipt){
        func(m *CommitReceipt){m.Protocol="XMESH1"},
        func(m *CommitReceipt){m.Kind="ack"},
        func(m *CommitReceipt){m.ToEpoch=m.FromEpoch},
        func(m *CommitReceipt){m.AckNonceHex=strings.Repeat("00",16)},
        func(m *CommitReceipt){m.CommittedAtMS=0},
    }{
        m:=f.Message
        mutate(&m)
        if _,err=CommitReceiptCanonical(m);err==nil{t.Fatal("invalid receipt accepted")}
    }
    changed:=f.Message
    changed.RequestID="different"
    other,err:=CommitReceiptCanonical(changed)
    if err!=nil||bytes.Equal(input,other){t.Fatal("request ID not bound to receipt")}
}

func signReceiptForTest(t *testing.T,m CommitReceipt,ed ed25519.PrivateKey,pq *mldsa.PrivateKey)[]byte{
    t.Helper()
    input,err:=CommitReceiptCanonical(m)
    if err!=nil{t.Fatal(err)}
    pqSig,err:=pq.Sign(nil,input,nil)
    if err!=nil{t.Fatal(err)}
    signed:=SignedCommitReceipt{Message:m,Signatures:Signatures{
        Ed25519:base64.StdEncoding.EncodeToString(ed25519.Sign(ed,input)),
        MLDSA65:base64.StdEncoding.EncodeToString(pqSig),
    }}
    raw,err:=json.Marshal(signed)
    if err!=nil{t.Fatal(err)}
    return raw
}

// Exercises REAL Go ML-DSA-65 and Ed25519 signatures plus the saved signed
// permit->ACK->receipt binding, tampering and long-delayed retry.
func TestSignedCommitReceiptVerifiesAgainstExactPersistedACK(t *testing.T) {
    f:=load(t)
    panelEd,panelPQ,panelPin:=pair(t)
    nodeEd,nodePQ,nodePin:=pair(t)
    panelPin.Purpose="panel_response"
    panelPin.IssuerID=f.Permit.IssuerID
    panelPin.NodeID=f.Permit.NodeID
    nodePin.Purpose="node_request"
    nodePin.IssuerID=f.Ack.IssuerID
    nodePin.NodeID=f.Ack.NodeID
    f.Permit.SignerEdKeyID=panelPin.EdKeyID
    f.Permit.SignerPQKeyID=panelPin.PQKeyID
    f.Permit.ToEdKeyID=nodePin.EdKeyID
    f.Permit.ToPQKeyID=nodePin.PQKeyID
    f.Ack.SignerEdKeyID=nodePin.EdKeyID
    f.Ack.SignerPQKeyID=nodePin.PQKeyID
    f.Ack.ToEdKeyID=nodePin.EdKeyID
    f.Ack.ToPQKeyID=nodePin.PQKeyID
    originalPermit:=mustSign(t,f.Permit,panelEd,panelPQ)
    want:=ExpectedPermit{
        NodeID:f.Permit.NodeID,
        FromEpoch:f.Permit.FromEpoch,
        ToEpoch:f.Permit.ToEpoch,
        RequestID:f.Permit.RequestID,
        FromEdKeyID:f.Permit.FromEdKeyID,
        FromPQKeyID:f.Permit.FromPQKeyID,
        ToEdKeyID:f.Permit.ToEdKeyID,
        ToPQKeyID:f.Permit.ToPQKeyID,
        CandidateSHA256Hex:f.Permit.CandidateSHA256Hex,
    }
    permit,err:=VerifyPermit(originalPermit,panelPin,want,f.Permit.IssuedAtMS+1)
    if err!=nil{t.Fatal(err)}
    f.Ack.PermitSHA256Hex=permit.PermitDigest()
    originalACK:=mustSign(t,f.Ack,nodeEd,nodePQ)
    if _,err=VerifyAppliedACK(originalACK,permit,nodePin,f.Ack.IssuedAtMS+1);err!=nil{t.Fatal(err)}
    committed:=f.Ack.IssuedAtMS+1000
    msg:=CommitReceipt{
        Protocol:"XSP/2", Kind:"commit_receipt",
        IssuerID:panelPin.IssuerID,
        SignerEdKeyID:panelPin.EdKeyID,SignerPQKeyID:panelPin.PQKeyID,
        NodeID:f.Ack.NodeID,FromEpoch:f.Ack.FromEpoch,ToEpoch:f.Ack.ToEpoch,
        RequestID:f.Ack.RequestID,CommittedAtMS:committed,
        AckNonceHex:f.Ack.NonceHex,
        CandidateSHA256Hex:f.Ack.CandidateSHA256Hex,
        PermitSHA256Hex:permit.PermitDigest(),
        SignedACKSHA256Hex:sha(originalACK),
    }
    signedReceipt:=signReceiptForTest(t,msg,panelEd,panelPQ)
    // A delayed identical signed receipt remains valid after the original ACK
    // expiry, but *only* for the exact locally saved signed ACK.
    retryTime:=f.Ack.ExpiresAtMS+86400000
    verified,err:=VerifyCommitReceipt(signedReceipt,panelPin,permit,originalACK,nodePin,f.Ack.ToEpoch,retryTime)
    if err!=nil{t.Fatalf("legitimate delayed receipt failed closed: %v",err)}
    if verified.NodeID!=f.Ack.NodeID||verified.ToEpoch!=f.Ack.ToEpoch||
        verified.RequestID!=f.Ack.RequestID||verified.SignedACKSHA256Hex!=sha(originalACK){
        t.Fatal("verified historical receipt binding mismatch")
    }
    cases:=[]struct{
        name string
        raw []byte
        pin PinnedPublic
        ack []byte
        floor uint64
    }{}
    corrupt:=func(change func(*SignedCommitReceipt))[]byte{
        t.Helper()
        var s SignedCommitReceipt
        if err:=json.Unmarshal(signedReceipt,&s);err!=nil{t.Fatal(err)}
        change(&s)
        raw,err:=json.Marshal(s);if err!=nil{t.Fatal(err)}
        return raw
    }
    cases=append(cases,
        struct{name string;raw []byte;pin PinnedPublic;ack []byte;floor uint64}{"wrong-request",corrupt(func(s *SignedCommitReceipt){s.Message.RequestID="other"}),panelPin,originalACK,f.Ack.ToEpoch},
        struct{name string;raw []byte;pin PinnedPublic;ack []byte;floor uint64}{"altered-ack-digest",corrupt(func(s *SignedCommitReceipt){s.Message.SignedACKSHA256Hex=strings.Repeat("aa",32)}),panelPin,originalACK,f.Ack.ToEpoch},
        struct{name string;raw []byte;pin PinnedPublic;ack []byte;floor uint64}{"wrong-pq-signature",corrupt(func(s *SignedCommitReceipt){s.Signatures.MLDSA65=base64.StdEncoding.EncodeToString(make([]byte,mldsa.MLDSA65SignatureSize))}),panelPin,originalACK,f.Ack.ToEpoch},
        struct{name string;raw []byte;pin PinnedPublic;ack []byte;floor uint64}{"missing-ed-signature",corrupt(func(s *SignedCommitReceipt){s.Signatures.Ed25519=""}),panelPin,originalACK,f.Ack.ToEpoch},
        struct{name string;raw []byte;pin PinnedPublic;ack []byte;floor uint64}{"wrong-epoch",corrupt(func(s *SignedCommitReceipt){s.Message.ToEpoch++}),panelPin,originalACK,f.Ack.ToEpoch},
        struct{name string;raw []byte;pin PinnedPublic;ack []byte;floor uint64}{"wrong-ack-nonce",corrupt(func(s *SignedCommitReceipt){s.Message.AckNonceHex=strings.Repeat("bb",16)}),panelPin,originalACK,f.Ack.ToEpoch},
        struct{name string;raw []byte;pin PinnedPublic;ack []byte;floor uint64}{"future-floor",signedReceipt,panelPin,originalACK,f.Ack.ToEpoch+1},
        struct{name string;raw []byte;pin PinnedPublic;ack []byte;floor uint64}{"raw-ack-byte-change",signedReceipt,panelPin,append(append([]byte{},originalACK...),byte(' ')),f.Ack.ToEpoch},
    )
    wrongPin:=panelPin;wrongPin.Purpose="node_request"
    cases=append(cases,struct{name string;raw []byte;pin PinnedPublic;ack []byte;floor uint64}{"wrong-pin-purpose",signedReceipt,wrongPin,originalACK,f.Ack.ToEpoch})
    wrongPin=panelPin;wrongPin.PQPublic=bytes.Repeat([]byte{9},mldsa.MLDSA65PublicKeySize)
    cases=append(cases,struct{name string;raw []byte;pin PinnedPublic;ack []byte;floor uint64}{"wrong-pq-public-key",signedReceipt,wrongPin,originalACK,f.Ack.ToEpoch})
    for _,tc:=range cases {
        t.Run(tc.name,func(t *testing.T){
            if _,err:=VerifyCommitReceipt(tc.raw,tc.pin,permit,tc.ack,nodePin,tc.floor,retryTime);err==nil {
                t.Fatal("tampered or downgraded commit receipt accepted")
            }
        })
    }
    // A signed but fabricated receipt outside ACK TTL must fail.
    impossible:=msg;impossible.CommittedAtMS=f.Ack.ExpiresAtMS+1
    if _,err=VerifyCommitReceipt(signReceiptForTest(t,impossible,panelEd,panelPQ),panelPin,permit,originalACK,nodePin,f.Ack.ToEpoch,retryTime);err==nil{
        t.Fatal("commit receipt claimed DB commit after ACK expiry")
    }
    // Duplicate JSON fields, unsupported modes and unsigned 204-style
    // acknowledgments may NEVER count as a trusted receipt.
    duplicate:=strings.Replace(string(signedReceipt),`"protocol":"XSP/2"`,`"protocol":"XSP/2","protocol":"XSP/2"`,1)
    if _,err=DecodeSignedCommitReceipt([]byte(duplicate));err==nil{t.Fatal("duplicate JSON accepted")}
    if _,err=VerifyCommitReceipt([]byte("{}"),panelPin,permit,originalACK,nodePin,f.Ack.ToEpoch,retryTime);err==nil{
        t.Fatal("unsigned response accepted")
    }
    _=sha256.Sum256 // avoid fixture-only crypto import misread
}
