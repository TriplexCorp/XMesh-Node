package cutover

// Offline Go 1.27 verification. Not linked into the current Go 1.23 Agent.
import (
    "bytes"
    "crypto/ed25519"
    "crypto/mldsa"
    "encoding/binary"
    "encoding/json"
    "errors"
    "fmt"
    "io"
)
const receiptDomain = "XSP2-CUTOVER-COMMIT-RECEIPT-V1\x00"

type CommitReceipt struct {
    Protocol string `json:"protocol"`
    Kind string `json:"kind"`
    IssuerID string `json:"issuerId"`
    SignerEdKeyID string `json:"signerEdKeyId"`
    SignerPQKeyID string `json:"signerPQKeyId"`
    NodeID uint64 `json:"nodeId"`
    FromEpoch uint64 `json:"fromEpoch"`
    ToEpoch uint64 `json:"toEpoch"`
    RequestID string `json:"requestId"`
    CommittedAtMS int64 `json:"committedAtMs"`
    AckNonceHex string `json:"ackNonceHex"`
    CandidateSHA256Hex string `json:"candidateSHA256Hex"`
    PermitSHA256Hex string `json:"permitSHA256Hex"`
    SignedACKSHA256Hex string `json:"signedACKSHA256Hex"`
}
type SignedCommitReceipt struct {
    Message CommitReceipt `json:"message"`
    Signatures Signatures `json:"signatures"`
}
// A verified historical witness, not a new command or key-retirement permit.
type VerifiedCommitReceipt struct {
    NodeID uint64
    FromEpoch uint64
    ToEpoch uint64
    RequestID string
    ToEdKeyID string
    ToPQKeyID string
    CommittedAtMS int64
    SignedACKSHA256Hex string
}
func CommitReceiptCanonical(m CommitReceipt)([]byte,error){
    if m.Protocol!="XSP/2"||m.Kind!="commit_receipt"||
        m.IssuerID=="node-"+fmt.Sprint(m.NodeID)||
        m.NodeID==0||m.NodeID>uint64(^uint64(0)>>1)||
        m.FromEpoch==0||m.FromEpoch==^uint64(0)||
        m.ToEpoch!=m.FromEpoch+1||m.CommittedAtMS<=0 {
        return nil,errors.New("invalid receipt role, protocol, epoch or committed time")
    }
    nonce,e1:=hexField(m.AckNonceHex,16)
    candidate,e2:=hexField(m.CandidateSHA256Hex,32)
    permit,e3:=hexField(m.PermitSHA256Hex,32)
    ack,e4:=hexField(m.SignedACKSHA256Hex,32)
    if e1!=nil||e2!=nil||e3!=nil||e4!=nil||
        zero(nonce)||zero(candidate)||zero(permit)||zero(ack) {
        return nil,errors.New("missing or noncanonical receipt bindings")
    }
    var out bytes.Buffer
    out.WriteString(receiptDomain);out.Write([]byte{1,2})
    for _,n:=range []uint64{m.NodeID,m.FromEpoch,m.ToEpoch} {u64(&out,n)}
    for _,f:=range []struct{s string;max int}{
        {m.RequestID,64},{m.IssuerID,64},{m.SignerEdKeyID,64},{m.SignerPQKeyID,64},
    }{if err:=text(&out,f.s,f.max);err!=nil{return nil,err}}
    var raw [8]byte
    binary.BigEndian.PutUint64(raw[:],uint64(m.CommittedAtMS))
    out.Write(raw[:])
    out.Write(nonce);out.Write(candidate);out.Write(permit);out.Write(ack)
    return out.Bytes(),nil
}
func DecodeSignedCommitReceipt(raw []byte)(SignedCommitReceipt,error){
    var empty SignedCommitReceipt
    if len(raw)==0||len(raw)>16*1024{return empty,errors.New("signed receipt envelope size")}
    if err:=uniqueFields(raw);err!=nil{return empty,err}
    dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
    var s SignedCommitReceipt
    if err:=dec.Decode(&s);err!=nil{return empty,err}
    if err:=dec.Decode(new(any));err!=io.EOF{return empty,errors.New("trailing receipt JSON")}
    if _,err:=CommitReceiptCanonical(s.Message);err!=nil{return empty,err}
    return s,nil
}

// VerifyCommitReceipt binds both panel signatures to the original locally
// verified permit AND a separately verified exact-byte signed Node ACK.
// It has NO fallback to unsigned, Ed-only, classical or expired new commands.
// A historical receipt has no TTL; it is matched to the Node's durable pending
// request, ACK and independent monotonic epoch floor. This method alone does
// not persist the receipt or authorize old-key retirement.
func VerifyCommitReceipt(
    raw []byte,
    panelPin PinnedPublic,
    permit VerifiedPermit,
    exactSignedACK []byte,
    nextNodeKeys PinnedPublic,
    minEpoch uint64,
    nowMS int64,
)(VerifiedCommitReceipt,error){
    var empty VerifiedCommitReceipt
    if nowMS<=0||minEpoch==0||permit.inputHash==""||permit.message.Kind!="permit" {
        return empty,errors.New("no independently trusted permit, time or epoch")
    }
    signed,err:=DecodeSignedCommitReceipt(raw)
    if err!=nil{return empty,err}
    m,p:=signed.Message,permit.message
    if err:=checkPublic(panelPin,Message{
        NodeID:m.NodeID,IssuerID:m.IssuerID,
        SignerEdKeyID:m.SignerEdKeyID,SignerPQKeyID:m.SignerPQKeyID,
    },"panel_response");err!=nil {
        return empty,fmt.Errorf("untrusted panel receipt signer: %w",err)
    }
    if m.IssuerID!=p.IssuerID||
        m.SignerEdKeyID!=p.SignerEdKeyID||m.SignerPQKeyID!=p.SignerPQKeyID||
        m.NodeID!=p.NodeID||m.FromEpoch!=p.FromEpoch||m.ToEpoch!=p.ToEpoch||
        m.RequestID!=p.RequestID||m.ToEpoch<minEpoch||
        m.CandidateSHA256Hex!=p.CandidateSHA256Hex||
        m.PermitSHA256Hex!=permit.inputHash||
        (m.CommittedAtMS>nowMS && m.CommittedAtMS-nowMS>120000) {
        return empty,errors.New("receipt not bound to independently trusted permit/state")
    }
    // Historical ACK signature validation is allowed after its original TTL
    // only for comparing the EXACT locally saved ACK bytes. It never accepts a
    // new request or changes the server's epoch/nonce.
    parsedACK,err:=Decode(exactSignedACK)
    if err!=nil{return empty,fmt.Errorf("invalid saved ACK: %w",err)}
    a:=parsedACK.Message
    if a.Kind!="ack"||a.PermitNonceHex!=p.PermitNonceHex||
        a.PermitSHA256Hex!=permit.inputHash||
        a.CandidateSHA256Hex!=p.CandidateSHA256Hex {
        return empty,errors.New("saved ACK not linked to trusted permit")
    }
    if _,err=VerifyAppliedACK(exactSignedACK,permit,nextNodeKeys,a.IssuedAtMS);err!=nil {
        return empty,fmt.Errorf("saved ACK signatures invalid: %w",err)
    }
    if m.AckNonceHex!=a.NonceHex||
        m.SignedACKSHA256Hex!=sha(exactSignedACK)||
        m.CommittedAtMS<a.IssuedAtMS||m.CommittedAtMS>a.ExpiresAtMS {
        return empty,errors.New("receipt differs from exact signed ACK or commit TTL")
    }
    canonical,err:=CommitReceiptCanonical(m)
    if err!=nil{return empty,err}
    edSig,err:=b64(signed.Signatures.Ed25519,ed25519.SignatureSize)
    if err!=nil{return empty,err}
    pqSig,err:=b64(signed.Signatures.MLDSA65,mldsa.MLDSA65SignatureSize)
    if err!=nil{return empty,err}
    if !ed25519.Verify(panelPin.EdPublic,canonical,edSig) {
        return empty,errors.New("invalid Ed25519 receipt signature")
    }
    pub,err:=mldsa.NewPublicKey(mldsa.MLDSA65(),panelPin.PQPublic)
    if err!=nil{return empty,errors.New("invalid panel PQ verifier")}
    if err=mldsa.Verify(pub,canonical,pqSig,nil);err!=nil {
        return empty,errors.New("invalid ML-DSA-65 receipt signature")
    }
    return VerifiedCommitReceipt{
        NodeID:m.NodeID,FromEpoch:m.FromEpoch,ToEpoch:m.ToEpoch,
        RequestID:m.RequestID,ToEdKeyID:a.ToEdKeyID,ToPQKeyID:a.ToPQKeyID,
        CommittedAtMS:m.CommittedAtMS,SignedACKSHA256Hex:m.SignedACKSHA256Hex,
    },nil
}
