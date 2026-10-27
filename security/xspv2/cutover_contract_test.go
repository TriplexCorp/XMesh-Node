package xspv2

// Contract-only canonical byte checks; no signer, verifier, endpoint, or activation.
import (
    "bytes"
    "crypto/sha256"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "errors"
    "os"
    "path/filepath"
    "strconv"
    "testing"
)

type cutoverCandidate struct {
    Kind string `json:"kind"`
    IssuerID string `json:"issuerId"`
    SignerEdKeyID string `json:"signerEdKeyId"`
    SignerPQKeyID string `json:"signerPQKeyId"`
    NodeID uint64 `json:"nodeId"`
    FromEpoch uint64 `json:"fromEpoch"`
    ToEpoch uint64 `json:"toEpoch"`
    RequestID string `json:"requestId"`
    FromEdKeyID string `json:"fromEdKeyId"`
    FromPQKeyID string `json:"fromPQKeyId"`
    ToEdKeyID string `json:"toEdKeyId"`
    ToPQKeyID string `json:"toPQKeyId"`
    Method string `json:"method"`
    Path string `json:"path"`
    IssuedAtMS int64 `json:"issuedAtMs"`
    ExpiresAtMS int64 `json:"expiresAtMs"`
    PermitNonceHex string `json:"permitNonceHex"`
    NonceHex string `json:"nonceHex"`
    CandidateSHA256Hex string `json:"candidateSha256Hex"`
    PermitSHA256Hex string `json:"permitSha256Hex"`
    AppliedStateSHA256Hex string `json:"appliedStateSha256Hex"`
}
type cutoverFixtures struct {
    Schema string `json:"schema"`
    Permit cutoverCandidate `json:"permit"`
    Ack cutoverCandidate `json:"ack"`
    PermitInputSHA256Hex string `json:"permitInputSha256Hex"`
    AckInputSHA256Hex string `json:"ackInputSha256Hex"`
    StateDigestSHA256Hex string `json:"stateDigestSha256Hex"`
}
func cutoverHex(src string, size int) ([]byte, error) {
    if len(src) != size*2 { return nil, errors.New("invalid hex length") }
    raw, err := hex.DecodeString(src)
    if err != nil || hex.EncodeToString(raw) != src { return nil, errors.New("noncanonical hex") }
    return raw, nil
}
func cutoverAllZero(p []byte) bool {
    for _, v := range p { if v != 0 { return false } }
    return true
}
func cutoverText(b *bytes.Buffer, s string, max int) error {
    if len(s) == 0 || len(s) > max { return errors.New("invalid ASCII length") }
    for i:=0; i<len(s); i++ { if s[i] < 0x21 || s[i] > 0x7e { return errors.New("non-printable metadata") } }
    if err := binary.Write(b, binary.BigEndian, uint32(len(s))); err != nil { return err }
    _, err := b.WriteString(s)
    return err
}
func cutoverBytes(v cutoverCandidate) ([]byte,error) {
    var domain string
    var direction byte
    switch v.Kind {
    case "permit":
        domain, direction = "XSP2-CUTOVER-PERMIT-V1", 2
        if v.Path != "/api/v2/node/keys/rotation/permit" || v.IssuerID == "node-"+strconv.FormatUint(v.NodeID,10) ||
            v.SignerEdKeyID == v.ToEdKeyID || v.SignerPQKeyID == v.ToPQKeyID { return nil, errors.New("invalid permit role") }
    case "ack":
        domain, direction = "XSP2-CUTOVER-APPLIED-ACK-V1", 1
        if v.Path != "/api/v2/node/keys/rotation/ack" || v.IssuerID != "node-"+strconv.FormatUint(v.NodeID,10) ||
            v.SignerEdKeyID != v.ToEdKeyID || v.SignerPQKeyID != v.ToPQKeyID { return nil, errors.New("invalid ACK signer") }
    default:
        return nil, errors.New("invalid message type")
    }
    if v.NodeID == 0 || v.FromEpoch == 0 || v.ToEpoch != v.FromEpoch+1 || v.ToEpoch == 0 ||
        v.IssuedAtMS <= 0 || v.ExpiresAtMS <= v.IssuedAtMS ||
        v.ExpiresAtMS-v.IssuedAtMS > 60000 || v.Method != "POST" {
        return nil, errors.New("invalid epoch or expiry or method")
    }
    pn,e1:=cutoverHex(v.PermitNonceHex,16)
    nonce,e2:=cutoverHex(v.NonceHex,16)
    candidate,e3:=cutoverHex(v.CandidateSHA256Hex,32)
    permitHash,e4:=cutoverHex(v.PermitSHA256Hex,32)
    stateHash,e5:=cutoverHex(v.AppliedStateSHA256Hex,32)
    if e1!=nil||e2!=nil||e3!=nil||e4!=nil||e5!=nil ||
        cutoverAllZero(pn)||cutoverAllZero(nonce)||cutoverAllZero(candidate) {
        return nil, errors.New("invalid binary metadata")
    }
    if v.Kind == "permit" && (!bytes.Equal(pn,nonce) || !cutoverAllZero(permitHash) || !cutoverAllZero(stateHash)) {
        return nil, errors.New("permit must not assert applied state")
    }
    if v.Kind == "ack" && (bytes.Equal(pn,nonce) || cutoverAllZero(permitHash) || cutoverAllZero(stateHash)) {
        return nil, errors.New("ACK must bind permit and applied state")
    }
    var b bytes.Buffer
    b.WriteString(domain)
    b.WriteByte(0)
    b.Write([]byte{1,direction})
    for _, n := range []uint64{v.NodeID,v.FromEpoch,v.ToEpoch} {
        if err:=binary.Write(&b,binary.BigEndian,n);err!=nil{return nil,err}
    }
    for _, s := range []struct{s string;max int}{
        {v.RequestID,64},{v.IssuerID,64},{v.SignerEdKeyID,64},{v.SignerPQKeyID,64},
        {v.FromEdKeyID,64},{v.FromPQKeyID,64},{v.ToEdKeyID,64},{v.ToPQKeyID,64},
        {v.Method,8},{v.Path,256},
    }{
        if err:=cutoverText(&b,s.s,s.max);err!=nil{return nil,err}
    }
    for _, n:=range []int64{v.IssuedAtMS,v.ExpiresAtMS}{
        if err:=binary.Write(&b,binary.BigEndian,n);err!=nil{return nil,err}
    }
    b.Write(pn);b.Write(nonce);b.Write(candidate);b.Write(permitHash);b.Write(stateHash)
    return b.Bytes(),nil
}
func cutoverDigest(input []byte) string { sum:=sha256.Sum256(input);return hex.EncodeToString(sum[:]) }
func cutoverStateHash(v cutoverCandidate) string {
    candidate,_:=cutoverHex(v.CandidateSHA256Hex,32)
    var b bytes.Buffer
    b.WriteString("XSP2-APPLIED-STATE-V1")
    b.WriteByte(0)
    _=binary.Write(&b,binary.BigEndian,v.NodeID)
    _=binary.Write(&b,binary.BigEndian,v.ToEpoch)
    b.Write(candidate)
    return cutoverDigest(b.Bytes())
}
func ackMatchesPermit(p,a cutoverCandidate) bool {
    x,err1:=cutoverBytes(p)
    _,err2:=cutoverBytes(a)
    if err1!=nil || err2!=nil || p.Kind!="permit" || a.Kind!="ack" { return false }
    return p.NodeID==a.NodeID && p.FromEpoch==a.FromEpoch && p.ToEpoch==a.ToEpoch &&
        p.RequestID==a.RequestID && p.PermitNonceHex==a.PermitNonceHex &&
        p.CandidateSHA256Hex==a.CandidateSHA256Hex &&
        p.FromEdKeyID==a.FromEdKeyID && p.FromPQKeyID==a.FromPQKeyID &&
        p.ToEdKeyID==a.ToEdKeyID && p.ToPQKeyID==a.ToPQKeyID &&
        a.PermitSHA256Hex==cutoverDigest(x) &&
        a.AppliedStateSHA256Hex==cutoverStateHash(a) &&
        a.IssuedAtMS>=p.IssuedAtMS
}
func TestSignedCutoverContractVectorsAndNegativeCases(t *testing.T) {
    data,err:=os.ReadFile(filepath.Join("..","..","docs","XSP_V2_CUTOVER_CONTRACT_VECTORS.json"))
    if err!=nil { t.Fatal(err) }
    var doc cutoverFixtures
    if err=json.Unmarshal(data,&doc);err!=nil { t.Fatal(err) }
    if doc.Schema!="xsp2-cutover-contract-1" {t.Fatal("unknown version")}
    permit,err:=cutoverBytes(doc.Permit);if err!=nil {t.Fatal(err)}
    ack,err:=cutoverBytes(doc.Ack);if err!=nil {t.Fatal(err)}
    if cutoverDigest(permit)!=doc.PermitInputSHA256Hex || cutoverDigest(ack)!=doc.AckInputSHA256Hex ||
        cutoverStateHash(doc.Ack)!=doc.StateDigestSHA256Hex || !ackMatchesPermit(doc.Permit,doc.Ack){
        t.Fatal("canonical bytes or proposal/ACK binding changed")
    }
    invalid:=[]struct{name string;edit func(*cutoverCandidate)}{
        {"role",func(v *cutoverCandidate){v.Kind="ack"}},
        {"issuer",func(v *cutoverCandidate){v.IssuerID="node-13"}},
        {"signer",func(v *cutoverCandidate){v.SignerEdKeyID=v.ToEdKeyID}},
        {"path",func(v *cutoverCandidate){v.Path="/api/v2/node/keys/rotation/prove"}},
        {"method",func(v *cutoverCandidate){v.Method="GET"}},
        {"epoch",func(v *cutoverCandidate){v.ToEpoch=v.FromEpoch}},
        {"expired",func(v *cutoverCandidate){v.ExpiresAtMS=v.IssuedAtMS}},
        {"ttl",func(v *cutoverCandidate){v.ExpiresAtMS=v.IssuedAtMS+60001}},
        {"nonce",func(v *cutoverCandidate){v.NonceHex="ZZ"+v.NonceHex[2:]}},
        {"zero digest",func(v *cutoverCandidate){v.CandidateSHA256Hex=string(bytes.Repeat([]byte("0"),64))}},
        {"unbound permit",func(v *cutoverCandidate){v.PermitSHA256Hex=v.CandidateSHA256Hex}},
    }
    for _,tc:=range invalid{t.Run("permit_"+tc.name,func(t *testing.T){
        v:=doc.Permit;tc.edit(&v);if _,err:=cutoverBytes(v);err==nil{t.Fatal("invalid permit accepted")}
    })}
    for _,tc:=range []struct{name string;edit func(*cutoverCandidate)}{
        {"request ID",func(v *cutoverCandidate){v.RequestID="other"}},
        {"next epoch",func(v *cutoverCandidate){v.ToEpoch++}},
        {"old key",func(v *cutoverCandidate){v.FromEdKeyID="other"}},
        {"new key",func(v *cutoverCandidate){v.ToPQKeyID="other"}},
        {"candidate",func(v *cutoverCandidate){v.CandidateSHA256Hex=doc.PermitInputSHA256Hex}},
        {"permit nonce",func(v *cutoverCandidate){v.PermitNonceHex="102132435465768798a9bacbdcedfe0f"}},
        {"permit digest",func(v *cutoverCandidate){v.PermitSHA256Hex=doc.StateDigestSHA256Hex}},
        {"claimed state",func(v *cutoverCandidate){v.AppliedStateSHA256Hex=doc.PermitInputSHA256Hex}},
        {"missing ACK nonce",func(v *cutoverCandidate){v.NonceHex=v.PermitNonceHex}},
    }{t.Run("ack_"+tc.name,func(t *testing.T){
        v:=doc.Ack;tc.edit(&v);if ackMatchesPermit(doc.Permit,v){t.Fatal("unbound ACK accepted")}
    })}
    v:=doc.Permit;v.RequestID="tampered-but-canonical"
    changed,err:=cutoverBytes(v)
    if err!=nil || bytes.Equal(changed,permit){t.Fatal("request ID is not covered by signature input")}
}
