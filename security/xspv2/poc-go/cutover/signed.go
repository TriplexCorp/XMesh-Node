// Package cutover contains staging-only XSP-v2 signed cutover protocol primitives.
// It has no network endpoints, durable replay database, or production activation.
package cutover

import (
 "bytes"
 "crypto/ed25519"
 "crypto/mldsa"
 "crypto/sha256"
 "encoding/base64"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "strconv"
)

// Message is a purpose- and endpoint-bound cutover permit or applied ACK.
// It MUST be authenticated before any side effect.
type Message struct {
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
type Signatures struct {
 Ed25519 string `json:"ed25519"`
 MLDSA65 string `json:"mldsa65"`
}
type SignedMessage struct {
 Message Message `json:"message"`
 Signatures Signatures `json:"signatures"`
}
type PinnedPublic struct {
 IssuerID string
 Purpose string
 NodeID uint64
 EdKeyID string
 PQKeyID string
 EdPublic []byte
 PQPublic []byte
}
type ExpectedPermit struct {
 NodeID, FromEpoch, ToEpoch uint64
 RequestID, FromEdKeyID, FromPQKeyID, ToEdKeyID, ToPQKeyID string
 CandidateSHA256Hex string // MUST come from independently approved candidate, never the message
}
type VerifiedPermit struct {
 message Message
 inputHash string
}
func (v VerifiedPermit) Message() Message { return v.message }
func (v VerifiedPermit) PermitDigest() string { return v.inputHash }

func sha(raw []byte) string { s:=sha256.Sum256(raw);return hex.EncodeToString(s[:]) }
func id(prefix string, raw []byte) string { h:=sha256.Sum256(raw);return prefix+hex.EncodeToString(h[:12]) }
func hexField(s string, size int) ([]byte,error) {
 if len(s)!=size*2{return nil,errors.New("wrong hex length")}
 b,e:=hex.DecodeString(s);if e!=nil||hex.EncodeToString(b)!=s{return nil,errors.New("noncanonical hex")}
 return b,nil
}
func zero(b []byte) bool { for _,v:=range b{if v!=0{return false}};return true }
func text(out *bytes.Buffer, s string, max int) error {
 if len(s)==0||len(s)>max{return errors.New("invalid field length")}
 for _,b:=range []byte(s){if b<33||b>126{return errors.New("invalid ASCII field")}}
 var n [4]byte
 binary.BigEndian.PutUint32(n[:],uint32(len(s)))
 out.Write(n[:]);out.WriteString(s)
 return nil
}
func u64(out *bytes.Buffer, n uint64){var tmp [8]byte;binary.BigEndian.PutUint64(tmp[:],n);out.Write(tmp[:])}
func i64(out *bytes.Buffer, n int64){u64(out,uint64(n))}

// Canonical reconstructs the frozen cross-language byte sequence.
// This is syntax and role validation only; no trust, freshness or signature verification.
func Canonical(v Message)([]byte,error) {
 var domain string
 var direction byte
 switch v.Kind{
 case "permit":
  domain="XSP2-CUTOVER-PERMIT-V1";direction=2
  if v.Path!="/api/v2/node/keys/rotation/permit" || v.IssuerID=="node-"+strconv.FormatUint(v.NodeID,10) ||
    v.SignerEdKeyID==v.ToEdKeyID || v.SignerPQKeyID==v.ToPQKeyID{return nil,errors.New("permit role invalid")}
 case "ack":
  domain="XSP2-CUTOVER-APPLIED-ACK-V1";direction=1
  if v.Path!="/api/v2/node/keys/rotation/ack" || v.IssuerID!="node-"+strconv.FormatUint(v.NodeID,10) ||
    v.SignerEdKeyID!=v.ToEdKeyID || v.SignerPQKeyID!=v.ToPQKeyID{return nil,errors.New("ACK role invalid")}
 default:return nil,errors.New("unknown signed cutover kind")
 }
 if v.NodeID==0||v.FromEpoch==0||v.FromEpoch==^uint64(0)||v.ToEpoch!=v.FromEpoch+1||
   v.IssuedAtMS<=0||v.ExpiresAtMS<=v.IssuedAtMS||v.ExpiresAtMS-v.IssuedAtMS>60000||
   v.Method!="POST"{return nil,errors.New("invalid epochs/method/TTL")}
 pn,e1:=hexField(v.PermitNonceHex,16);nonce,e2:=hexField(v.NonceHex,16)
 candidate,e3:=hexField(v.CandidateSHA256Hex,32);ph,e4:=hexField(v.PermitSHA256Hex,32)
 ah,e5:=hexField(v.AppliedStateSHA256Hex,32)
 if e1!=nil||e2!=nil||e3!=nil||e4!=nil||e5!=nil||zero(pn)||zero(nonce)||zero(candidate){
  return nil,errors.New("invalid nonce/digest")
 }
 if v.Kind=="permit" && (!bytes.Equal(pn,nonce)||!zero(ph)||!zero(ah)) {return nil,errors.New("permit cannot claim applied")}
 if v.Kind=="ack" && (bytes.Equal(pn,nonce)||zero(ph)||zero(ah)){return nil,errors.New("unbound ACK")}
 var out bytes.Buffer
 out.WriteString(domain);out.WriteByte(0);out.Write([]byte{1,direction})
 for _,n:=range []uint64{v.NodeID,v.FromEpoch,v.ToEpoch}{u64(&out,n)}
 for _,field:=range []struct{s string;max int}{
  {v.RequestID,64},{v.IssuerID,64},{v.SignerEdKeyID,64},{v.SignerPQKeyID,64},
  {v.FromEdKeyID,64},{v.FromPQKeyID,64},{v.ToEdKeyID,64},{v.ToPQKeyID,64},
  {v.Method,8},{v.Path,256},
 }{if e:=text(&out,field.s,field.max);e!=nil{return nil,e}}
 i64(&out,v.IssuedAtMS);i64(&out,v.ExpiresAtMS)
 out.Write(pn);out.Write(nonce);out.Write(candidate);out.Write(ph);out.Write(ah)
 return out.Bytes(),nil
}
func StateDigest(m Message)(string,error){
 candidate,e:=hexField(m.CandidateSHA256Hex,32);if e!=nil{return "",e}
 var out bytes.Buffer
 out.WriteString("XSP2-APPLIED-STATE-V1");out.WriteByte(0)
 u64(&out,m.NodeID);u64(&out,m.ToEpoch);out.Write(candidate)
 return sha(out.Bytes()),nil
}
// No recursive maps/arrays in this protocol. This rejects duplicate keys at
// both levels, including ambiguous nested signature representations.
func uniqueFields(raw []byte) error {
 d:=json.NewDecoder(bytes.NewReader(raw));d.UseNumber()
 count:=0
 var walk func(int)error
 walk=func(depth int)error{
  count++;if depth>3||count>64{return errors.New("excessive JSON complexity")}
  tok,e:=d.Token();if e!=nil{return e}
  delim,ok:=tok.(json.Delim);if !ok{return nil}
  if delim!='{' {return errors.New("arrays not allowed")}
  seen:=map[string]bool{}
  for d.More(){
   k,e:=d.Token();if e!=nil{return e}
   name,ok:=k.(string);if !ok||seen[name]{return errors.New("duplicate JSON field")}
   seen[name]=true
   if e=walk(depth+1);e!=nil{return e}
  }
  _,e=d.Token();return e
 }
 if e:=walk(0);e!=nil{return e}
 if _,e:=d.Token();e!=io.EOF{return errors.New("trailing JSON")}
 return nil
}
func Decode(raw []byte)(SignedMessage,error){
 var m SignedMessage
 if len(raw)==0||len(raw)>16*1024{return m,errors.New("signed message size")}
 if e:=uniqueFields(raw);e!=nil{return m,e}
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 if e:=d.Decode(&m);e!=nil{return SignedMessage{},e}
 if e:=d.Decode(new(any));e!=io.EOF{return SignedMessage{},errors.New("trailing bytes")}
 if _,e:=Canonical(m.Message);e!=nil{return SignedMessage{},e}
 return m,nil
}
func b64(src string,n int)([]byte,error){
 if len(src)!=((n+2)/3)*4{return nil,errors.New("signature size")}
 v,e:=base64.StdEncoding.Strict().DecodeString(src)
 if e!=nil||len(v)!=n||base64.StdEncoding.EncodeToString(v)!=src{return nil,errors.New("noncanonical signature")}
 return v,nil
}
func checkPublic(p PinnedPublic, v Message, purpose string) error {
 if p.Purpose!=purpose||p.NodeID!=v.NodeID||p.IssuerID!=v.IssuerID||
   p.EdKeyID!=v.SignerEdKeyID||p.PQKeyID!=v.SignerPQKeyID||
   len(p.EdPublic)!=ed25519.PublicKeySize||len(p.PQPublic)!=mldsa.MLDSA65PublicKeySize||
   p.EdKeyID!=id("ed-",p.EdPublic)||p.PQKeyID!=id("pq-",p.PQPublic){
   return errors.New("untrusted signer identity, purpose or fingerprint")
 }
 return nil
}
func verifyBoth(s SignedMessage,p PinnedPublic)([]byte,error){
 input,e:=Canonical(s.Message);if e!=nil{return nil,e}
 ed,e:=b64(s.Signatures.Ed25519,ed25519.SignatureSize);if e!=nil{return nil,e}
 pq,e:=b64(s.Signatures.MLDSA65,mldsa.MLDSA65SignatureSize);if e!=nil{return nil,e}
 if !ed25519.Verify(p.EdPublic,input,ed){return nil,errors.New("Ed25519 signature invalid")}
 pub,e:=mldsa.NewPublicKey(mldsa.MLDSA65(),p.PQPublic);if e!=nil{return nil,e}
 if e=mldsa.Verify(pub,input,pq,nil);e!=nil{return nil,errors.New("ML-DSA-65 signature invalid")}
 return input,nil
}
func checkClock(v Message,now int64) error {
 if now<=0||now>v.ExpiresAtMS||v.IssuedAtMS>now+120000||now>v.IssuedAtMS+120000{
  return errors.New("stale or future signed message")
 }
 return nil
}
func permitMatches(v Message,e ExpectedPermit)bool{
 return v.NodeID==e.NodeID && v.FromEpoch==e.FromEpoch && v.ToEpoch==e.ToEpoch &&
  v.RequestID==e.RequestID && v.FromEdKeyID==e.FromEdKeyID && v.FromPQKeyID==e.FromPQKeyID &&
  v.ToEdKeyID==e.ToEdKeyID && v.ToPQKeyID==e.ToPQKeyID &&
  v.CandidateSHA256Hex==e.CandidateSHA256Hex
}
// VerifyPermit returns an unforgeable-in-process marker; caller STILL MUST
// implement durable nonce/request replay, local vault checks and persistence.
func VerifyPermit(raw []byte,pin PinnedPublic,want ExpectedPermit,now int64)(VerifiedPermit,error){
 s,e:=Decode(raw);if e!=nil{return VerifiedPermit{},e}
 if s.Message.Kind!="permit"||!permitMatches(s.Message,want){return VerifiedPermit{},errors.New("unapproved candidate/request")}
 if e=checkPublic(pin,s.Message,"panel_response");e!=nil{return VerifiedPermit{},e}
 if e=checkClock(s.Message,now);e!=nil{return VerifiedPermit{},e}
 signed,e:=verifyBoth(s,pin);if e!=nil{return VerifiedPermit{},e}
 return VerifiedPermit{message:s.Message,inputHash:sha(signed)},nil
}
// VerifyAppliedACK authenticates the NEW pending Node pair (not old keys)
// and checks exact saved, previously trusted permit binding. The external DB
// must atomically consume nonce/ack and advance epoch only after this passes.
func VerifyAppliedACK(raw []byte,issued VerifiedPermit,newKeys PinnedPublic,now int64)(Message,error){
 s,e:=Decode(raw);if e!=nil{return Message{},e}
 a,p:=s.Message,issued.message
 if issued.inputHash==""||p.Kind!="permit"||a.Kind!="ack"||
  a.NodeID!=p.NodeID||a.FromEpoch!=p.FromEpoch||a.ToEpoch!=p.ToEpoch||
  a.RequestID!=p.RequestID||a.PermitNonceHex!=p.PermitNonceHex||
  a.CandidateSHA256Hex!=p.CandidateSHA256Hex||
  a.FromEdKeyID!=p.FromEdKeyID||a.FromPQKeyID!=p.FromPQKeyID||
  a.ToEdKeyID!=p.ToEdKeyID||a.ToPQKeyID!=p.ToPQKeyID||
  a.PermitSHA256Hex!=issued.inputHash||a.IssuedAtMS<p.IssuedAtMS {
  return Message{},errors.New("ACK not bound to trusted permit")
 }
 expectedState,e:=StateDigest(a)
 if e!=nil||a.AppliedStateSHA256Hex!=expectedState{return Message{},errors.New("wrong applied state digest")}
 if e=checkPublic(newKeys,a,"node_request");e!=nil{return Message{},e}
 if newKeys.EdKeyID!=p.ToEdKeyID||newKeys.PQKeyID!=p.ToPQKeyID{return Message{},errors.New("ACK not signed by pending identity")}
 if e=checkClock(a,now);e!=nil{return Message{},e}
 if _,e=verifyBoth(s,newKeys);e!=nil{return Message{},e}
 return a,nil
}
// Offline-only test/staging utility: signing keys are injected from trusted
// local storage, not from a request. It does not grant owner approval.
func Sign(m Message, ed ed25519.PrivateKey,pq *mldsa.PrivateKey)(SignedMessage,error){
 input,e:=Canonical(m);if e!=nil{return SignedMessage{},e}
 if len(ed)!=ed25519.PrivateKeySize||pq==nil{return SignedMessage{},errors.New("signing keys absent")}
 pqSig,e:=pq.Sign(nil,input,nil);if e!=nil{return SignedMessage{},fmt.Errorf("ML-DSA signing: %w",e)}
 return SignedMessage{Message:m,Signatures:Signatures{
  Ed25519:base64.StdEncoding.EncodeToString(ed25519.Sign(ed,input)),
  MLDSA65:base64.StdEncoding.EncodeToString(pqSig),
 }},nil
}
