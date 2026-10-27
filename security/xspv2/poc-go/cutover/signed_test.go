package cutover

import (
 "crypto/ed25519"
 "crypto/mldsa"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

type fixture struct {
 Permit Message `json:"permit"`
 Ack Message `json:"ack"`
 PermitHash string `json:"permitInputSha256Hex"`
 AckHash string `json:"ackInputSha256Hex"`
 StateHash string `json:"stateDigestSha256Hex"`
}
func pair(t *testing.T)(ed25519.PrivateKey,*mldsa.PrivateKey,PinnedPublic){
 t.Helper()
 ePub,ePriv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 pqPriv,e:=mldsa.GenerateKey(mldsa.MLDSA65());if e!=nil{t.Fatal(e)}
 pqPub:=pqPriv.PublicKey().Bytes()
 pin:=PinnedPublic{EdKeyID:id("ed-",ePub),PQKeyID:id("pq-",pqPub),
  EdPublic:ePub,PQPublic:pqPub}
 return ePriv,pqPriv,pin
}
func mustSign(t *testing.T,m Message,e ed25519.PrivateKey,p *mldsa.PrivateKey)[]byte{
 t.Helper()
 v,err:=Sign(m,e,p);if err!=nil{t.Fatal(err)}
 raw,err:=json.Marshal(v);if err!=nil{t.Fatal(err)}
 return raw
}
func load(t *testing.T)fixture{
 t.Helper()
 raw,e:=os.ReadFile(filepath.Join("..","..","..","..","docs","XSP_V2_CUTOVER_CONTRACT_VECTORS.json"))
 if e!=nil{t.Fatal(e)}
 var f fixture
 if e=json.Unmarshal(raw,&f);e!=nil{t.Fatal(e)}
 return f
}
func TestIndependentContractHashes(t *testing.T){
 f:=load(t)
 p,e:=Canonical(f.Permit);if e!=nil{t.Fatal(e)}
 a,e:=Canonical(f.Ack);if e!=nil{t.Fatal(e)}
 if sha(p)!=f.PermitHash||sha(a)!=f.AckHash{t.Fatal("Rust/Go contract digest mismatch")}
 h,e:=StateDigest(f.Ack);if e!=nil||h!=f.StateHash{t.Fatal("Rust/Go applied digest mismatch")}
}
func TestSignedPermitAndNodeAppliedACK(t *testing.T){
 f:=load(t)
 panelEd,panelPQ,pin:=pair(t)
 nodeEd,nodePQ,nodePin:=pair(t)
 pin.Purpose="panel_response";pin.IssuerID=f.Permit.IssuerID;pin.NodeID=f.Permit.NodeID
 f.Permit.SignerEdKeyID=pin.EdKeyID;f.Permit.SignerPQKeyID=pin.PQKeyID
 f.Ack.ToEdKeyID=nodePin.EdKeyID;f.Ack.ToPQKeyID=nodePin.PQKeyID
 f.Permit.ToEdKeyID=nodePin.EdKeyID;f.Permit.ToPQKeyID=nodePin.PQKeyID
 f.Ack.SignerEdKeyID=nodePin.EdKeyID;f.Ack.SignerPQKeyID=nodePin.PQKeyID
 nodePin.Purpose="node_request";nodePin.IssuerID=f.Ack.IssuerID;nodePin.NodeID=f.Ack.NodeID
 permitRaw:=mustSign(t,f.Permit,panelEd,panelPQ)
 want:=ExpectedPermit{NodeID:f.Permit.NodeID,FromEpoch:f.Permit.FromEpoch,ToEpoch:f.Permit.ToEpoch,
  RequestID:f.Permit.RequestID,FromEdKeyID:f.Permit.FromEdKeyID,FromPQKeyID:f.Permit.FromPQKeyID,
  ToEdKeyID:f.Permit.ToEdKeyID,ToPQKeyID:f.Permit.ToPQKeyID,CandidateSHA256Hex:f.Permit.CandidateSHA256Hex}
 now:=f.Permit.IssuedAtMS+1000
 ok,e:=VerifyPermit(permitRaw,pin,want,now);if e!=nil{t.Fatal(e)}
 f.Ack.PermitSHA256Hex=ok.PermitDigest()
 ackRaw:=mustSign(t,f.Ack,nodeEd,nodePQ)
 if _,e=VerifyAppliedACK(ackRaw,ok,nodePin,f.Ack.IssuedAtMS+1000);e!=nil{t.Fatal(e)}
 if _,e=VerifyPermit(permitRaw,pin,want,f.Permit.ExpiresAtMS+1);e==nil{t.Fatal("expired permit accepted")}
 if _,e=VerifyAppliedACK(ackRaw,ok,nodePin,f.Ack.ExpiresAtMS+1);e==nil{t.Fatal("expired ACK accepted")}
 wrong:=want;wrong.CandidateSHA256Hex=strings.Repeat("ab",32)
 if _,e=VerifyPermit(permitRaw,pin,wrong,now);e==nil{t.Fatal("changed owner approved digest accepted")}
 wrong=want;wrong.NodeID++;if _,e=VerifyPermit(permitRaw,pin,wrong,now);e==nil{t.Fatal("wrong node accepted")}
 wrong=want;wrong.RequestID="replayed";if _,e=VerifyPermit(permitRaw,pin,wrong,now);e==nil{t.Fatal("wrong request accepted")}
 badPin:=pin;badPin.Purpose="node_request"
 if _,e=VerifyPermit(permitRaw,badPin,want,now);e==nil{t.Fatal("panel signer purpose changed")}
 badPin=pin;badPin.PQPublic=[]byte{1}
 if _,e=VerifyPermit(permitRaw,badPin,want,now);e==nil{t.Fatal("PQ trust key substitution accepted")}
 badPin=nodePin;badPin.EdPublic=pin.EdPublic
 if _,e=VerifyAppliedACK(ackRaw,ok,badPin,f.Ack.IssuedAtMS+1);e==nil{t.Fatal("Node Ed25519 substitution accepted")}
 oldEd,oldPQ,oldPin:=pair(t)
 oldPin.Purpose="node_request";oldPin.NodeID=f.Ack.NodeID;oldPin.IssuerID=f.Ack.IssuerID
 oldACK:=f.Ack
 oldACK.SignerEdKeyID=oldPin.EdKeyID;oldACK.SignerPQKeyID=oldPin.PQKeyID
 // Old epoch keys cannot be accepted even if they sign BOTH signatures.
 // Canonical itself refuses signer key IDs that differ from pending next IDs.
 if _,e=Sign(oldACK,oldEd,oldPQ);e==nil{t.Fatal("old-key ACK accepted")}
 signEd:=f.Ack
 signEd.FromEdKeyID="tampered"
 tampered:=mustSign(t,signEd,nodeEd,nodePQ)
 if _,e=VerifyAppliedACK(tampered,ok,nodePin,f.Ack.IssuedAtMS+1);e==nil{t.Fatal("changed old-key binding accepted")}
 changed:=f.Ack
 changed.AppliedStateSHA256Hex=f.Permit.CandidateSHA256Hex
 tampered=mustSign(t,changed,nodeEd,nodePQ)
 if _,e=VerifyAppliedACK(tampered,ok,nodePin,f.Ack.IssuedAtMS+1);e==nil{t.Fatal("fabricated applied digest accepted")}
 signed,e:=Decode(permitRaw);if e!=nil{t.Fatal(e)}
 signed.Message.RequestID="changed-after-signing"
 raw,e:=json.Marshal(signed);if e!=nil{t.Fatal(e)}
 if _,e=VerifyPermit(raw,pin,want,now);e==nil{t.Fatal("tampered permit accepted")}
 signed,e=Decode(permitRaw);if e!=nil{t.Fatal(e)}
 signed.Signatures.MLDSA65=base64.StdEncoding.EncodeToString(make([]byte,mldsa.MLDSA65SignatureSize))
 raw,e=json.Marshal(signed);if e!=nil{t.Fatal(e)}
 if _,e=VerifyPermit(raw,pin,want,now);e==nil{t.Fatal("ML-DSA bypass accepted")}
 signed,e=Decode(permitRaw);if e!=nil{t.Fatal(e)}
 signed.Signatures.Ed25519=base64.StdEncoding.EncodeToString(make([]byte,ed25519.SignatureSize))
 raw,e=json.Marshal(signed);if e!=nil{t.Fatal(e)}
 if _,e=VerifyPermit(raw,pin,want,now);e==nil{t.Fatal("Ed25519 bypass accepted")}
 dup:=strings.Replace(string(permitRaw),`"kind":"permit"`,`"kind":"permit","kind":"permit"`,1)
 if _,e=Decode([]byte(dup));e==nil{t.Fatal("duplicate JSON keys accepted")}
 if _,e=Decode(append(permitRaw,[]byte("null")...));e==nil{t.Fatal("trailing JSON accepted")}
}
