//go:build linux

package cutover

import (
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"

 "github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

func TestACKJournalRequiresCommittedEncryptedKeyEpoch(t *testing.T) {
 f:=load(t)
 root:=privateJournalTestDir(t)
 master:=filepath.Join(root,"master.key")
 vault:=filepath.Join(root,"vault.json")
 if e:=keyring.CreateMasterKey(master);e!=nil{t.Fatal(e)}
 prior,e:=keyring.Initialize(vault,master,int64(f.Permit.NodeID),"node_request")
 if e!=nil{t.Fatal(e)}
 next,e:=keyring.PrepareRotation(vault,master,prior.KeyEpoch)
 if e!=nil{t.Fatal(e)}
 source:=CandidateSource{
  NodeID:f.Permit.NodeID,FromEpoch:prior.KeyEpoch,ToEpoch:next.KeyEpoch,
  Purpose:"node_request",
  FromEdKeyID:prior.EdKeyID,FromPQKeyID:prior.PQKeyID,
  ToEdKeyID:next.EdKeyID,ToPQKeyID:next.PQKeyID,
  FromEdPublic:prior.EdPublic,FromPQPublic:prior.PQPublic,
  ToEdPublic:next.EdPublic,ToPQPublic:next.PQPublic,
 }
 approvedDigest,e:=CandidateDigest(source);if e!=nil{t.Fatal(e)}
 panelEd,panelPQ,pin:=pair(t)
 pin.Purpose="panel_response";pin.IssuerID=f.Permit.IssuerID;pin.NodeID=f.Permit.NodeID
 f.Permit.SignerEdKeyID=pin.EdKeyID;f.Permit.SignerPQKeyID=pin.PQKeyID
 f.Permit.FromEdKeyID=prior.EdKeyID;f.Permit.FromPQKeyID=prior.PQKeyID
 f.Permit.ToEdKeyID=next.EdKeyID;f.Permit.ToPQKeyID=next.PQKeyID
 f.Permit.CandidateSHA256Hex=approvedDigest
 want:=ExpectedPermit{NodeID:f.Permit.NodeID,FromEpoch:prior.KeyEpoch,ToEpoch:next.KeyEpoch,
  RequestID:f.Permit.RequestID,FromEdKeyID:prior.EdKeyID,FromPQKeyID:prior.PQKeyID,
  ToEdKeyID:next.EdKeyID,ToPQKeyID:next.PQKeyID,CandidateSHA256Hex:approvedDigest}
 signedPermit:=mustSign(t,f.Permit,panelEd,panelPQ)
 verified,e:=VerifyPermit(signedPermit,pin,want,f.Permit.IssuedAtMS+1000)
 if e!=nil{t.Fatal(e)}
 nextPin:=PinnedPublic{Purpose:"node_request",IssuerID:f.Ack.IssuerID,
  NodeID:f.Ack.NodeID,EdKeyID:next.EdKeyID,PQKeyID:next.PQKeyID,
  EdPublic:next.EdPublic,PQPublic:next.PQPublic}
 if _,e=keyring.AttestAppliedRotation(vault,master,prior.NodeID,1,2,next.EdKeyID,next.PQKeyID);e==nil{
  t.Fatal("permit proof must not be mistaken for applied cutover")
 }
 if _,e=keyring.ActivatePreparedRotation(vault,master,prior.KeyEpoch,next.EdKeyID,next.PQKeyID);e!=nil{t.Fatal(e)}
 keys,nowActive,e:=keyring.Open(vault,master)
 if e!=nil{t.Fatal(e)}
 if nowActive.KeyEpoch!=next.KeyEpoch{t.Fatal("wrong active epoch")}
 f.Ack.FromEdKeyID=prior.EdKeyID;f.Ack.FromPQKeyID=prior.PQKeyID
 f.Ack.ToEdKeyID=next.EdKeyID;f.Ack.ToPQKeyID=next.PQKeyID
 f.Ack.SignerEdKeyID=next.EdKeyID;f.Ack.SignerPQKeyID=next.PQKeyID
 f.Ack.CandidateSHA256Hex=approvedDigest
 f.Ack.PermitSHA256Hex=verified.PermitDigest()
 f.Ack.AppliedStateSHA256Hex,e=StateDigest(f.Ack);if e!=nil{t.Fatal(e)}
 input,e:=Canonical(f.Ack);if e!=nil{t.Fatal(e)}
 edSig,pqSig,e:=keys.Sign(input);if e!=nil{t.Fatal(e)}
 if len(edSig)!=ed25519.SignatureSize{t.Fatal("bad Ed signature length")}
 signedACK,e:=json.Marshal(SignedMessage{Message:f.Ack,Signatures:Signatures{
  Ed25519:base64.StdEncoding.EncodeToString(edSig),
  MLDSA65:base64.StdEncoding.EncodeToString(pqSig),
 }})
 if e!=nil{t.Fatal(e)}
 journal:=filepath.Join(root,"journal")
 if e=os.Mkdir(journal,0700);e!=nil{t.Fatal(e)}
 now:=f.Ack.IssuedAtMS+1000
 if _,e=PersistACKForCommittedVault(journal,vault,master,signedACK,verified,nextPin,now);e!=nil{t.Fatal(e)}
 if _,e=ReloadACKForCommittedVault(journal,vault,master,verified,nextPin,now);e!=nil{t.Fatal(e)}
 wrong:=nextPin
 wrong.EdPublic=[]byte{0}
 if _,e=ReloadACKForCommittedVault(journal,vault,master,verified,wrong,now);e==nil{
  t.Fatal("active vault Ed public substitution accepted")
 }
 previousRaw,e:=os.ReadFile(vault+".previous");if e!=nil{t.Fatal(e)}
 if e=os.WriteFile(vault,previousRaw,0600);e!=nil{t.Fatal(e)}
 if _,e=ReloadACKForCommittedVault(journal,vault,master,verified,nextPin,now);e==nil{
  t.Fatal("restored old encrypted vault trusted despite higher floor")
 }
 if _,e=keyring.RecoverRotation(vault,master);e!=nil{t.Fatal(e)}
 if _,e=ReloadACKForCommittedVault(journal,vault,master,verified,nextPin,now);e!=nil{
  t.Fatal("forward recovery cannot recover valid ACK",e)
 }
}
