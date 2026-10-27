package keyring

import (
 "bytes"
 "crypto/ed25519"
 "crypto/mldsa"
 "encoding/base64"
 "encoding/hex"
 "testing"
)
func TestOwnerApprovedDualKeyChallengeAndRotation(t *testing.T){
 keys,pub,err:=Generate(42,"node_request",1)
 if err!=nil{t.Fatal(err)}
 nonce:=bytes.Repeat([]byte{0xa5},32)
 msg,err:=EnrollmentSigningInput(pub,nonce)
 if err!=nil{t.Fatal(err)}
 if !bytes.HasPrefix(msg,[]byte("XSP2-KEY-ENROLL-V1\x00")){t.Fatal("missing domain separator")}
 first,err:=BuildEnrollmentProof(keys,pub,hex.EncodeToString(nonce))
 if err!=nil{t.Fatal(err)}
 edSig,err:=base64.StdEncoding.DecodeString(first.Ed25519SignatureB64)
 if err!=nil||len(edSig)!=64{t.Fatal("bad Ed25519 signature")}
 pqSig,err:=base64.StdEncoding.DecodeString(first.MLDSA65SignatureB64)
 if err!=nil||len(pqSig)!=3309{t.Fatal("bad ML-DSA-65 signature")}
 pqPublic,err:=mldsa.NewPublicKey(mldsa.MLDSA65(),pub.PQPublic)
 if err!=nil{t.Fatal(err)}
 if !ed25519.Verify(pub.EdPublic,msg,edSig)||mldsa.Verify(pqPublic,msg,pqSig,nil)!=nil{
  t.Fatal("valid dual proof rejected")
 }
 for _,other:=range []PublicBundle{
  func()PublicBundle{p:=pub;p.NodeID=43;return p}(),
  func()PublicBundle{p:=pub;p.KeyEpoch=2;return p}(),
  func()PublicBundle{p:=pub;p.EdKeyID="ed-other";return p}(),
 }{
  value,err:=EnrollmentSigningInput(other,nonce)
  if err==nil && (ed25519.Verify(pub.EdPublic,value,edSig)||mldsa.Verify(pqPublic,value,pqSig,nil)==nil){
   t.Fatal("proof bound to another node/epoch/key")
  }
 }
 changed:=bytes.Clone(nonce);changed[0]^=1
 different,err:=EnrollmentSigningInput(pub,changed)
 if err!=nil{t.Fatal(err)}
 if bytes.Equal(msg,different)||ed25519.Verify(pub.EdPublic,different,edSig)||mldsa.Verify(pqPublic,different,pqSig,nil)==nil{
  t.Fatal("challenge substitution accepted")
 }
 if _,err:=BuildEnrollmentProof(keys,pub,"abcd");err==nil{t.Fatal("invalid challenge accepted")}
 if _,err:=BuildEnrollmentProof(keys,pub,"A"+hex.EncodeToString(nonce)[1:]);err==nil{
  t.Fatal("noncanonical challenge accepted")
 }
 if first.KeyEpoch!=1||first.NodeID!=42||first.Purpose!="node_request"{t.Fatal("wrong claim identifiers")}
 // Same original proof cannot authorize a new epoch or a rotated keypair.
 _,next,err:=Generate(42,"node_request",2)
 if err!=nil{t.Fatal(err)}
 nextInput,err:=EnrollmentSigningInput(next,nonce)
 if err!=nil{t.Fatal(err)}
 if ed25519.Verify(next.EdPublic,msg,edSig)||bytes.Equal(nextInput,msg){t.Fatal("old proof reused after rotation")}
}
