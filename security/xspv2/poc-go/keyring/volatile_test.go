package keyring

import (
 "bytes"
 "crypto/ed25519"
 "crypto/mldsa"
 "encoding/json"
 "testing"
)
func TestVolatileDualKeyGenerationAndValidation(t *testing.T){
 for _,v:=range []struct{node int64;purpose string;epoch uint64}{
  {0,"node_request",1},{5,"observer",1},{5,"node_request",0},
 }{
  if _,_,err:=Generate(v.node,v.purpose,v.epoch);err==nil{t.Fatal("accepted invalid key identity")}
 }
 for _,purpose:=range []string{"node_request","panel_response"}{
  private,pub,err:=Generate(42,purpose,1)
  if err!=nil{t.Fatal(err)}
  if len(pub.EdPublic)!=32||len(pub.PQPublic)!=1952||pub.EdKeyID==pub.PQKeyID{
   t.Fatal("wrong public key sizes or algorithm identity")
  }
  if pub.Purpose!=purpose||pub.KeyEpoch!=1||pub.NodeID!=42{t.Fatal("wrong identity binding")}
  message:=[]byte("XSP2-SIGNED-MESSAGE\x00test-only")
  edSig,pqSig,err:=private.Sign(message);if err!=nil{t.Fatal(err)}
  pqPub,err:=mldsa.NewPublicKey(mldsa.MLDSA65(),pub.PQPublic);if err!=nil{t.Fatal(err)}
  if !ed25519.Verify(pub.EdPublic,message,edSig)||mldsa.Verify(pqPub,message,pqSig,nil)!=nil{
   t.Fatal("generated signatures were not independently verified")
  }
  changed:=bytes.Clone(message);changed[0]^=1
  if ed25519.Verify(pub.EdPublic,changed,edSig)||mldsa.Verify(pqPub,changed,pqSig,nil)==nil{
   t.Fatal("tamper accepted")
  }
  _,other,err:=Generate(42,purpose,2);if err!=nil{t.Fatal(err)}
  if bytes.Equal(pub.EdPublic,other.EdPublic)||bytes.Equal(pub.PQPublic,other.PQPublic){
   t.Fatal("key rotation reused a public key")
  }
  // Only public fields have JSON representation; signing material cannot be marshaled.
  encoded,e:=json.Marshal(private);if e!=nil{t.Fatal(e)}
  if string(encoded)!="{}"{t.Fatal("secret appeared in JSON")}
  pubEncoded,e:=json.Marshal(pub);if e!=nil{t.Fatal(e)}
  if !bytes.Contains(pubEncoded,[]byte("ed25519Public")){t.Fatal("missing public bundle")}
 }
 var absent *VolatileKeys
 if _,_,err:=absent.Sign([]byte("x"));err==nil{t.Fatal("nil key accepted")}
}
