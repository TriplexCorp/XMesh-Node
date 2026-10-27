package poc

// PR02 crypto interop PoC ONLY. Not linked into active Node heartbeat or router.
// Known fixed seeds in docs are PUBLIC test keys and MUST NEVER be used in production.

import (
 "bytes"
 "crypto/ed25519"
 "crypto/mldsa"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
)

type record struct {
 ID string `json:"id"`
 EdSeed string `json:"ed_seed_hex"`
 PQSeed string `json:"mldsa_seed_hex"`
 EdPublicSHA string `json:"ed_public_sha256"`
 EdSignatureSHA string `json:"ed_signature_sha256"`
 PQPublicSHA string `json:"mldsa_public_sha256"`
 PQSignatureSHA string `json:"mldsa_signature_sha256"`
}
type vector struct { ID string `json:"id"`; SigningInputHex string `json:"signing_input_hex"` }
type cryptoDoc struct { Schema string `json:"schema"`; Context string `json:"context"`; Records []record `json:"records"` }
type wireDoc struct { Vectors []vector `json:"vectors"` }
func readFixture(t *testing.T, name string, v any) {
 t.Helper()
 blob,err:=os.ReadFile(filepath.Join("..","..","..","docs",name))
 if err!=nil{t.Fatal(err)}
 if err:=json.Unmarshal(blob,v);err!=nil{t.Fatal(err)}
}
func shaHex(in []byte)string{sum:=sha256.Sum256(in);return hex.EncodeToString(sum[:])}
func decode(t *testing.T,s string,size int)[]byte{
 t.Helper();raw,err:=hex.DecodeString(s);if err!=nil||len(raw)!=size{t.Fatalf("bad fixture bytes len=%d expected=%d",len(raw),size)};return raw
}
// checkAND is intentionally NOT used for production: it demonstrates fail-closed
// hybrid verification, requiring both signatures rather than accepting either.
func checkAND(pubEd ed25519.PublicKey,pubPQ *mldsa.PublicKey,msg,sigEd,sigPQ []byte)bool{
 if len(pubEd)!=ed25519.PublicKeySize||len(sigEd)!=ed25519.SignatureSize||
   len(pubPQ.Bytes())!=mldsa.MLDSA65PublicKeySize||len(sigPQ)!=mldsa.MLDSA65SignatureSize{return false}
 if !ed25519.Verify(pubEd,msg,sigEd){return false}
 return mldsa.Verify(pubPQ,msg,sigPQ,nil)==nil
}
func TestEd25519AndMLDSA65CrossImplementationVectors(t *testing.T){
 var crypto cryptoDoc
 var wire wireDoc
 readFixture(t,"XSP_V2_CRYPTO_POC.json",&crypto)
 readFixture(t,"XSP_V2_VECTORS.json",&wire)
 if crypto.Schema!="xsp2-crypto-poc-1"||crypto.Context!=""||len(crypto.Records)!=2||len(wire.Vectors)!=2{
  t.Fatal("unexpected fixture version")
 }
 for _,r:=range crypto.Records{t.Run(r.ID,func(t *testing.T){
  var input []byte
  for _,v:=range wire.Vectors{
   if v.ID==r.ID{input=decode(t,v.SigningInputHex,len(v.SigningInputHex)/2);break}
  }
  if len(input)==0{t.Fatal("missing cross-language wire input")}
  ed:=ed25519.NewKeyFromSeed(decode(t,r.EdSeed,ed25519.SeedSize))
  pubEd:=ed.Public().(ed25519.PublicKey)
  pq,err:=mldsa.NewPrivateKey(mldsa.MLDSA65(),decode(t,r.PQSeed,mldsa.PrivateKeySize))
  if err!=nil{t.Fatal(err)}
  pubPQ:=pq.PublicKey()
  sigEd:=ed25519.Sign(ed,input)
  sigPQ,err:=pq.SignDeterministic(input,nil)
  if err!=nil{t.Fatal(err)}
  if len(pubPQ.Bytes())!=mldsa.MLDSA65PublicKeySize||len(sigPQ)!=mldsa.MLDSA65SignatureSize{
   t.Fatal("ML-DSA-65 key or signature size")
  }
  // Digests come from independently signed OpenSSL 3.5.5 test seeds.
  if shaHex(pubEd)!=r.EdPublicSHA||shaHex(sigEd)!=r.EdSignatureSHA||
   shaHex(pubPQ.Bytes())!=r.PQPublicSHA||shaHex(sigPQ)!=r.PQSignatureSHA{
   t.Fatal("Go signature/public key differs from independent OpenSSL+Ed25519 fixture")
  }
  reconstructed,err:=mldsa.NewPublicKey(mldsa.MLDSA65(),pubPQ.Bytes())
  if err!=nil{t.Fatal(err)}
  if !checkAND(pubEd,reconstructed,input,sigEd,sigPQ){t.Fatal("both valid signatures rejected")}
  altered:=bytes.Clone(input);altered[0]^=1
  if checkAND(pubEd,reconstructed,altered,sigEd,sigPQ){t.Fatal("tampered message accepted")}
  missing:=make([]byte,0)
  if checkAND(pubEd,reconstructed,input,missing,sigPQ)||checkAND(pubEd,reconstructed,input,sigEd,missing){
   t.Fatal("Ed-only or ML-DSA-only downgrade accepted")
  }
  corruptEd:=bytes.Clone(sigEd);corruptEd[0]^=1
  corruptPQ:=bytes.Clone(sigPQ);corruptPQ[len(corruptPQ)-1]^=1
  if checkAND(pubEd,reconstructed,input,corruptEd,sigPQ)||checkAND(pubEd,reconstructed,input,sigEd,corruptPQ){
   t.Fatal("corrupt signature accepted")
  }
  badEdPub:=bytes.Clone(pubEd);badEdPub[0]^=1
  if checkAND(badEdPub,reconstructed,input,sigEd,sigPQ){t.Fatal("Ed key substitution accepted")}
  wrongSeed:=decode(t,r.PQSeed,mldsa.PrivateKeySize);wrongSeed[0]^=1
  other,err:=mldsa.NewPrivateKey(mldsa.MLDSA65(),wrongSeed)
  if err!=nil{t.Fatal(err)}
  if checkAND(pubEd,other.PublicKey(),input,sigEd,sigPQ){t.Fatal("PQ key substitution accepted")}
 })}
}
