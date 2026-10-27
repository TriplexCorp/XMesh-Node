// Command interop is a TEST-ONLY bridge for XSP-v2 cross-language CI.
// Do not deploy: the wire record exposes demo seeds and has no authenticated transport.
package main

import (
 "crypto/ed25519"
 "crypto/mldsa"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "os"
)

type record struct {
 Mode string `json:"mode"`
 MessageHex string `json:"messageHex"`
 EdSeedHex string `json:"edSeedHex,omitempty"`
 PQSeedHex string `json:"pqSeedHex,omitempty"`
 EdPublicHex string `json:"edPublicHex,omitempty"`
 PQPublicHex string `json:"pqPublicHex,omitempty"`
 EdSignatureHex string `json:"edSignatureHex,omitempty"`
 PQSignatureHex string `json:"pqSignatureHex,omitempty"`
}
func raw(text string,n int)([]byte,error){
 b,e:=hex.DecodeString(text)
 if e!=nil||len(b)!=n{return nil,fmt.Errorf("invalid length or encoding")}
 return b,nil
}
func process(v record)(record,error){
 msg,e:=hex.DecodeString(v.MessageHex)
 if e!=nil||len(msg)==0||len(msg)>524288{return record{},fmt.Errorf("invalid message")}
 if v.Mode=="sign"{
  edseed,e:=raw(v.EdSeedHex,32);if e!=nil{return record{},e}
  pqseed,e:=raw(v.PQSeedHex,32);if e!=nil{return record{},e}
  ed:=ed25519.NewKeyFromSeed(edseed)
  pq,e:=mldsa.NewPrivateKey(mldsa.MLDSA65(),pqseed);if e!=nil{return record{},e}
  ps,e:=pq.SignDeterministic(msg,nil);if e!=nil{return record{},e}
  return record{Mode:"signed",MessageHex:v.MessageHex,
    EdPublicHex:hex.EncodeToString(ed.Public().(ed25519.PublicKey)),
    PQPublicHex:hex.EncodeToString(pq.PublicKey().Bytes()),
    EdSignatureHex:hex.EncodeToString(ed25519.Sign(ed,msg)),
    PQSignatureHex:hex.EncodeToString(ps)},nil
 }
 if v.Mode!="verify"{return record{},fmt.Errorf("unknown mode")}
 edpub,e:=raw(v.EdPublicHex,32);if e!=nil{return record{},e}
 pqpub,e:=raw(v.PQPublicHex,mldsa.MLDSA65PublicKeySize);if e!=nil{return record{},e}
 edsig,e:=raw(v.EdSignatureHex,64);if e!=nil{return record{},e}
 pqsig,e:=raw(v.PQSignatureHex,mldsa.MLDSA65SignatureSize);if e!=nil{return record{},e}
 public,e:=mldsa.NewPublicKey(mldsa.MLDSA65(),pqpub);if e!=nil{return record{},e}
 if !ed25519.Verify(edpub,msg,edsig){return record{},fmt.Errorf("ed25519 verification failed")}
 if e:=mldsa.Verify(public,msg,pqsig,nil);e!=nil{return record{},fmt.Errorf("ml-dsa verification failed: %w",e)}
 return record{Mode:"verified"},nil
}
func main(){
 b,e:=io.ReadAll(io.LimitReader(os.Stdin,2*1024*1024+1))
 if e!=nil||len(b)>2*1024*1024{panic("oversized or unreadable fixture")}
 var value record
 if e=json.Unmarshal(b,&value);e!=nil{panic(e)}
 result,e:=process(value);if e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
 if e=json.NewEncoder(os.Stdout).Encode(result);e!=nil{panic(e)}
}
