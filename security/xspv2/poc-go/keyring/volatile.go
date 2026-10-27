// Package keyring is an IN-MEMORY PR03 key lifecycle PoC, not a deployed vault.
// It never stores private keys in PostgreSQL, JSON, logs, or plaintext files.
// A production implementation still needs OS/KMS-backed persistence, rotation,
// atomic activation, backup/recovery, and independent security review.
package keyring

import (
 "crypto/ed25519"
 "crypto/mldsa"
 "crypto/rand"
 "crypto/sha256"
 "encoding/hex"
 "errors"
)

type PublicBundle struct{
 NodeID int64 `json:"nodeId"`
 Purpose string `json:"purpose"`
 KeyEpoch uint64 `json:"keyEpoch"`
 EdKeyID string `json:"ed25519KeyId"`
 PQKeyID string `json:"mldsa65KeyId"`
 EdPublic []byte `json:"ed25519Public"`
 PQPublic []byte `json:"mldsa65Public"`
}

// Secrets are deliberately private/unexported: no JSON serialization path.
type VolatileKeys struct{
 ed ed25519.PrivateKey
 pq *mldsa.PrivateKey
}

func fingerprint(prefix string, raw []byte)string{
 sum:=sha256.Sum256(raw)
 return prefix+hex.EncodeToString(sum[:12])
}

// Generate creates independently randomized key pairs for ONE identity,
// purpose, and epoch. Caller must NOT use this volatile PoC for live enrollment.
func Generate(nodeID int64,purpose string,epoch uint64)(*VolatileKeys,PublicBundle,error){
 if nodeID<=0||epoch==0||(purpose!="node_request"&&purpose!="panel_response"){
  return nil,PublicBundle{},errors.New("invalid identity, key epoch or purpose")
 }
 edPub,edPriv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{return nil,PublicBundle{},err}
 pqPriv,err:=mldsa.GenerateKey(mldsa.MLDSA65())
 if err!=nil{return nil,PublicBundle{},err}
 pqPub:=pqPriv.PublicKey().Bytes()
 if len(pqPub)!=mldsa.MLDSA65PublicKeySize {return nil,PublicBundle{},errors.New("bad provider public key size")}
 pub:=PublicBundle{
  NodeID:nodeID,Purpose:purpose,KeyEpoch:epoch,
  EdKeyID:fingerprint("ed-",edPub),PQKeyID:fingerprint("pq-",pqPub),
  EdPublic:append([]byte(nil),edPub...),PQPublic:append([]byte(nil),pqPub...),
 }
 return &VolatileKeys{ed:edPriv,pq:pqPriv},pub,nil
}

// Sign BOTH signatures on exactly the same caller-supplied canonical bytes.
func (v *VolatileKeys) Sign(input []byte)([]byte,[]byte,error){
 if v==nil||v.pq==nil||len(v.ed)!=ed25519.PrivateKeySize||len(input)==0{
  return nil,nil,errors.New("incomplete keypair or empty message")
 }
 ed:=ed25519.Sign(v.ed,input)
 pq,err:=v.pq.Sign(nil,input,nil)
 if err!=nil{return nil,nil,err}
 return ed,pq,nil
}
