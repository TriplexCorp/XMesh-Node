package keyring

// Experimental owner-approved XSP-v2 key possession proof.
// Signed ONLY from locally protected key material, NEVER sent to the Nexus
// production API. Must run against an explicitly isolated staging endpoint.
import (
 "crypto/ed25519"
 "crypto/mldsa"
 "encoding/base64"
 "encoding/binary"
 "encoding/hex"
 "errors"
)

type EnrollmentProof struct {
 NodeID int64 `json:"nodeId"`
 Purpose string `json:"purpose"`
 KeyEpoch uint64 `json:"keyEpoch"`
 ChallengeHex string `json:"challengeHex"`
 Ed25519SignatureB64 string `json:"ed25519SignatureB64"`
 MLDSA65SignatureB64 string `json:"mldsa65SignatureB64"`
}

func PutProofASCII(buf []byte,part string,max int)([]byte,error){
 if len(part)==0||len(part)>max {return nil,errors.New("invalid XSP-v2 proof metadata length")}
 for i:=0;i<len(part);i++{if part[i]<33||part[i]>126{return nil,errors.New("invalid XSP-v2 proof metadata")}
 }
 var length [4]byte
 binary.BigEndian.PutUint32(length[:],uint32(len(part)))
 buf=append(buf,length[:]...)
 return append(buf,part...),nil
}

// marshalProofInput encodes the bounded, length-framed Node identity and
// public keys. Rotation uses a SEPARATE signature domain and binds the old
// and new epoch: an initial enrollment proof cannot be used for rotation.
func marshalProofInput(bundle PublicBundle,challenge []byte,domain string,from uint64)([]byte,error){
 if bundle.NodeID<=0||bundle.KeyEpoch==0||bundle.Purpose!="node_request"||
   len(challenge)!=32||len(bundle.EdPublic)!=ed25519.PublicKeySize||
   len(bundle.PQPublic)!=mldsa.MLDSA65PublicKeySize||
   bundle.EdKeyID!=fingerprint("ed-",bundle.EdPublic)||
   bundle.PQKeyID!=fingerprint("pq-",bundle.PQPublic){
  return nil,errors.New("invalid proof subject or public key IDs")
 }
 buf:=append([]byte(nil),[]byte(domain)...)
 buf=append(buf,0)
 var be [8]byte
 binary.BigEndian.PutUint64(be[:],uint64(bundle.NodeID));buf=append(buf,be[:]...)
 if from>0{binary.BigEndian.PutUint64(be[:],from);buf=append(buf,be[:]...)}
 binary.BigEndian.PutUint64(be[:],bundle.KeyEpoch);buf=append(buf,be[:]...)
 var err error
 buf,err=PutProofASCII(buf,bundle.Purpose,32);if err!=nil{return nil,err}
 buf=append(buf,challenge...)
 buf=append(buf,bundle.EdPublic...)
 buf=append(buf,bundle.PQPublic...)
 buf,err=PutProofASCII(buf,bundle.EdKeyID,64);if err!=nil{return nil,err}
 buf,err=PutProofASCII(buf,bundle.PQKeyID,64);if err!=nil{return nil,err}
 return buf,nil
}

// EnrollmentSigningInput matches Rust initial enrollment verification bytes.
func EnrollmentSigningInput(bundle PublicBundle,challenge []byte)([]byte,error){
 return marshalProofInput(bundle,challenge,"XSP2-KEY-ENROLL-V1",0)
}

// RotationSigningInput binds a prepared keyset and its currently active
// epoch in a different signature domain. This is NOT a signed Nexus ACK.
func RotationSigningInput(bundle PublicBundle,fromEpoch uint64,challenge []byte)([]byte,error){
 if fromEpoch==0||fromEpoch==^uint64(0)||bundle.KeyEpoch!=fromEpoch+1{
  return nil,errors.New("invalid prepared rotation epochs")
 }
 return marshalProofInput(bundle,challenge,"XSP2-KEY-ROTATE-PREPARE-V1",fromEpoch)
}

// BuildEnrollmentProof refuses wrong epochs and uses BOTH private keys.
// Proof is one-use on the backend, tied to owner-approved registered keys.
func BuildEnrollmentProof(keys *VolatileKeys,bundle PublicBundle,challengeHex string)(EnrollmentProof,error){
 var zero EnrollmentProof
 if len(challengeHex)!=64{return zero,errors.New("invalid enrollment challenge size")}
 challenge,err:=hex.DecodeString(challengeHex)
 if err!=nil||hex.EncodeToString(challenge)!=challengeHex{return zero,errors.New("noncanonical enrollment challenge")}
 input,err:=EnrollmentSigningInput(bundle,challenge);if err!=nil{return zero,err}
 ed,pq,err:=keys.Sign(input);if err!=nil{return zero,err}
 return EnrollmentProof{
  NodeID:bundle.NodeID,Purpose:bundle.Purpose,KeyEpoch:bundle.KeyEpoch,
  ChallengeHex:challengeHex,
  Ed25519SignatureB64:base64.StdEncoding.EncodeToString(ed),
  MLDSA65SignatureB64:base64.StdEncoding.EncodeToString(pq),
 },nil
}
func ProveFromEncryptedVault(vault,master,challengeHex string)(EnrollmentProof,error){
 var zero EnrollmentProof
 keys,bundle,err:=Open(vault,master);if err!=nil{return zero,err}
 return BuildEnrollmentProof(keys,bundle,challengeHex)
}
