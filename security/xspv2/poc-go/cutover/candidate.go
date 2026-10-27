package cutover

// Candidate v1 binds the exact independently approved old + pending public
// keysets. This is a staging-only serializer; it does not grant cutover consent.
import (
 "bytes"
 "errors"
)

// CandidateSource must be populated from a trusted current keyset and separately
// approved, dual-PoP-verified pending keyset. Never populate from a signed
// permit's candidateSha256Hex or from untrusted JSON supplied by the caller.
type CandidateSource struct {
 NodeID uint64
 FromEpoch uint64
 ToEpoch uint64
 Purpose string
 FromEdKeyID string
 FromPQKeyID string
 ToEdKeyID string
 ToPQKeyID string
 FromEdPublic []byte
 FromPQPublic []byte
 ToEdPublic []byte
 ToPQPublic []byte
}

func CandidateCanonical(c CandidateSource) ([]byte,error) {
 if c.NodeID==0 || c.FromEpoch==0 || c.FromEpoch==^uint64(0) || c.ToEpoch!=c.FromEpoch+1 ||
  c.Purpose!="node_request" {
  return nil,errors.New("candidate epoch, recipient or purpose mismatch")
 }
 fields:=[]string{c.Purpose,c.FromEdKeyID,c.FromPQKeyID,c.ToEdKeyID,c.ToPQKeyID}
 keys:=[][]byte{c.FromEdPublic,c.FromPQPublic,c.ToEdPublic,c.ToPQPublic}
 for i,key:=range keys{
  size:=1952
  if i%2==0 {size=32}
  if len(key)!=size || zero(key) { return nil,errors.New("missing or invalid public key bytes") }
 }
 if c.FromEdKeyID!=id("ed-",c.FromEdPublic) ||
  c.FromPQKeyID!=id("pq-",c.FromPQPublic) ||
  c.ToEdKeyID!=id("ed-",c.ToEdPublic) ||
  c.ToPQKeyID!=id("pq-",c.ToPQPublic) {
  return nil,errors.New("public key ID does not match SHA-256 fingerprint")
 }
 var out bytes.Buffer
 out.WriteString("XSP2-CUTOVER-CANDIDATE-V1")
 out.WriteByte(0)
 out.WriteByte(1)
 for _,n:=range []uint64{c.NodeID,c.FromEpoch,c.ToEpoch} {u64(&out,n)}
 for i,s:=range fields {
  max:=64
  if i==0{max=len("node_request")}
  if err:=text(&out,s,max);err!=nil{return nil,err}
 }
 for _,key:=range keys {out.Write(key)}
 return out.Bytes(),nil
}
func CandidateDigest(c CandidateSource) (string,error) {
 b,err:=CandidateCanonical(c)
 if err!=nil {return "",err}
 return sha(b),nil
}
