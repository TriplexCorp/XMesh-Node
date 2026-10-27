package cutover

import (
 "bytes"
 "encoding/json"
 "math"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
type candidateFixture struct {
 Schema string `json:"schema"`
 NodeID uint64 `json:"nodeId"`
 FromEpoch uint64 `json:"fromEpoch"`
 ToEpoch uint64 `json:"toEpoch"`
 Purpose string `json:"purpose"`
 FromEdKeyID string `json:"fromEdKeyId"`
 FromPQKeyID string `json:"fromPQKeyId"`
 ToEdKeyID string `json:"toEdKeyId"`
 ToPQKeyID string `json:"toPQKeyId"`
 OldEdByteHex string `json:"oldEdByteHex"`
 OldPQByteHex string `json:"oldPQByteHex"`
 NewEdByteHex string `json:"newEdByteHex"`
 NewPQByteHex string `json:"newPQByteHex"`
 CandidateSHA256Hex string `json:"candidateSha256Hex"`
 CanonicalLength int `json:"canonicalLength"`
}
func testCandidateFixture(t *testing.T) CandidateSource {
 t.Helper()
 b,e:=os.ReadFile(filepath.Join("..","..","..","..","docs","XSP_V2_CUTOVER_CANDIDATE_VECTORS.json"))
 if e!=nil {t.Fatal(e)}
 var v candidateFixture
 if e=json.Unmarshal(b,&v);e!=nil{t.Fatal(e)}
 if v.Schema!="xsp2-cutover-candidate-public-binding-1" {t.Fatal("schema mismatch")}
 key:=func(one string,size int) []byte {
  b,e:=hexField(one,1);if e!=nil{t.Fatal(e)}
  return bytes.Repeat(b,size)
 }
 c:=CandidateSource{NodeID:v.NodeID,FromEpoch:v.FromEpoch,ToEpoch:v.ToEpoch,Purpose:v.Purpose,
  FromEdKeyID:v.FromEdKeyID,FromPQKeyID:v.FromPQKeyID,ToEdKeyID:v.ToEdKeyID,ToPQKeyID:v.ToPQKeyID,
  FromEdPublic:key(v.OldEdByteHex,32),FromPQPublic:key(v.OldPQByteHex,1952),
  ToEdPublic:key(v.NewEdByteHex,32),ToPQPublic:key(v.NewPQByteHex,1952)}
 actual,e:=CandidateCanonical(c);if e!=nil{t.Fatal(e)}
 digest,e:=CandidateDigest(c);if e!=nil{t.Fatal(e)}
 if len(actual)!=v.CanonicalLength || digest!=v.CandidateSHA256Hex {t.Fatalf("candidate digest mismatch: %s length %d",digest,len(actual))}
 return c
}
func TestCandidateBindingMatchesIndependentFixture(t *testing.T) {
 base:=testCandidateFixture(t)
 original,_:=CandidateDigest(base)
 for _,tc:=range []struct{name string;edit func(*CandidateSource)}{
  {"node",func(c *CandidateSource){c.NodeID++}},
  {"from_epoch",func(c *CandidateSource){c.FromEpoch++}},
  {"to_epoch",func(c *CandidateSource){c.ToEpoch++}},
  {"purpose",func(c *CandidateSource){c.Purpose="panel_response"}},
  {"old_ed_id",func(c *CandidateSource){c.FromEdKeyID="other-old-ed"}},
  {"old_pq_id",func(c *CandidateSource){c.FromPQKeyID="other-old-pq"}},
  {"new_ed_id",func(c *CandidateSource){c.ToEdKeyID="other-new-ed"}},
  {"new_pq_id",func(c *CandidateSource){c.ToPQKeyID="other-new-pq"}},
  {"old_ed_bytes",func(c *CandidateSource){c.FromEdPublic=bytes.Clone(c.FromEdPublic);c.FromEdPublic[0]^=0x01}},
  {"old_pq_bytes",func(c *CandidateSource){c.FromPQPublic=bytes.Clone(c.FromPQPublic);c.FromPQPublic[0]^=0x01}},
  {"new_ed_bytes",func(c *CandidateSource){c.ToEdPublic=bytes.Clone(c.ToEdPublic);c.ToEdPublic[0]^=0x01}},
  {"new_pq_bytes",func(c *CandidateSource){c.ToPQPublic=bytes.Clone(c.ToPQPublic);c.ToPQPublic[0]^=0x01}},
 }{
  t.Run(tc.name,func(t *testing.T){c:=base;tc.edit(&c);digest,e:=CandidateDigest(c);if e==nil && digest==original {t.Fatal("candidate mutation escaped binding")}})
 }
}
func TestCandidateRejectsBadPublicInput(t *testing.T) {
 base:=testCandidateFixture(t)
 for _,tc:=range []struct{name string;edit func(*CandidateSource)}{
  {"zero_node",func(c *CandidateSource){c.NodeID=0}},
  {"zero_epoch",func(c *CandidateSource){c.FromEpoch=0}},
  {"epoch_overflow",func(c *CandidateSource){c.FromEpoch=math.MaxUint64;c.ToEpoch=0}},
  {"same_epoch",func(c *CandidateSource){c.ToEpoch=c.FromEpoch}},
  {"unapproved_purpose",func(c *CandidateSource){c.Purpose="panel_response"}},
  {"empty_id",func(c *CandidateSource){c.ToPQKeyID=""}},
  {"overlong_id",func(c *CandidateSource){c.FromEdKeyID=strings.Repeat("x",65)}},
  {"space_id",func(c *CandidateSource){c.ToEdKeyID="has space"}},
  {"wrong_ed_size",func(c *CandidateSource){c.FromEdPublic=c.FromEdPublic[:31]}},
  {"wrong_pq_size",func(c *CandidateSource){c.ToPQPublic=c.ToPQPublic[:1951]}},
  {"zero_old_ed",func(c *CandidateSource){c.FromEdPublic=make([]byte,32)}},
  {"zero_new_pq",func(c *CandidateSource){c.ToPQPublic=make([]byte,1952)}},
 }{
  t.Run(tc.name,func(t *testing.T){c:=base;tc.edit(&c);if _,e:=CandidateDigest(c);e==nil{t.Fatal("invalid candidate accepted")}})
 }
}
