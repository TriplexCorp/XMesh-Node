package envelope

import (
 "bytes"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

type fixture struct{ Vectors []struct{
 ID string `json:"id"`
 DirectionID uint8 `json:"direction_id"`
 MessageType string `json:"message_type"`
 IssuerID string `json:"issuer_id"`
 NodeID int64 `json:"node_id"`
 Method string `json:"method"`
 Path string `json:"path"`
 EdKeyID string `json:"ed_key_id"`
 PQKeyID string `json:"pq_key_id"`
 KeyEpoch int64 `json:"key_epoch"`
 IssuedMS int64 `json:"issued_at_ms"`
 ExpiresMS int64 `json:"expires_at_ms"`
 NonceHex string `json:"nonce_hex"`
 RequestID string `json:"request_id"`
 Revision string `json:"revision"`
 Payload string `json:"payload_utf8"`
 SigningHex string `json:"signing_input_hex"`
} `json:"vectors"` }
func TestStrictEnvelopeGoldenAndNegative(t *testing.T){
 raw,err:=os.ReadFile(filepath.Join("..","..","..","docs","XSP_V2_VECTORS.json"))
 if err!=nil{t.Fatal(err)}
 var f fixture
 if err:=json.Unmarshal(raw,&f);err!=nil{t.Fatal(err)}
 if len(f.Vectors)!=2{t.Fatal("expected two wire directions")}
 for _,v:=range f.Vectors{t.Run(v.ID,func(t *testing.T){
  doc:=Envelope{
   Protocol:"XSP/2",Suite:"Ed25519+ML-DSA-65",Direction:v.DirectionID,
   MessageType:v.MessageType,IssuerID:v.IssuerID,NodeID:v.NodeID,
   Method:v.Method,Path:v.Path,Ed25519KeyID:v.EdKeyID,
   MLDSA65KeyID:v.PQKeyID,KeyEpoch:v.KeyEpoch,
   IssuedAtMS:v.IssuedMS,ExpiresAtMS:v.ExpiresMS,
   NonceHex:v.NonceHex,RequestID:v.RequestID,Revision:v.Revision,
   PayloadB64:base64.StdEncoding.EncodeToString([]byte(v.Payload)),
   Signatures:Signatures{
    Ed25519:base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xa3},64)),
    MLDSA65:base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xb7},3309)),
   },
  }
  pack:=func(d Envelope)[]byte{t.Helper();b,e:=json.Marshal(d);if e!=nil{t.Fatal(e)};return b}
  good:=pack(doc)
  parsed,err:=DecodeUntrustedEnvelope(good);if err!=nil{t.Fatal(err)}
  if hex.EncodeToString(parsed.SigningInput)!=v.SigningHex{t.Fatal("does not match shared signed bytes")}
  if !bytes.Equal(parsed.Payload,[]byte(v.Payload)){t.Fatal("payload was transformed")}
  // A parser returning Untrusted does not authenticate the synthetic test signatures.
  badCases:=[]struct{name string;data []byte}{
   {"duplicate top-level",append([]byte(`{"protocol":"XSP/2",`),good[1:]...)},
   {"unknown top-level",append([]byte(`{"unexpected":1,`),good[1:]...)},
   {"duplicate nested signature",bytes.Replace(good,[]byte(`"ed25519":`),[]byte(`"ed25519":"x","ed25519":`),1)},
   {"unknown nested signature",bytes.Replace(good,[]byte(`"signatures":{`),[]byte(`"signatures":{"unknown":1,`),1)},
   {"trailing object",append(append([]byte{},good...),[]byte("{}")...)},
   {"oversized",bytes.Repeat([]byte("x"),MaxEnvelopeBytes+1)},
  }
  for _,bad:=range badCases{if _,e:=DecodeUntrustedEnvelope(bad.data);e==nil{t.Errorf("accepted %s",bad.name)}}
  variants:=[]struct{name string;modify func(*Envelope)}{
   {"missing ed25519",func(e *Envelope){e.Signatures.Ed25519=""}},
   {"missing pq",func(e *Envelope){e.Signatures.MLDSA65=""}},
   {"short pq",func(e *Envelope){e.Signatures.MLDSA65=base64.StdEncoding.EncodeToString([]byte{1})}},
   {"no canonical Base64",func(e *Envelope){e.PayloadB64="Zh=="}},
   {"suite downgrade",func(e *Envelope){e.Suite="Ed25519"}},
   {"protocol downgrade",func(e *Envelope){e.Protocol="XMESH1"}},
   {"wrong direction",func(e *Envelope){e.Direction=3}},
   {"wrong path",func(e *Envelope){e.Path+="/../heartbeat"}},
   {"wrong HTTP method",func(e *Envelope){e.Method="GET"}},
   {"unknown message",func(e *Envelope){e.MessageType="node.execute"}},
   {"zero epoch",func(e *Envelope){e.KeyEpoch=0}},
   {"expired",func(e *Envelope){e.ExpiresAtMS=e.IssuedAtMS-1}},
   {"long lifetime",func(e *Envelope){e.ExpiresAtMS=e.IssuedAtMS+300001}},
   {"short nonce",func(e *Envelope){e.NonceHex="00"}},
   {"uppercase nonce",func(e *Envelope){e.NonceHex=strings.ToUpper(e.NonceHex)}},
   {"whitespace issuer",func(e *Envelope){e.IssuerID="node 42"}},
   {"bad revision",func(e *Envelope){e.Revision=strings.Repeat("a",129)}},
  }
  for _,tc:=range variants{
   copyDoc:=doc;tc.modify(&copyDoc)
   if _,e:=DecodeUntrustedEnvelope(pack(copyDoc));e==nil{t.Errorf("accepted %s",tc.name)}
  }
  // Changing a valid payload changes the actual signing input; the
  // parser alone must NOT report the changed message authenticated.
  changed:=doc;changed.PayloadB64=base64.StdEncoding.EncodeToString([]byte(v.Payload+"!"))
  next,e:=DecodeUntrustedEnvelope(pack(changed))
  if e!=nil||bytes.Equal(next.SigningInput,parsed.SigningInput){t.Fatal("payload digest not bound")}
 })}
}
