// Package envelope implements a STRICT, test-only XSP-v2 candidate decoder.
// DecodeUntrustedEnvelope only parses bytes. It does NOT authenticate a peer,
// verify Ed25519/ML-DSA, persist nonces, or activate production v2 endpoints.
package envelope

import (
 "bytes"
 "crypto/sha256"
 "encoding/base64"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "strings"
)

const (
 MaxEnvelopeBytes = 1024 * 1024
 MaxPayloadBytes = 512 * 1024
)

type Signatures struct {
 Ed25519 string `json:"ed25519"`
 MLDSA65 string `json:"mldsa65"`
}

type Envelope struct {
 Protocol string `json:"protocol"`
 Suite string `json:"suite"`
 Direction uint8 `json:"direction"`
 MessageType string `json:"messageType"`
 IssuerID string `json:"issuerId"`
 NodeID int64 `json:"nodeId"`
 Method string `json:"method"`
 Path string `json:"path"`
 Ed25519KeyID string `json:"ed25519KeyId"`
 MLDSA65KeyID string `json:"mldsa65KeyId"`
 KeyEpoch int64 `json:"keyEpoch"`
 IssuedAtMS int64 `json:"issuedAtMs"`
 ExpiresAtMS int64 `json:"expiresAtMs"`
 NonceHex string `json:"nonceHex"`
 RequestID string `json:"requestId"`
 Revision string `json:"revision"`
 PayloadB64 string `json:"payloadB64"`
 Signatures Signatures `json:"signatures"`
}

// Untrusted is deliberately NOT a verified/authenticated security principal.
type Untrusted struct {
 Metadata Envelope
 Payload []byte
 SigningInput []byte
 Ed25519Signature []byte
 MLDSA65Signature []byte
}

var endpointRegistry = map[string]struct {
 direction uint8
 path string
}{
 "node.heartbeat": {1, "/api/v2/node/heartbeat"},
 "node.desired-config.response": {2, "/api/v2/node/desired-config"},
}

// checkUniqueJSONKeys checks ALL nested maps (including signatures and payload)
// and fails on duplicate JSON keys, excessive nesting or unknown tokens.
func checkUniqueJSONKeys(raw []byte) error {
 dec := json.NewDecoder(bytes.NewReader(raw))
 dec.UseNumber()
 nodes := 0
 var walk func(int) error
 walk = func(depth int) error {
  nodes++
  if nodes > 256 || depth > 12 {return errors.New("JSON complexity limit")}
  token,err:=dec.Token()
  if err!=nil{return err}
  delimiter,ok:=token.(json.Delim)
  if !ok{return nil}
  switch delimiter {
  case '{':
   found:=make(map[string]bool)
   for dec.More(){
    keyToken,e:=dec.Token();if e!=nil{return e}
    key,ok:=keyToken.(string);if !ok{return errors.New("object field name not string")}
    if found[key]{return errors.New("duplicate JSON key")}
    found[key]=true
    if e:=walk(depth+1);e!=nil{return e}
   }
   end,e:=dec.Token();if e!=nil{return e}
   if end!=json.Delim('}') {return errors.New("unbalanced object")}
  case '[':
   for dec.More(){if e:=walk(depth+1);e!=nil{return e}}
   end,e:=dec.Token();if e!=nil{return e}
   if end!=json.Delim(']'){return errors.New("unbalanced array")}
  default:return errors.New("unexpected JSON delimiter")
  }
  return nil
 }
 if err:=walk(0);err!=nil{return err}
 if _,err:=dec.Token();err!=io.EOF {
  return errors.New("trailing JSON data")
 }
 return nil
}

func strictBase64(encoded string,size int,allowEmpty bool)([]byte,error){
 if !allowEmpty && encoded=="" {return nil,errors.New("missing signature or payload")}
 if len(encoded)>((size+2)/3)*4 {return nil,errors.New("base64 field too large")}
 value,e:=base64.StdEncoding.Strict().DecodeString(encoded)
 if e!=nil || len(value)>size || base64.StdEncoding.EncodeToString(value)!=encoded {
  return nil,errors.New("noncanonical Base64 or bad length")
 }
 if !allowEmpty && len(value)!=size {return nil,errors.New("invalid signature size")}
 return value,nil
}

func ascii(out *bytes.Buffer,value string,max int,optional bool)error{
 if len(value)>max || (!optional&&len(value)==0) {return errors.New("metadata length")}
 for i:=0;i<len(value);i++{if value[i]<0x21||value[i]>0x7e{return errors.New("non-ASCII metadata")}}
 var tmp [4]byte
 binary.BigEndian.PutUint32(tmp[:],uint32(len(value)))
 out.Write(tmp[:]);out.WriteString(value)
 return nil
}
func u64(out *bytes.Buffer,n uint64) {var buf [8]byte;binary.BigEndian.PutUint64(buf[:],n);out.Write(buf[:])}

// DecodeUntrustedEnvelope strictly validates byte layout but does NOT verify
// identities, actual HTTP binding, fresh clock time, durable replay, or signatures.
func DecodeUntrustedEnvelope(raw []byte) (Untrusted,error) {
 var zero Untrusted
 if len(raw)==0||len(raw)>MaxEnvelopeBytes {return zero,errors.New("XSP-v2 envelope size")}
 if e:=checkUniqueJSONKeys(raw);e!=nil{return zero,fmt.Errorf("unsafe JSON: %w",e)}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var env Envelope
 if e:=dec.Decode(&env);e!=nil{return zero,fmt.Errorf("envelope fields: %w",e)}
 if e:=dec.Decode(new(any));e!=io.EOF{return zero,errors.New("trailing JSON data")}
 if env.Protocol!="XSP/2"||env.Suite!="Ed25519+ML-DSA-65" {return zero,errors.New("unrecognized protocol or signature suite")}
 registered,ok:=endpointRegistry[env.MessageType]
 if !ok||env.Direction!=registered.direction||env.Method!="POST"||env.Path!=registered.path{
  return zero,errors.New("unregistered type/direction/method/endpoint")
 }
 if env.NodeID<=0||env.KeyEpoch<=0||env.IssuedAtMS<=0||env.ExpiresAtMS<=env.IssuedAtMS||
   env.ExpiresAtMS-env.IssuedAtMS>300000||env.ExpiresAtMS-env.IssuedAtMS<0{
  return zero,errors.New("invalid node/epoch/time window")
 }
 if strings.ToLower(env.NonceHex)!=env.NonceHex||len(env.NonceHex)!=32{return zero,errors.New("invalid lowercase nonce")}
 nonce,e:=hex.DecodeString(env.NonceHex);if e!=nil||len(nonce)!=16{return zero,errors.New("invalid nonce")}
 // This parser is for the two documented candidate message kinds only.
 if env.MessageType=="node.desired-config.response"&&env.Revision==""{
  return zero,errors.New("desired-config response missing revision")
 }
 payload,e:=strictBase64(env.PayloadB64,MaxPayloadBytes,true);if e!=nil{return zero,e}
 ed,e:=strictBase64(env.Signatures.Ed25519,64,false);if e!=nil{return zero,e}
 pq,e:=strictBase64(env.Signatures.MLDSA65,3309,false);if e!=nil{return zero,e}
 out:=bytes.NewBuffer(make([]byte,0,256+len(payload)/16))
 out.WriteString("XSP2-SIGNED-MESSAGE");out.WriteByte(0)
 out.Write([]byte{2,1,env.Direction})
 for _,f:=range []struct{v string;max int;optional bool}{
  {env.MessageType,64,false},{env.IssuerID,64,false},
 }{if e:=ascii(out,f.v,f.max,f.optional);e!=nil{return zero,e}}
 u64(out,uint64(env.NodeID))
 for _,f:=range []struct{v string;max int;optional bool}{
  {env.Method,8,false},{env.Path,256,false},{env.Ed25519KeyID,64,false},{env.MLDSA65KeyID,64,false},
 }{if e:=ascii(out,f.v,f.max,f.optional);e!=nil{return zero,e}}
 u64(out,uint64(env.KeyEpoch));u64(out,uint64(env.IssuedAtMS));u64(out,uint64(env.ExpiresAtMS))
 out.Write(nonce)
 if e:=ascii(out,env.RequestID,64,false);e!=nil{return zero,e}
 if e:=ascii(out,env.Revision,128,true);e!=nil{return zero,e}
 h:=sha256.Sum256(payload);out.Write(h[:])
 return Untrusted{Metadata:env,Payload:payload,SigningInput:out.Bytes(),Ed25519Signature:ed,MLDSA65Signature:pq},nil
}
