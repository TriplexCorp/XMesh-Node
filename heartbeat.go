package main

import (
 "bytes"
 "context"
 "crypto"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "crypto/x509"
 "encoding/hex"
 "encoding/json"
 "encoding/pem"
 "fmt"
 "io"
 "log"
 "net/http"
 "os"
 "strings"
 "time"
)

func heartbeatKey(path string) (ed25519.PrivateKey,error) {
 b,err:=os.ReadFile(path);if err!=nil{return nil,err}
 block,_:=pem.Decode(b);if block==nil{return nil,fmt.Errorf("private key is not PEM")}
 key,err:=x509.ParsePKCS8PrivateKey(block.Bytes);if err!=nil{return nil,err}
 private,ok:=key.(ed25519.PrivateKey);if !ok{return nil,fmt.Errorf("expected Ed25519 private key")}
 return private,nil
}

func heartbeatLoop(ctx context.Context, c Config) {
 key,err:=heartbeatKey(c.PrivateKeyFile)
 if err!=nil {log.Printf("Node heartbeat disabled: %v",err);return}
 client:=&http.Client{Timeout:12*time.Second}
 send:=func(){
  body,err:=json.Marshal(struct{
   NodeID int64 `json:"node_id"`
   Version string `json:"version"`
   RouterRunning bool `json:"router_running"`
   XrayRunning bool `json:"xray_running"`
  }{NodeID:c.NodeID,Version:"0.1.0",RouterRunning:true,XrayRunning:false})
  if err!=nil{return}
  timestamp:=time.Now().Unix()
  nonce:=make([]byte,16)
  if _,err=rand.Read(nonce);err!=nil{log.Printf("nonce: %v",err);return}
  nonceText:=hex.EncodeToString(nonce)
  digest:=sha256.Sum256(body)
  canonical:=fmt.Sprintf("XMESH1\nPOST\n/api/v1/node/heartbeat\n%d\n%d\n%s\n%s\n",c.NodeID,timestamp,nonceText,hex.EncodeToString(digest[:]))
  signature:=ed25519.Sign(key,[]byte(canonical))
  url:=strings.TrimRight(c.PanelURL,"/")+"/api/v1/node/heartbeat"
  request,err:=http.NewRequestWithContext(ctx,http.MethodPost,url,bytes.NewReader(body))
  if err!=nil{log.Printf("heartbeat request: %v",err);return}
  request.Header.Set("Content-Type","application/json")
  request.Header.Set("X-XMesh-Timestamp",fmt.Sprint(timestamp))
  request.Header.Set("X-XMesh-Nonce",nonceText)
  request.Header.Set("X-XMesh-Signature",hex.EncodeToString(signature))
  response,err:=client.Do(request)
  if err!=nil{if ctx.Err()==nil{log.Printf("heartbeat: %v",err)};return}
  io.Copy(io.Discard,io.LimitReader(response.Body,4096));response.Body.Close()
  if response.StatusCode!=http.StatusOK{log.Printf("heartbeat rejected: HTTP %d",response.StatusCode)}
 }
 send()
 ticker:=time.NewTicker(60*time.Second);defer ticker.Stop()
 for{select{case <-ctx.Done():return;case <-ticker.C:send()}}
}

var _ crypto.Signer = ed25519.PrivateKey{}
