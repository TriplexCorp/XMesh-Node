// Command tlsprobe verifies only the nominated HTTPS TLS termination hop.
// This is a test/diagnostic utility. It does NOT change Node's live TLS policy.
package main

import (
 "context"
 "crypto/x509"
 "encoding/json"
 "flag"
 "fmt"
 "os"
 "time"
 "github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/tlsprobe"
)
func main(){
 address:=flag.String("address","","TLS endpoint host:port (required)")
 hostname:=flag.String("servername","","trusted certificate DNS name / SNI (required)")
 ca:=flag.String("ca-file","","optional PEM CA bundle for lab; empty means system trust")
 timeout:=flag.Duration("timeout",10*time.Second,"connection timeout")
 flag.Parse()
 if *timeout<=0||*timeout>60*time.Second{fmt.Fprintln(os.Stderr,"timeout must be (0,60s]");os.Exit(2)}
 var roots *x509.CertPool
 if *ca!=""{
  pem,err:=os.ReadFile(*ca)
  if err!=nil{fmt.Fprintln(os.Stderr,"cannot read CA bundle");os.Exit(2)}
  roots=x509.NewCertPool()
  if !roots.AppendCertsFromPEM(pem){fmt.Fprintln(os.Stderr,"invalid CA PEM");os.Exit(2)}
 }
 ctx,cancel:=context.WithTimeout(context.Background(),*timeout)
 defer cancel()
 report,err:=tlsprobe.Probe(ctx,*address,*hostname,roots)
 if err!=nil{fmt.Fprintln(os.Stderr,"XSP-v2 TLS probe FAILED:",err);os.Exit(1)}
 if err:=json.NewEncoder(os.Stdout).Encode(report);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
