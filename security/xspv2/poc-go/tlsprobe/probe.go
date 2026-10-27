// Package tlsprobe provides a NON-PRODUCTION XSP-v2 strict hybrid TLS handshake probe.
// The production Go 1.23 Node is NOT linked against this Go 1.27 module.
package tlsprobe

import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "errors"
 "fmt"
 "net"
 "strings"
 "time"
)

// Report confirms only THIS Node-to-TLS-terminator handshake, not any
// terminator-to-origin hop, XSP signatures, key pinning or deployment status.
type Report struct {
 TLSVersion string `json:"tlsVersion"`
 NegotiatedGroup string `json:"negotiatedGroup"`
 CertificateVerified bool `json:"certificateVerified"`
 FullHandshake bool `json:"fullHandshake"`
}

// VerifyNegotiated applies a strict, fail-closed policy to the observed state.
// Do not use a status flag or configured groups as a substitute for CurveID.
func VerifyNegotiated(state tls.ConnectionState) error {
 if !state.HandshakeComplete {return errors.New("TLS handshake incomplete")}
 if state.Version!=tls.VersionTLS13 {return fmt.Errorf("TLS downgrade: version 0x%x",state.Version)}
 if state.DidResume {return errors.New("resumed handshake cannot prove a fresh hybrid key exchange")}
 if state.CurveID!=tls.X25519MLKEM768 {return fmt.Errorf("TLS downgrade: negotiated group %s (want X25519MLKEM768)",state.CurveID)}
 if len(state.PeerCertificates)==0||len(state.VerifiedChains)==0 {
  return errors.New("missing verified peer certificate chain")
 }
 return nil
}

// Probe establishes a fresh, authenticated TLS 1.3 handshake and never sends
// HTTP data. roots=nil uses system trust. An additional CA bundle, if supplied,
// must be explicitly trusted by the operator. InsecureSkipVerify is NEVER set.
// No session cache or TLS resumption is used.
func Probe(ctx context.Context, address, serverName string, roots *x509.CertPool) (Report,error) {
 if strings.TrimSpace(serverName)==""||strings.TrimSpace(address)=="" {return Report{},errors.New("address and serverName are required")}
 host,port,err:=net.SplitHostPort(address)
 if err!=nil||host==""||port=="" {return Report{},errors.New("address must be host:port")}
 config:=&tls.Config{
  MinVersion:tls.VersionTLS13,
  MaxVersion:tls.VersionTLS13,
  CurvePreferences:[]tls.CurveID{tls.X25519MLKEM768},
  ServerName:serverName,RootCAs:roots,
  ClientSessionCache:nil,
 }
 dialer:=tls.Dialer{NetDialer:&net.Dialer{Timeout:8*time.Second},Config:config}
 raw,err:=dialer.DialContext(ctx,"tcp",address)
 if err!=nil {return Report{},fmt.Errorf("authenticated hybrid handshake failed: %w",err)}
 defer raw.Close()
 conn,ok:=raw.(*tls.Conn)
 if !ok{return Report{},errors.New("TLS connection state unavailable")}
 state:=conn.ConnectionState()
 if err:=VerifyNegotiated(state);err!=nil{return Report{},err}
 return Report{TLSVersion:"TLS1.3",NegotiatedGroup:state.CurveID.String(),CertificateVerified:true,FullHandshake:true},nil
}
