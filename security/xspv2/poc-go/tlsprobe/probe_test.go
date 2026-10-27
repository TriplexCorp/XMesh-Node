package tlsprobe

import (
 "context"
 "crypto/ecdsa"
 "crypto/elliptic"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "math/big"
 "net"
 "testing"
 "time"
)

func testCertificate(t *testing.T, dnsName string) (tls.Certificate,*x509.CertPool){
 t.Helper()
 key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
 if err!=nil{t.Fatal(err)}
 now:=time.Now()
 template:=&x509.Certificate{
  SerialNumber:big.NewInt(98765),
  Subject:pkix.Name{CommonName:dnsName},
  NotBefore:now.Add(-time.Minute),
  NotAfter:now.Add(time.Hour),
  DNSNames:[]string{dnsName},
  KeyUsage:x509.KeyUsageDigitalSignature,
  ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
  BasicConstraintsValid:true,
 }
 der,err:=x509.CreateCertificate(rand.Reader,template,template,key.Public(),key)
 if err!=nil{t.Fatal(err)}
 cert,err:=x509.ParseCertificate(der)
 if err!=nil{t.Fatal(err)}
 roots:=x509.NewCertPool()
 roots.AddCert(cert)
 return tls.Certificate{Certificate:[][]byte{der},PrivateKey:key,Leaf:cert},roots
}

func launchServer(t *testing.T,certificate tls.Certificate,version uint16,curves []tls.CurveID)string{
 t.Helper()
 raw,err:=net.Listen("tcp","127.0.0.1:0")
 if err!=nil{t.Fatal(err)}
 listener:=tls.NewListener(raw,&tls.Config{
  Certificates:[]tls.Certificate{certificate},
  MinVersion:version,MaxVersion:version,CurvePreferences:curves,
  SessionTicketsDisabled:true,
 })
 done:=make(chan struct{})
 t.Cleanup(func(){listener.Close();<-done})
 go func(){
  defer close(done)
  for{
   conn,err:=listener.Accept()
   if err!=nil{return}
   go func(){
    defer conn.Close()
    _=conn.SetDeadline(time.Now().Add(4*time.Second))
    _=conn.(*tls.Conn).Handshake()
   }()
  }
 }()
 return listener.Addr().String()
}

func TestStrictHybridTLSAndDowngradeFailures(t *testing.T){
 cert,roots:=testCertificate(t,"panel.example.test")
 address:=launchServer(t,cert,tls.VersionTLS13,[]tls.CurveID{tls.X25519MLKEM768})
 ctx,cancel:=context.WithTimeout(context.Background(),8*time.Second)
 defer cancel()
 report,err:=Probe(ctx,address,"panel.example.test",roots)
 if err!=nil{t.Fatalf("valid hybrid handshake rejected: %v",err)}
 if report.TLSVersion!="TLS1.3"||report.NegotiatedGroup!="X25519MLKEM768"||
  !report.CertificateVerified||!report.FullHandshake{
  t.Fatalf("invalid hybrid report: %+v",report)
 }
 if _,err:=Probe(ctx,address,"wrong.example.test",roots);err==nil{
  t.Fatal("wrong hostname accepted")
 }
 if _,err:=Probe(ctx,address,"panel.example.test",x509.NewCertPool());err==nil{
  t.Fatal("untrusted certificate accepted")
 }
 classical:=launchServer(t,cert,tls.VersionTLS13,[]tls.CurveID{tls.X25519})
 if _,err:=Probe(ctx,classical,"panel.example.test",roots);err==nil{
  t.Fatal("classical-only TLS 1.3 downgrade accepted")
 }
 legacy:=launchServer(t,cert,tls.VersionTLS12,[]tls.CurveID{tls.X25519})
 if _,err:=Probe(ctx,legacy,"panel.example.test",roots);err==nil{
  t.Fatal("TLS 1.2 downgrade accepted")
 }
 // Demonstrate why merely requiring TLS1.3 is not enough: a permissive
 // client CAN negotiate X25519 with a classical-only TLS1.3 endpoint.
 raw,err:=tls.DialWithDialer(&net.Dialer{Timeout:4*time.Second},"tcp",classical,
  &tls.Config{MinVersion:tls.VersionTLS13,RootCAs:roots,
   ServerName:"panel.example.test",CurvePreferences:[]tls.CurveID{tls.X25519MLKEM768,tls.X25519}})
 if err!=nil{t.Fatal(err)}
 state:=raw.ConnectionState()
 raw.Close()
 if state.Version!=tls.VersionTLS13||state.CurveID!=tls.X25519{
  t.Fatalf("classical downgrade control was not exercised: %v %v",state.Version,state.CurveID)
 }
 if err:=VerifyNegotiated(state);err==nil{t.Fatal("post-handshake curve check failed open")}
}

func TestNoProofFromIncompleteOrResumedSessions(t *testing.T){
 if err:=VerifyNegotiated(tls.ConnectionState{
  HandshakeComplete:false,Version:tls.VersionTLS13,CurveID:tls.X25519MLKEM768,
 });err==nil{t.Fatal("incomplete handshake accepted")}
 if err:=VerifyNegotiated(tls.ConnectionState{
  HandshakeComplete:true,Version:tls.VersionTLS13,CurveID:tls.X25519MLKEM768,
  DidResume:true,
 });err==nil{t.Fatal("resumption accepted as full PQ key agreement")}
 if err:=VerifyNegotiated(tls.ConnectionState{
  HandshakeComplete:true,Version:tls.VersionTLS13,CurveID:tls.X25519MLKEM768,
 });err==nil{t.Fatal("missing certificate verification accepted")}
}

func TestMandatoryPQDialNeverReturnsClassicalConnection(t *testing.T) {
    cert, roots := testCertificate(t, "node-control.example.test")
    ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
    defer cancel()

    secure := launchServer(t, cert, tls.VersionTLS13, []tls.CurveID{tls.X25519MLKEM768})
    conn, err := DialStrict(ctx, secure, "node-control.example.test", roots)
    if err != nil {
        t.Fatalf("mandatory PQ dial rejected valid hybrid connection: %v", err)
    }
    state := conn.ConnectionState()
    if err := conn.Close(); err != nil {
        t.Fatalf("close secure dial: %v", err)
    }
    if state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 ||
        state.DidResume || !state.HandshakeComplete || len(state.VerifiedChains) == 0 {
        t.Fatalf("invalid strict control connection: version=%x group=%s resumed=%v",
            state.Version, state.CurveID, state.DidResume)
    }

    // Each of these servers might offer valid HTTPS, but MUST NOT produce
    // a usable XSP/2 control connection. No flags or user-selected fallback.
    insecureCases := []struct {
        name string
        address string
        serverName string
        roots *x509.CertPool
    }{
        {
            name: "valid-cert-classical-only",
            address: launchServer(t, cert, tls.VersionTLS13, []tls.CurveID{tls.X25519}),
            serverName: "node-control.example.test",
            roots: roots,
        },
        {
            name: "valid-cert-tls12-only",
            address: launchServer(t, cert, tls.VersionTLS12, []tls.CurveID{tls.X25519}),
            serverName: "node-control.example.test",
            roots: roots,
        },
        {
            name: "wrong-server-identity",
            address: secure,
            serverName: "attacker.example.test",
            roots: roots,
        },
        {
            name: "untrusted-certificate",
            address: secure,
            serverName: "node-control.example.test",
            roots: x509.NewCertPool(),
        },
        {
            name: "missing-name",
            address: secure,
            serverName: "",
            roots: roots,
        },
    }
    for _, tc := range insecureCases {
        t.Run(tc.name, func(t *testing.T) {
            rejected, err := DialStrict(ctx, tc.address, tc.serverName, tc.roots)
            if rejected != nil {
                rejected.Close()
                t.Fatal("fail-open: returned a usable connection without mandatory PQ trust")
            }
            if err == nil {
                t.Fatal("fail-open: missing mandatory PQ rejection")
            }
        })
    }
}
