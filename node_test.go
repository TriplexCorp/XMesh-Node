package main

import (
 "encoding/binary"
 "os"
 "path/filepath"
 "strings"
 "net"
 "testing"
 "time"
)

func TestRouteSelection(t *testing.T){
 c:=Config{DefaultTCP:"127.0.0.1:8443",Routes:[]Route{
 {SNI:"vpn.example.com",Backend:"127.0.0.1:10001"},
 {SNI:"*.example.net",ALPN:[]string{"h2"},Backend:"127.0.0.1:10002"},
 }}
 cases:=[]struct{host string;alpn []string;want string}{
 {"VPN.EXAMPLE.COM",nil,"127.0.0.1:10001"},
 {"a.example.net",[]string{"h2"},"127.0.0.1:10002"},
 {"a.example.net",[]string{"http/1.1"},"127.0.0.1:8443"},
 {"example.net",[]string{"h2"},"127.0.0.1:8443"},
 {"unknown.example",nil,"127.0.0.1:8443"},
 }
 for _,tt:=range cases{if got:=c.destination(tt.host,tt.alpn);got!=tt.want{t.Errorf("%s: got %s want %s",tt.host,got,tt.want)}}
}
func TestLocalBackends(t *testing.T){
 for _,addr:=range []string{"127.0.0.1:443","[::1]:8080"}{if err:=checkBackend(addr);err!=nil{t.Fatal(err)}}
 for _,addr:=range []string{"10.0.0.1:80","example.com:443","0.0.0.0:123"}{if err:=checkBackend(addr);err==nil{t.Fatalf("%s should be refused",addr)}}
}
func TestClientHelloParser(t *testing.T){
 sni:=[]byte("vpn.example.com")
 name:=append([]byte{0},byte(len(sni)>>8),byte(len(sni)),);name=append(name,sni...)
 names:=make([]byte,2);binary.BigEndian.PutUint16(names,uint16(len(name)));names=append(names,name...)
 e1:=[]byte{0,0,byte(len(names)>>8),byte(len(names))};e1=append(e1,names...)
 prot:=[]byte{2,'h','2'}
 protList:=append([]byte{0,byte(len(prot))},prot...)
 e2:=[]byte{0,16,0,byte(len(protList))};e2=append(e2,protList...)
 exts:=append(e1,e2...)
 body:=make([]byte,34);body[0]=3;body[1]=3
 body=append(body,0,0,2,0x13,1,1,0)
 body=append(body,byte(len(exts)>>8),byte(len(exts)));body=append(body,exts...)
 msg:=[]byte{1,byte(len(body)>>16),byte(len(body)>>8),byte(len(body))}
 msg=append(msg,body...)
 record:=[]byte{22,3,3,byte(len(msg)>>8),byte(len(msg))}
 record=append(record,msg...)
 a,b:=net.Pipe();defer a.Close();defer b.Close()
 go func(){b.Write(record)}()
 a.SetReadDeadline(time.Now().Add(time.Second))
 raw,host,alpn,err:=peekHello(a)
 if err!=nil||host!="vpn.example.com"||len(alpn)!=1||alpn[0]!="h2"||string(raw)!=string(record){t.Fatalf("got host=%q alpn=%v err=%v",host,alpn,err)}
}

func TestTransportSpecificSelfLoopRejection(t *testing.T) {
 cases:=[]struct{
  name string
  config string
  problem string
 }{
  {"default tcp loop", `{"listen_tcp":":443","default_tcp":"127.0.0.1:443"}`, "default_tcp"},
  {"SNI TCP loop", `{"listen_tcp":":443","default_tcp":"127.0.0.1:5000","routes":[{"sni":"example.org","backend":"127.0.0.1:443"}]}`, "loops back"},
  {"UDP loop", `{"listen_tcp":":443","default_tcp":"127.0.0.1:5000","listen_udp":":443","udp_backend":"127.0.0.1:443"}`, "udp_backend"},
  {"Dual VLESS/Hysteria", `{"listen_tcp":":443","default_tcp":"127.0.0.1:5000","listen_udp":":443","udp_backend":"127.0.0.1:5001"}`, ""},
  {"Shared private port across TCP and UDP", `{"listen_tcp":":443","default_tcp":"127.0.0.1:5000","listen_udp":":443","udp_backend":"127.0.0.1:5000"}`, ""},
  {"UDP backend alone may use TCP public port", `{"listen_tcp":":443","default_tcp":"127.0.0.1:5000","listen_udp":":8443","udp_backend":"127.0.0.1:443"}`, ""},
 }
 for _,tt:=range cases {
  t.Run(tt.name,func(t *testing.T){
   path:=filepath.Join(t.TempDir(),"router.json")
   if err:=os.WriteFile(path,[]byte(tt.config),0600);err!=nil{t.Fatal(err)}
   _,err:=loadConfig(path)
   if tt.problem==""{
    if err!=nil{t.Fatalf("valid transport-specific mapping was rejected: %v",err)}
   }else if err==nil || !strings.Contains(err.Error(),tt.problem){
    t.Fatalf("want error containing %q, got %v",tt.problem,err)
   }
  })
 }
}
