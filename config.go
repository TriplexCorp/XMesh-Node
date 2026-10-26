package main

import (
 "encoding/json"
 "errors"
 "fmt"
 "net"
 "os"
 "strings"
)

type Route struct {
 SNI string `json:"sni"`
 ALPN []string `json:"alpn,omitempty"`
 Backend string `json:"backend"`
}
type Config struct {
 PanelURL string `json:"panel_url,omitempty"`
 NodeID int64 `json:"node_id,omitempty"`
 PrivateKeyFile string `json:"private_key_file,omitempty"`
 ListenTCP string `json:"listen_tcp"`
 ListenUDP string `json:"listen_udp"`
 DefaultTCP string `json:"default_tcp"`
 Routes []Route `json:"routes"`
 UDPBackend string `json:"udp_backend"`
 HelloTimeoutSeconds int `json:"hello_timeout_seconds"`
 IdleTimeoutSeconds int `json:"idle_timeout_seconds"`
 MaxTCPConnections int `json:"max_tcp_connections"`
 MaxUDPSessions int `json:"max_udp_sessions"`
}
func loadConfig(path string)(Config,error){
 var c Config
 f,e:=os.Open(path);if e!=nil{return c,e};defer f.Close()
 dec:=json.NewDecoder(f);dec.DisallowUnknownFields()
 if e=dec.Decode(&c);e!=nil{return c,e}
 if dec.Decode(new(any))==nil{return c,errors.New("multiple JSON values")}
 if c.PanelURL!="" { if !strings.HasPrefix(c.PanelURL,"https://") || c.NodeID<=0 || c.PrivateKeyFile=="" {return c,errors.New("panel_url requires HTTPS, node_id and private_key_file")} }
 if c.ListenTCP==""{c.ListenTCP=":443"}
 if c.HelloTimeoutSeconds==0{c.HelloTimeoutSeconds=5}
 if c.IdleTimeoutSeconds==0{c.IdleTimeoutSeconds=120}
 if c.MaxTCPConnections==0{c.MaxTCPConnections=4096}
 if c.MaxUDPSessions==0{c.MaxUDPSessions=2048}
 if c.HelloTimeoutSeconds<1||c.HelloTimeoutSeconds>30||c.IdleTimeoutSeconds<10||c.IdleTimeoutSeconds>3600||c.MaxTCPConnections<1||c.MaxTCPConnections>100000||c.MaxUDPSessions<1||c.MaxUDPSessions>100000{return c,errors.New("invalid limits or timeouts")}
 if c.DefaultTCP==""{return c,errors.New("default_tcp is required")}
 // A loopback backend on the same port as our listener creates an infinite relay loop.
 _,listenPort,listenErr:=net.SplitHostPort(c.ListenTCP)
 _,backendPort,backendErr:=net.SplitHostPort(c.DefaultTCP)
 if listenErr==nil&&backendErr==nil&&listenPort==backendPort{
  return c,errors.New("default_tcp must not point back to XMesh Node listening port")
 }
 for _,x:=range append([]Route{{Backend:c.DefaultTCP}},c.Routes...){
  if e:=checkBackend(x.Backend);e!=nil{return c,e}
  // Every TCP route (not just default_tcp) must avoid the local listener.
  // TCP and UDP may share the *number* 443; check each protocol separately.
  if listenErr==nil {
   _,routePort,routeErr:=net.SplitHostPort(x.Backend)
   if routeErr==nil&&routePort==listenPort{
    return c,fmt.Errorf("TCP backend %q loops back to XMesh Node listener",x.Backend)
   }
  }
  if x.SNI!=""{s:=strings.ToLower(x.SNI);if strings.ContainsAny(s," /:\\")||strings.Count(s,"*")>1||(strings.Contains(s,"*")&&!strings.HasPrefix(s,"*.")){return c,fmt.Errorf("invalid SNI rule %q",x.SNI)}}
 }
 if c.ListenUDP!=""{
  if c.UDPBackend==""{return c,errors.New("udp_backend required when listen_udp is enabled")}
  if e:=checkBackend(c.UDPBackend);e!=nil{return c,e}
  _,udpListenPort,udpListenErr:=net.SplitHostPort(c.ListenUDP)
  _,udpBackendPort,udpBackendErr:=net.SplitHostPort(c.UDPBackend)
  if udpListenErr!=nil{return c,fmt.Errorf("invalid UDP listener: %w",udpListenErr)}
  if udpBackendErr==nil&&udpListenPort==udpBackendPort{
   return c,errors.New("udp_backend must not point back to XMesh Node UDP listening port")
  }
 }
 return c,nil
}
func checkBackend(address string)error{
 host,port,e:=net.SplitHostPort(address);if e!=nil{return fmt.Errorf("invalid backend %q: %w",address,e)}
 ip:=net.ParseIP(host);if ip==nil||!ip.IsLoopback(){return fmt.Errorf("backend %q must use loopback IP",address)}
 if port==""||port=="0"{return fmt.Errorf("invalid backend port for %q",address)}
 return nil
}
func (c Config) destination(sni string,alpn []string)string{
 sni=strings.ToLower(strings.TrimSuffix(sni,"."))
 for _,r:=range c.Routes{
  rule:=strings.ToLower(strings.TrimSuffix(r.SNI,"."))
  if rule==""{continue}
  matched:=rule==sni
  if strings.HasPrefix(rule,"*."){base:=strings.TrimPrefix(rule,"*");matched=strings.HasSuffix(sni,base)&&len(sni)>len(base)}
  if !matched{continue}
  if len(r.ALPN)>0{found:=false;for _,want:=range r.ALPN{for _,got:=range alpn{if want==got{found=true}}};if !found{continue}}
  return r.Backend
 }
 return c.DefaultTCP
}
