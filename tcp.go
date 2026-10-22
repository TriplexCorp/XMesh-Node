package main

import (
 "encoding/binary"
 "errors"
 "io"
 "net"
 "time"
)

// peekHello reads up to 64 KiB of plaintext TLS records to extract SNI/ALPN.
// It returns every consumed byte so a passthrough backend receives the
// unmodified handshake. Unknown / non-TLS streams use the default route.
func peekHello(conn net.Conn)([]byte,string,[]string,error){
 var raw,handshake []byte
 for len(raw)<65536 {
  var header [5]byte
  if _,e:=io.ReadFull(conn,header[:]);e!=nil{return raw,"",nil,e}
  raw=append(raw,header[:]...)
  size:=int(binary.BigEndian.Uint16(header[3:5]))
  if header[0]!=22||header[1]!=3||header[2]>4||size<1||size>18432{return raw,"",nil,nil}
  if len(raw)+size>65536{return raw,"",nil,errors.New("ClientHello too large")}
  chunk:=make([]byte,size)
  if _,e:=io.ReadFull(conn,chunk);e!=nil{return raw,"",nil,e}
  raw=append(raw,chunk...)
  handshake=append(handshake,chunk...)
  if len(handshake)<4{continue}
  if handshake[0]!=1{return raw,"",nil,nil}
  total:=int(handshake[1])<<16|int(handshake[2])<<8|int(handshake[3])
  if total>60000{return raw,"",nil,errors.New("ClientHello exceeds limit")}
  if len(handshake)<4+total{continue}
  host,protocols:=parseHello(handshake[4:4+total])
  return raw,host,protocols,nil
 }
 return raw,"",nil,errors.New("ClientHello exceeds limit")
}
func parseHello(b []byte)(string,[]string){
 // version(2), random(32), session-id, cipher suites, compression, extensions
 if len(b)<35{return "",nil}
 p:=34
 take:=func(n int)([]byte,bool){if n<0||p+n>len(b){return nil,false};v:=b[p:p+n];p+=n;return v,true}
 sid,ok:=take(1);if !ok{return "",nil};if _,ok=take(int(sid[0]));!ok{return "",nil}
 cs,ok:=take(2);if !ok{return "",nil};if _,ok=take(int(binary.BigEndian.Uint16(cs)));!ok{return "",nil}
 cm,ok:=take(1);if !ok{return "",nil};if _,ok=take(int(cm[0]));!ok{return "",nil}
 extlen,ok:=take(2);if !ok{return "",nil}
 end:=p+int(binary.BigEndian.Uint16(extlen));if end>len(b){return "",nil}
 var host string;var alpns []string
 for p+4<=end {
  typ:=binary.BigEndian.Uint16(b[p:p+2]);size:=int(binary.BigEndian.Uint16(b[p+2:p+4]));p+=4
  if p+size>end{return "",nil}
  ext:=b[p:p+size];p+=size
  if len(ext)<2{continue}
  count:=int(binary.BigEndian.Uint16(ext[:2]));if count>len(ext)-2{continue}
  val:=ext[2:2+count]
  switch typ {
  case 0:
   for len(val)>=3{kind:=val[0];n:=int(binary.BigEndian.Uint16(val[1:3]));val=val[3:];if n>len(val){break};if kind==0&&n>0&&n<=253{host=string(val[:n]);break};val=val[n:]}
  case 16:
   for len(val)>0{n:=int(val[0]);val=val[1:];if n==0||n>len(val){break};alpns=append(alpns,string(val[:n]));val=val[n:]}
  }
 }
 return host,alpns
}
func pipeTCP(a,b net.Conn,timeout time.Duration){
 done:=make(chan struct{},2)
 pump:=func(dst,src net.Conn){buf:=make([]byte,32*1024);for {src.SetReadDeadline(time.Now().Add(timeout));n,e:=src.Read(buf);if n>0{dst.SetWriteDeadline(time.Now().Add(timeout));if _,we:=dst.Write(buf[:n]);we!=nil{break}};if e!=nil{break}};if x,ok:=dst.(*net.TCPConn);ok{x.CloseWrite()};done<-struct{}{}}
 go pump(a,b);go pump(b,a);<-done;a.Close();b.Close();<-done
}
