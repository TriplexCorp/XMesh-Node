package main

import (
 "flag"
 "log"
 "net"
 "os"
 "os/signal"
 "syscall"
 "context"
 "time"
)

func main(){
 file:=flag.String("config","config.json","JSON configuration")
 check:=flag.Bool("check",false,"validate config and exit")
 flag.Parse()
 c,e:=loadConfig(*file);if e!=nil{log.Fatalf("configuration: %v",e)}
 if *check{log.Println("configuration OK");return}
 listener,e:=net.Listen("tcp",c.ListenTCP);if e!=nil{log.Fatalf("tcp listener: %v",e)}
 defer listener.Close()
 ctx,cancel:=signal.NotifyContext(context.Background(),syscall.SIGTERM,syscall.SIGINT);defer cancel()
 if c.ListenUDP!=""{go func(){if e:=serveUDP(ctx,c);e!=nil&&ctx.Err()==nil{log.Printf("UDP listener failed: %v",e);cancel()}}()}
 go func(){<-ctx.Done();listener.Close()}()
 log.Printf("XMesh Node listening TCP %s / UDP %s",c.ListenTCP,c.ListenUDP)
 permits:=make(chan struct{},c.MaxTCPConnections)
 for{
  nc,e:=listener.Accept();if e!=nil{if ctx.Err()!=nil{return};log.Printf("accept: %v",e);continue}
  select{case permits<-struct{}{}:go func(){defer func(){<-permits}();handleTCP(nc,c)}()
  default:nc.Close()}
 }
}
func handleTCP(client net.Conn,c Config){
 defer client.Close()
 client.SetReadDeadline(time.Now().Add(time.Duration(c.HelloTimeoutSeconds)*time.Second))
 raw,sni,alpn,e:=peekHello(client);if e!=nil{return}
 client.SetReadDeadline(time.Time{})
 target:=c.destination(sni,alpn)
 upstream,e:=net.DialTimeout("tcp",target,5*time.Second);if e!=nil{log.Printf("backend unavailable %s: %v",target,e);return}
 defer upstream.Close()
 upstream.SetWriteDeadline(time.Now().Add(5*time.Second))
 if len(raw)>0{if _,e=upstream.Write(raw);e!=nil{return}}
 upstream.SetWriteDeadline(time.Time{})
 pipeTCP(client,upstream,time.Duration(c.IdleTimeoutSeconds)*time.Second)
}
var _ = os.ErrClosed
