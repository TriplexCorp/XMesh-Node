package main

import (
 "context"
 "log"
 "net"
 "sync"
 "time"
)

type udpSession struct{conn *net.UDPConn;last time.Time}
func serveUDP(ctx context.Context,c Config)error{
 listen,e:=net.ListenPacket("udp",c.ListenUDP);if e!=nil{return e};defer listen.Close()
 remote,e:=net.ResolveUDPAddr("udp",c.UDPBackend);if e!=nil{return e}
 var mu sync.Mutex
 sessions:=map[string]*udpSession{}
 timeout:=time.Duration(c.IdleTimeoutSeconds)*time.Second
 go func(){<-ctx.Done();listen.Close();mu.Lock();for _,s:=range sessions{s.conn.Close()};mu.Unlock()}()
 go func(){ticker:=time.NewTicker(30*time.Second);defer ticker.Stop();for{select{case <-ctx.Done():return;case <-ticker.C:
  mu.Lock();for k,s:=range sessions{if time.Since(s.last)>timeout{s.conn.Close();delete(sessions,k)}};mu.Unlock()
 }}()
 buf:=make([]byte,65535)
 log.Printf("UDP %s forwarding to %s",c.ListenUDP,c.UDPBackend)
 for{
  n,client,e:=listen.ReadFrom(buf);if e!=nil{if ctx.Err()!=nil{return nil};return e}
  key:=client.String()
  mu.Lock()
  session:=sessions[key]
  if session==nil&&len(sessions)<c.MaxUDPSessions{
   uc,err:=net.DialUDP("udp",nil,remote)
   if err==nil{
    session=&udpSession{conn:uc,last:time.Now()}
    sessions[key]=session
    upstream:=uc
    go func(client net.Addr,key string){
     resp:=make([]byte,65535)
     for{
      upstream.SetReadDeadline(time.Now().Add(timeout))
      m,err:=upstream.Read(resp);if err!=nil{break}
      listen.WriteTo(resp[:m],client)
     }
     mu.Lock();if s:=sessions[key];s!=nil&&s.conn==upstream{delete(sessions,key)};mu.Unlock();upstream.Close()
    }(client,key)
   }
  }
  if session!=nil{session.last=time.Now();session.conn.SetWriteDeadline(time.Now().Add(5*time.Second));session.conn.Write(buf[:n])}
  mu.Unlock()
 }
}
