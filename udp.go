package main

import (
 "context"
 "log"
 "net"
 "sync"
 "time"
)

type udpSession struct {
 conn *net.UDPConn
 last time.Time
}

func serveUDP(ctx context.Context, c Config) error {
 listen, err := net.ListenPacket("udp", c.ListenUDP)
 if err != nil { return err }
 defer listen.Close()
 remote, err := net.ResolveUDPAddr("udp", c.UDPBackend)
 if err != nil { return err }

 var mu sync.Mutex
 sessions := make(map[string]*udpSession)
 timeout := time.Duration(c.IdleTimeoutSeconds) * time.Second

 go func() {
  <-ctx.Done()
  listen.Close()
  mu.Lock()
  defer mu.Unlock()
  for _, s := range sessions { s.conn.Close() }
 }()
 go func() {
  tick := time.NewTicker(30 * time.Second)
  defer tick.Stop()
  for {
   select {
   case <-ctx.Done():
    return
   case <-tick.C:
    mu.Lock()
    for key, session := range sessions {
     if time.Since(session.last) > timeout {
      session.conn.Close()
      delete(sessions, key)
     }
    }
    mu.Unlock()
   }
  }
 }()

 buf := make([]byte, 65535)
 log.Printf("UDP %s forwarding to %s", c.ListenUDP, c.UDPBackend)
 for {
  n, client, err := listen.ReadFrom(buf)
  if err != nil {
   if ctx.Err() != nil { return nil }
   return err
  }
  key := client.String()
  mu.Lock()
  session := sessions[key]
  if session == nil && len(sessions) < c.MaxUDPSessions {
   socket, dialErr := net.DialUDP("udp", nil, remote)
   if dialErr == nil {
    session = &udpSession{conn:socket, last:time.Now()}
    sessions[key] = session
    go func(src net.Addr, id string, upstream *net.UDPConn) {
     replies := make([]byte, 65535)
     for {
      upstream.SetReadDeadline(time.Now().Add(timeout))
      size, readErr := upstream.Read(replies)
      if readErr != nil { break }
      listen.WriteTo(replies[:size], src)
     }
     mu.Lock()
     if current := sessions[id]; current != nil && current.conn == upstream {
      delete(sessions, id)
     }
     mu.Unlock()
     upstream.Close()
    }(client, key, socket)
   }
  }
  if session != nil {
   session.last = time.Now()
   session.conn.SetWriteDeadline(time.Now().Add(5*time.Second))
   session.conn.Write(buf[:n])
  }
  mu.Unlock()
 }
}
