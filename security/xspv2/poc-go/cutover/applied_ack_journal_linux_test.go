//go:build linux

package cutover

import (
 "bytes"
 "os"
 "path/filepath"
 "sync"
 "testing"
)

func ackJournalFixture(t *testing.T)([]byte,VerifiedPermit,PinnedPublic,int64){
 t.Helper()
 f:=load(t)
 ed,pq,pin:=pair(t)
 nextEd,nextPQ,next:=pair(t)
 pin.Purpose="panel_response";pin.IssuerID=f.Permit.IssuerID;pin.NodeID=f.Permit.NodeID
 next.Purpose="node_request";next.IssuerID=f.Ack.IssuerID;next.NodeID=f.Ack.NodeID
 f.Permit.SignerEdKeyID=pin.EdKeyID;f.Permit.SignerPQKeyID=pin.PQKeyID
 f.Permit.ToEdKeyID=next.EdKeyID;f.Permit.ToPQKeyID=next.PQKeyID
 want:=ExpectedPermit{
  NodeID:f.Permit.NodeID,FromEpoch:f.Permit.FromEpoch,ToEpoch:f.Permit.ToEpoch,
  RequestID:f.Permit.RequestID,FromEdKeyID:f.Permit.FromEdKeyID,
  FromPQKeyID:f.Permit.FromPQKeyID,ToEdKeyID:f.Permit.ToEdKeyID,
  ToPQKeyID:f.Permit.ToPQKeyID,CandidateSHA256Hex:f.Permit.CandidateSHA256Hex,
 }
 permitRaw:=mustSign(t,f.Permit,ed,pq)
 verified,e:=VerifyPermit(permitRaw,pin,want,f.Permit.IssuedAtMS+1000)
 if e!=nil{t.Fatal(e)}
 f.Ack.ToEdKeyID=next.EdKeyID;f.Ack.ToPQKeyID=next.PQKeyID
 f.Ack.SignerEdKeyID=next.EdKeyID;f.Ack.SignerPQKeyID=next.PQKeyID
 f.Ack.PermitSHA256Hex=verified.PermitDigest()
 return mustSign(t,f.Ack,nextEd,nextPQ),verified,next,f.Ack.IssuedAtMS+1000
}

func TestAppliedACKJournalIdempotentConcurrentAndTamper(t *testing.T){
 raw,permit,next,now:=ackJournalFixture(t)
 dir:=privateJournalTestDir(t)
 var wg sync.WaitGroup
 errs:=make(chan error,2)
 for i:=0;i<2;i++{
  wg.Add(1)
  go func(){defer wg.Done();_,e:=persistVerifiedAppliedACK(dir,raw,permit,next,now);errs<-e}()
 }
 wg.Wait();close(errs)
 for e:=range errs{if e!=nil{t.Fatalf("same signed ACK retry failed: %v",e)}}
 row,e:=readACKRecord(filepath.Join(dir,ackJournalName));if e!=nil{t.Fatal(e)}
 if !bytes.Equal(row.SignedACK,raw){t.Fatal("signed ACK bytes changed")}
 stat,e:=os.Stat(filepath.Join(dir,ackJournalName));if e!=nil{t.Fatal(e)}
 if stat.Mode().Perm()!=0600{t.Fatal("journal must be private")}
 if _,e=reloadVerifiedAppliedACK(dir,permit,next,now);e!=nil{t.Fatal(e)}
 if _,e=persistVerifiedAppliedACK(dir,append(append([]byte(nil),raw...),[]byte("evil")...),permit,next,now);e==nil{
  t.Fatal("malformed alternate ACK accepted")
 }
 if _,e=reloadVerifiedAppliedACK(dir,permit,next,now+120000);e==nil{t.Fatal("expired ACK accepted")}
 wrong:=next;wrong.Purpose="panel_response"
 if _,e=reloadVerifiedAppliedACK(dir,permit,wrong,now);e==nil{t.Fatal("wrong role accepted")}
 wrong=next;wrong.PQPublic=[]byte{1}
 if _,e=reloadVerifiedAppliedACK(dir,permit,wrong,now);e==nil{t.Fatal("substituted PQ key accepted")}
 path:=filepath.Join(dir,ackJournalName)
 if e=os.WriteFile(path,[]byte("{corrupt"),0600);e!=nil{t.Fatal(e)}
 if _,e=reloadVerifiedAppliedACK(dir,permit,next,now);e==nil{t.Fatal("corrupt journal accepted")}
 if _,e=persistVerifiedAppliedACK(dir,raw,permit,next,now);e==nil{t.Fatal("corrupt journal overwritten")}
}

func TestAppliedACKJournalUnsafePathRejected(t *testing.T){
 raw,permit,next,now:=ackJournalFixture(t)
 dir:=privateJournalTestDir(t)
 path:=filepath.Join(dir,ackJournalName)
 if e:=os.Symlink("/dev/null",path);e!=nil{t.Fatal(e)}
 if _,e:=persistVerifiedAppliedACK(dir,raw,permit,next,now);e==nil{
  t.Fatal("ACK journal symlink was accepted")
 }
}
