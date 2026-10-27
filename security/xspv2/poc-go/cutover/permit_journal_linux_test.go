//go:build linux

package cutover

import (
 "bytes"
 "os"
 "path/filepath"
 "sync"
 "testing"
)

// Go's testing.TempDir can be 0755 depending on the test runtime/umask.
// The journal deliberately requires a 0700 trust directory.
func privateJournalTestDir(t *testing.T) string {
 t.Helper()
 dir:=t.TempDir()
 if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 return dir
}

func makeJournalPermit(t *testing.T) ([]byte,PinnedPublic,ExpectedPermit,int64) {
 t.Helper()
 f:=load(t)
 ed,pq,pin:=pair(t)
 pin.Purpose="panel_response"
 pin.IssuerID=f.Permit.IssuerID
 pin.NodeID=f.Permit.NodeID
 f.Permit.SignerEdKeyID=pin.EdKeyID
 f.Permit.SignerPQKeyID=pin.PQKeyID
 raw:=mustSign(t,f.Permit,ed,pq)
 want:=ExpectedPermit{
  NodeID:f.Permit.NodeID,
  FromEpoch:f.Permit.FromEpoch, ToEpoch:f.Permit.ToEpoch,
  RequestID:f.Permit.RequestID,
  FromEdKeyID:f.Permit.FromEdKeyID, FromPQKeyID:f.Permit.FromPQKeyID,
  ToEdKeyID:f.Permit.ToEdKeyID, ToPQKeyID:f.Permit.ToPQKeyID,
  CandidateSHA256Hex:f.Permit.CandidateSHA256Hex,
 }
 return raw,pin,want,f.Permit.IssuedAtMS+1000
}

func TestJournalWritesExactVerifiedPermitAndReloads(t *testing.T){
 raw,pin,want,now:=makeJournalPermit(t)
 dir:=privateJournalTestDir(t)
 verified,e:=PersistVerifiedPermit(dir,raw,pin,want,now)
 if e!=nil{t.Fatal(e)}
 if verified.PermitDigest()==""{t.Fatal("missing trusted permit digest")}
 record,e:=readPermitFile(filepath.Join(dir,journalName));if e!=nil{t.Fatal(e)}
 if !bytes.Equal(record.SignedPermit,raw) {t.Fatal("journal changed signed envelope")}
 if record.PermitDigest!=verified.PermitDigest(){t.Fatal("canonical digest mismatch")}
 info,e:=os.Stat(filepath.Join(dir,journalName));if e!=nil{t.Fatal(e)}
 if info.Mode().Perm()!=0600{t.Fatal("journal permissions not 0600")}
 if _,e=PersistVerifiedPermit(dir,raw,pin,want,now);e!=nil{t.Fatalf("idempotent retry failed: %v",e)}
 after,e:=ReloadVerifiedPermit(dir,pin,want,now);if e!=nil{t.Fatal(e)}
 if after.PermitDigest()!=verified.PermitDigest(){t.Fatal("different digest after reload")}
 if _,e=ReloadVerifiedPermit(dir,pin,want,now+120000);e==nil{
  t.Fatal("expired persisted permit accepted")
 }
 wrong:=want
 wrong.NodeID++
 if _,e=ReloadVerifiedPermit(dir,pin,wrong,now);e==nil{
  t.Fatal("journal was trusted despite changed approved node")
 }
 if _,e=PersistVerifiedPermit(dir,raw,pin,wrong,now);e==nil{
  t.Fatal("permit accepted with unrelated approval")
 }
}

func TestJournalConflictsAndCorruptionFailClosed(t *testing.T){
 raw,pin,want,now:=makeJournalPermit(t)
 dir:=privateJournalTestDir(t)
 if _,e:=PersistVerifiedPermit(dir,raw,pin,want,now);e!=nil{t.Fatal(e)}
 // Even when signer is valid, changing the request must not replace an
 // already journaled permit. New approval must go through separate workflow.
 signed,e:=Decode(raw);if e!=nil{t.Fatal(e)}
 signed.Message.RequestID="alternative-request"
 // Deliberately reuse the original signature: VerifyPermit must reject first.
 altered,e:=os.ReadFile(filepath.Join(dir,journalName));if e!=nil{t.Fatal(e)}
 if len(altered)==0{t.Fatal("missing persisted bytes")}
 wrong:=want;wrong.RequestID="alternative-request"
 if _,e=PersistVerifiedPermit(dir,raw,pin,wrong,now);e==nil{
  t.Fatal("changed approved request accepted")
 }
 if _,e=PersistVerifiedPermit(dir,append(raw,[]byte("tampered")...),pin,want,now);e==nil{
  t.Fatal("noncanonical envelope accepted")
 }
 path:=filepath.Join(dir,journalName)
 if e=os.WriteFile(path,[]byte("{broken"),0600);e!=nil{t.Fatal(e)}
 if _,e=ReloadVerifiedPermit(dir,pin,want,now);e==nil{t.Fatal("corrupt journal was silently replaced")}
 if _,e=PersistVerifiedPermit(dir,raw,pin,want,now);e==nil{t.Fatal("corrupt journal rewritten")}
 // Reject ambiguous JSON even when one field contains the valid signed blob.
 if e=os.WriteFile(path,[]byte(`{"schema":"xsp2-verified-permit-journal-1","schema":"evil"}`),0600);e!=nil{t.Fatal(e)}
 if _,e=ReloadVerifiedPermit(dir,pin,want,now);e==nil{t.Fatal("duplicate journal fields accepted")}
}

func TestJournalRejectsUnsafeDirectoriesAndSymlinks(t *testing.T){
 raw,pin,want,now:=makeJournalPermit(t)
 base:=t.TempDir()
 loose:=filepath.Join(base,"loose")
 if e:=os.Mkdir(loose,0755);e!=nil{t.Fatal(e)}
 if _,e:=PersistVerifiedPermit(loose,raw,pin,want,now);e==nil{t.Fatal("world-readable dir accepted")}
 private:=filepath.Join(base,"private")
 if e:=os.Mkdir(private,0700);e!=nil{t.Fatal(e)}
 if e:=os.Symlink(loose,filepath.Join(private,journalName));e!=nil{t.Fatal(e)}
 if _,e:=PersistVerifiedPermit(private,raw,pin,want,now);e==nil{t.Fatal("preexisting symlink accepted")}
 if e:=os.Remove(filepath.Join(private,journalName));e!=nil{t.Fatal(e)}
 // The previous denied attempt may have created its (safe) lockfile.
 if e:=os.Remove(filepath.Join(private,lockName));e!=nil{t.Fatal(e)}
 if e:=os.Symlink(loose,filepath.Join(private,lockName));e!=nil{t.Fatal(e)}
 if _,e:=PersistVerifiedPermit(private,raw,pin,want,now);e==nil{t.Fatal("lockfile symlink accepted")}
}

func TestJournalSerializesRacingRequests(t *testing.T){
 raw,pin,want,now:=makeJournalPermit(t)
 dir:=privateJournalTestDir(t)
 var wg sync.WaitGroup
 successes:=make(chan error,2)
 for i:=0;i<2;i++{
  wg.Add(1)
  go func(){
   defer wg.Done()
   _,e:=PersistVerifiedPermit(dir,raw,pin,want,now)
   successes<-e
  }()
 }
 wg.Wait();close(successes)
 for e:=range successes{if e!=nil{t.Fatalf("identical concurrent retry must be idempotent: %v",e)}}
}
