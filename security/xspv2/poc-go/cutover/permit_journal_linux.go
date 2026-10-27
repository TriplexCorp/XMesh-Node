//go:build linux

package cutover

// Offline Linux staging only: this journal persists an already verified
// permit, NOT a vault transition or monotonic trusted suite floor.
import (
 "bytes"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "syscall"
)

const journalName = "xsp2-verified-permit.json"
const lockName = ".xsp2-permit.lock"

type permitRecord struct {
 Schema string `json:"schema"`
 SignedPermit []byte `json:"signedPermit"`
 EnvelopeSHA256 string `json:"envelopeSha256"`
 PermitDigest string `json:"permitDigest"`
}

func checkPrivateDir(dir string) error {
 if !filepath.IsAbs(dir) {return errors.New("journal dir must be absolute")}
 info,e:=os.Lstat(dir);if e!=nil{return e}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0||info.Mode().Perm()&0077!=0 {
  return errors.New("journal requires a private non-symlink directory (0700)")
 }
 return nil
}
func lockPermit(dir string)(*os.File,error){
 path:=filepath.Join(dir,lockName)
 fd,e:=syscall.Open(path,syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,0600)
 if e!=nil{return nil,e}
 file:=os.NewFile(uintptr(fd),path)
 info,e:=file.Stat()
 if e!=nil||!info.Mode().IsRegular()||info.Mode().Perm()&0077!=0{
  file.Close();return nil,errors.New("unsafe journal lock file")
 }
 if e=syscall.Flock(int(file.Fd()),syscall.LOCK_EX);e!=nil{file.Close();return nil,e}
 return file,nil
}
func readPermitFile(path string)(permitRecord,error) {
 var result permitRecord
 info,e:=os.Lstat(path)
 if e!=nil{return result,e}
 if !info.Mode().IsRegular()||info.Mode().Perm()&0077!=0||info.Size()>32*1024{
  return result,errors.New("unsafe journal file")
 }
 raw,e:=os.ReadFile(path);if e!=nil{return result,e}
 if e=uniqueFields(raw);e!=nil{return result,e}
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 if e=d.Decode(&result);e!=nil{return permitRecord{},e}
 if e=d.Decode(new(any));e!=io.EOF{return permitRecord{},errors.New("trailing journal bytes")}
 if result.Schema!="xsp2-verified-permit-journal-1"||
    len(result.SignedPermit)==0||len(result.SignedPermit)>16*1024||
    result.EnvelopeSHA256!=sha(result.SignedPermit)||
    len(result.PermitDigest)!=64 {
  return permitRecord{},errors.New("invalid journal record")
 }
 return result,nil
}
func atomicPersist(dir,path string,record permitRecord) error {
 out,e:=json.Marshal(record);if e!=nil{return e}
 tmp,e:=os.CreateTemp(dir,".xsp2-permit-tmp-");if e!=nil{return e}
 cleanup:=true
 defer func(){tmp.Close();if cleanup{os.Remove(tmp.Name())}}()
 if e=tmp.Chmod(0600);e!=nil{return e}
 if _,e=tmp.Write(out);e!=nil{return e}
 if e=tmp.Sync();e!=nil{return e}
 if e=tmp.Close();e!=nil{return e}
 if _,e=os.Lstat(path);e==nil {
  return errors.New("journal path unexpectedly exists during initial commit")
 } else if !errors.Is(e,os.ErrNotExist){return e}
 if e=os.Rename(tmp.Name(),path);e!=nil{return e}
 cleanup=false
 directory,e:=os.Open(dir);if e!=nil{return e}
 defer directory.Close()
 // Sync the parent directory entry to reduce rename loss on a crash.
 return directory.Sync()
}

// PersistVerifiedPermit records exact dual-signed permit bytes after both
// signatures were checked using an independently pinned panel_response pair.
//
// The caller must obtain ExpectedPermit from independently approved local
// keys; passing fields copied from the untrusted permit defeats this gate.
// Returns a verification marker, but NEVER changes the vault or epoch.
//
// # Security boundary
// This is a local filesystem *integrity and retry journal*, not an
// anti-rollback hardware floor: a restored disk snapshot can replace it.
// A pending ACK or active cutover needs a separate, stronger commit journal.
func PersistVerifiedPermit(dir string,raw []byte,pin PinnedPublic,want ExpectedPermit,nowMs int64)(VerifiedPermit,error){
 var empty VerifiedPermit
 v,e:=VerifyPermit(raw,pin,want,nowMs);if e!=nil{return empty,e}
 if e=checkPrivateDir(dir);e!=nil{return empty,e}
 lock,e:=lockPermit(dir);if e!=nil{return empty,e}
 defer func(){syscall.Flock(int(lock.Fd()),syscall.LOCK_UN);lock.Close()}()
 path:=filepath.Join(dir,journalName)
 existing,e:=readPermitFile(path)
 if e==nil {
  if existing.EnvelopeSHA256!=sha(raw)||existing.PermitDigest!=v.PermitDigest()||
     !bytes.Equal(existing.SignedPermit,raw){
   return empty,errors.New("different permit already journaled: deny cutover")
  }
  return v,nil
 }
 if !errors.Is(e,os.ErrNotExist){return empty,fmt.Errorf("invalid existing journal: %w",e)}
 row:=permitRecord{
  Schema:"xsp2-verified-permit-journal-1",SignedPermit:append([]byte(nil),raw...),
  EnvelopeSHA256:sha(raw),PermitDigest:v.PermitDigest(),
 }
 if e=atomicPersist(dir,path,row);e!=nil{return empty,e}
 return v,nil
}

// ReloadVerifiedPermit verifies the stored exact envelope AGAINST currently
// trusted pin and approval. Never treat filesystem contents as the authority.
func ReloadVerifiedPermit(dir string,pin PinnedPublic,want ExpectedPermit,nowMs int64)(VerifiedPermit,error){
 var empty VerifiedPermit
 if e:=checkPrivateDir(dir);e!=nil{return empty,e}
 lock,e:=lockPermit(dir);if e!=nil{return empty,e}
 defer func(){syscall.Flock(int(lock.Fd()),syscall.LOCK_UN);lock.Close()}()
 record,e:=readPermitFile(filepath.Join(dir,journalName));if e!=nil{return empty,e}
 v,e:=VerifyPermit(record.SignedPermit,pin,want,nowMs)
 if e!=nil{return empty,e}
 if v.PermitDigest()!=record.PermitDigest{return empty,errors.New("journal canonical digest changed")}
 return v,nil
}
