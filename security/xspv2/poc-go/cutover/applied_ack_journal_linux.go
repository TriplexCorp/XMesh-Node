//go:build linux

package cutover

// This OFFLINE staging journal records a previously verified dual-signed ACK.
// Caller must already have durably committed the protected new Node vault/floor.
// This file does not perform such a commit or transmit ACK to Nexus.
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

const ackJournalName = "xsp2-applied-ack.json"

type appliedACKRecord struct {
 Schema string `json:"schema"`
 SignedACK []byte `json:"signedAck"`
 EnvelopeSHA256 string `json:"envelopeSha256"`
 PermitDigest string `json:"permitDigest"`
 NodeID uint64 `json:"nodeId"`
 ToEpoch uint64 `json:"toEpoch"`
 RequestID string `json:"requestId"`
}
func readACKRecord(path string)(appliedACKRecord,error){
 var result appliedACKRecord
 info,e:=os.Lstat(path);if e!=nil{return result,e}
 if !info.Mode().IsRegular()||info.Mode().Perm()&0077!=0||info.Size()>32*1024{return result,errors.New("unsafe ACK journal file")}
 raw,e:=os.ReadFile(path);if e!=nil{return result,e}
 if e=uniqueFields(raw);e!=nil{return result,e}
 d:=json.NewDecoder(bytes.NewReader(raw));d.DisallowUnknownFields()
 if e=d.Decode(&result);e!=nil{return appliedACKRecord{},e}
 if e=d.Decode(new(any));e!=io.EOF{return appliedACKRecord{},errors.New("ACK journal trailing bytes")}
 if result.Schema!="xsp2-applied-ack-journal-1" || len(result.SignedACK)==0||
  len(result.SignedACK)>16*1024||result.EnvelopeSHA256!=sha(result.SignedACK)||
  len(result.PermitDigest)!=64||result.NodeID==0||result.ToEpoch==0||
  len(result.RequestID)==0||len(result.RequestID)>64 {
  return appliedACKRecord{},errors.New("corrupt ACK journal")
 }
 return result,nil
}
func persistACKFile(dir,path string,record appliedACKRecord)error{
 raw,e:=json.Marshal(record);if e!=nil{return e}
 tmp,e:=os.CreateTemp(dir,".xsp2-ack-tmp-");if e!=nil{return e}
 defer func(){_ = tmp.Close();_ = os.Remove(tmp.Name())}()
 if e=tmp.Chmod(0600);e!=nil{return e}
 if _,e=tmp.Write(raw);e!=nil{return e}
 if e=tmp.Sync();e!=nil{return e}
 if e=tmp.Close();e!=nil{return e}
 if _,e=os.Lstat(path);e==nil{return errors.New("ACK journal already exists")}
 else if !errors.Is(e,os.ErrNotExist){return e}
 if e=os.Rename(tmp.Name(),path);e!=nil{return e}
 directory,e:=os.Open(dir);if e!=nil{return e}
 defer directory.Close()
 return directory.Sync()
}

// PersistVerifiedAppliedACK is a retry journal, NOT an epoch activation API.
// No valid ACK should be created before an independently fsynced new-vault
// commit and protected monotonic floor; caller must enforce those preconditions.
func PersistVerifiedAppliedACK(dir string,raw []byte,permit VerifiedPermit,
 next PinnedPublic,nowMS int64)(Message,error){
 var empty Message
 msg,e:=VerifyAppliedACK(raw,permit,next,nowMS);if e!=nil{return empty,e}
 if e=checkPrivateDir(dir);e!=nil{return empty,e}
 lock,e:=lockPermit(dir);if e!=nil{return empty,e}
 defer func(){_ = syscall.Flock(int(lock.Fd()),syscall.LOCK_UN);_ = lock.Close()}()
 path:=filepath.Join(dir,ackJournalName)
 old,e:=readACKRecord(path)
 if e==nil{
  if !bytes.Equal(old.SignedACK,raw)||old.EnvelopeSHA256!=sha(raw)||
   old.PermitDigest!=permit.PermitDigest()||old.NodeID!=msg.NodeID||
   old.ToEpoch!=msg.ToEpoch||old.RequestID!=msg.RequestID{
   return empty,errors.New("conflicting ACK: refuse to replace prior commitment")
  }
  return msg,nil
 }
 if !errors.Is(e,os.ErrNotExist){return empty,fmt.Errorf("invalid ACK journal: %w",e)}
 row:=appliedACKRecord{Schema:"xsp2-applied-ack-journal-1",
  SignedACK:append([]byte(nil),raw...),EnvelopeSHA256:sha(raw),
  PermitDigest:permit.PermitDigest(),NodeID:msg.NodeID,
  ToEpoch:msg.ToEpoch,RequestID:msg.RequestID}
 if e=persistACKFile(dir,path,row);e!=nil{return empty,e}
 return msg,nil
}

// ReloadVerifiedAppliedACK authenticates original journal bytes afresh against
// pinned next keys and the independent verified permit. It never trusts disk
// data as the authority for key epochs, approval or floor.
func ReloadVerifiedAppliedACK(dir string,permit VerifiedPermit,
 next PinnedPublic,nowMS int64)(Message,error){
 var empty Message
 if e:=checkPrivateDir(dir);e!=nil{return empty,e}
 lock,e:=lockPermit(dir);if e!=nil{return empty,e}
 defer func(){_ = syscall.Flock(int(lock.Fd()),syscall.LOCK_UN);_ = lock.Close()}()
 row,e:=readACKRecord(filepath.Join(dir,ackJournalName));if e!=nil{return empty,e}
 msg,e:=VerifyAppliedACK(row.SignedACK,permit,next,nowMS);if e!=nil{return empty,e}
 if row.PermitDigest!=permit.PermitDigest()||row.NodeID!=msg.NodeID||
  row.ToEpoch!=msg.ToEpoch||row.RequestID!=msg.RequestID{
  return empty,errors.New("ACK journal binding mismatch")
 }
 return msg,nil
}
