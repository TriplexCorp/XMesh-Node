package keyring

// TEST/STAGING only. Root-owned, mode-0600 AES-256-GCM wrapping-key file is
// separate from the encrypted Ed25519/ML-DSA seed file. NOT an HSM/KMS.
// Deleting/restoring both files as root can roll back epochs. Never deploy
// without independent rollback protection and reviewed recovery procedures.
import (
 "bytes"
 "crypto/aes"
 "crypto/cipher"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/subtle"
 "encoding/base64"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "strconv"
 "syscall"
 "crypto/mldsa"
)

type sealedFile struct {
 Version int `json:"version"`
 Public PublicBundle `json:"public"`
 Nonce string `json:"nonce"`
 Ciphertext string `json:"ciphertext"`
}
const vaultVersion=1
func secureFile(path string) ([]byte,error){
 info,e:=os.Lstat(path);if e!=nil{return nil,e}
 if !info.Mode().IsRegular()||info.Mode().Perm()!=0600{return nil,errors.New("private file must be regular mode 0600")}
 st,ok:=info.Sys().(*syscall.Stat_t)
 if !ok||st.Uid!=uint32(os.Geteuid()){return nil,errors.New("private file owner mismatch")}
 return os.ReadFile(path)
}
func secureDir(file string)error{
 dir,e:=os.Lstat(filepath.Dir(file))
 if e!=nil{return e}
 if !dir.IsDir()||dir.Mode().Perm()!=0700{return errors.New("vault directory must be mode 0700")}
 st,ok:=dir.Sys().(*syscall.Stat_t)
 if !ok||st.Uid!=uint32(os.Geteuid()){return errors.New("vault directory owner mismatch")}
 return nil
}
func atomicFile(path string,raw []byte)error{
 if e:=secureDir(path);e!=nil{return e}
 tmp,e:=os.CreateTemp(filepath.Dir(path),".xsp-sealed-")
 if e!=nil{return e}
 defer os.Remove(tmp.Name())
 if e=tmp.Chmod(0600);e==nil{_,e=tmp.Write(raw)}
 if e==nil{e=tmp.Sync()}
 closeErr:=tmp.Close();if e!=nil{return e};if closeErr!=nil{return closeErr}
 if e:=os.Rename(tmp.Name(),path);e!=nil{return e}
 d,e:=os.Open(filepath.Dir(path));if e!=nil{return e}
 defer d.Close()
 return d.Sync()
}
func floorPath(vault string)string{return vault+".min-epoch"}
func readFloor(path string)(uint64,error){
 data,e:=secureFile(floorPath(path));if errors.Is(e,os.ErrNotExist){return 0,nil}
 if e!=nil{return 0,e}
 number,e:=strconv.ParseUint(string(data),10,64)
 if e!=nil||number==0{return 0,errors.New("invalid persisted key epoch floor")}
 return number,nil
}
func updateFloor(path string,epoch uint64)error{
 prior,e:=readFloor(path);if e!=nil{return e}
 if epoch<prior||epoch==0{return errors.New("key epoch rollback refused")}
 return atomicFile(floorPath(path),[]byte(strconv.FormatUint(epoch,10)))
}
// CreateMasterKey creates ONLY an external, random root-owner wrapping key.
// It will never replace an existing wrapping key. Losing it loses access.
func CreateMasterKey(path string)error{
 if e:=secureDir(path);e!=nil{return e}
 f,e:=os.OpenFile(path,os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if e!=nil{return e}
 raw:=make([]byte,32);_,e=io.ReadFull(rand.Reader,raw)
 if e==nil{_,e=f.Write(raw)}
 if e==nil{e=f.Sync()}
 cerr:=f.Close();clear(raw)
 if e!=nil||cerr!=nil{os.Remove(path);if e!=nil{return e};return cerr}
 return nil
}
func masterLocked(path string,exclusive bool)(*os.File,[]byte,error){
 if e:=secureDir(path);e!=nil{return nil,nil,e}
 _,e:=secureFile(path);if e!=nil{return nil,nil,e}
 f,e:=os.OpenFile(path,os.O_RDONLY,0);if e!=nil{return nil,nil,e}
 lock:=syscall.LOCK_SH;if exclusive{lock=syscall.LOCK_EX}
 if e=syscall.Flock(int(f.Fd()),lock);e!=nil{f.Close();return nil,nil,e}
 // Re-check to reject a replaced, symlinked or relaxed-permissions master.
 content,e:=secureFile(path)
 if e!=nil||len(content)!=32{f.Close();return nil,nil,errors.New("master key invalid")}
 return f,content,nil
}
func seal(keys *VolatileKeys,pub PublicBundle,master []byte)([]byte,error){
 if keys==nil||len(keys.ed)!=ed25519.PrivateKeySize||keys.pq==nil{return nil,errors.New("missing key material")}
 block,e:=aes.NewCipher(master);if e!=nil{return nil,e}
 gcm,e:=cipher.NewGCM(block);if e!=nil{return nil,e}
 nonce:=make([]byte,gcm.NonceSize());if _,e=rand.Read(nonce);e!=nil{return nil,e}
 payload:=append(append([]byte(nil),keys.ed.Seed()...),keys.pq.Bytes()...)
 defer clear(payload)
 aad,e:=json.Marshal(pub);if e!=nil{return nil,e}
 ciphertext:=gcm.Seal(nil,nonce,payload,aad)
 return json.Marshal(sealedFile{Version:vaultVersion,Public:pub,
  Nonce:base64.StdEncoding.EncodeToString(nonce),
  Ciphertext:base64.StdEncoding.EncodeToString(ciphertext)})
}
func openWithMaster(path string,master []byte)(*VolatileKeys,PublicBundle,error){
 var empty PublicBundle
 raw,e:=secureFile(path);if e!=nil{return nil,empty,e}
 if len(raw)>16384{return nil,empty,errors.New("oversized vault")}
 dec:=json.NewDecoder(bytes.NewReader(raw));dec.DisallowUnknownFields()
 var v sealedFile
 if e=dec.Decode(&v);e!=nil{return nil,empty,e}
 if e=dec.Decode(new(any));e!=io.EOF{return nil,empty,errors.New("trailing vault data")}
 if v.Version!=vaultVersion||v.Public.NodeID<=0||v.Public.KeyEpoch==0||
  (v.Public.Purpose!="node_request"&&v.Public.Purpose!="panel_response"){
  return nil,empty,errors.New("invalid vault metadata")
 }
 floor,e:=readFloor(path);if e!=nil{return nil,empty,e}
 if v.Public.KeyEpoch<floor{return nil,empty,errors.New("persisted epoch floor rejected old vault")}
 nonce,e:=base64.StdEncoding.Strict().DecodeString(v.Nonce);if e!=nil{return nil,empty,e}
 ciphertext,e:=base64.StdEncoding.Strict().DecodeString(v.Ciphertext);if e!=nil{return nil,empty,e}
 block,e:=aes.NewCipher(master);if e!=nil{return nil,empty,e}
 gcm,e:=cipher.NewGCM(block);if e!=nil{return nil,empty,e}
 if len(nonce)!=gcm.NonceSize(){return nil,empty,errors.New("invalid nonce length")}
 aad,e:=json.Marshal(v.Public);if e!=nil{return nil,empty,e}
 plaintext,e:=gcm.Open(nil,nonce,ciphertext,aad);if e!=nil{return nil,empty,errors.New("vault authentication failed")}
 defer clear(plaintext)
 if len(plaintext)!=64{return nil,empty,errors.New("invalid decrypted seed length")}
 ed:=ed25519.NewKeyFromSeed(plaintext[:32])
 pq,e:=mldsa.NewPrivateKey(mldsa.MLDSA65(),plaintext[32:]);if e!=nil{return nil,empty,e}
 edPub:=ed.Public().(ed25519.PublicKey);pqPub:=pq.PublicKey().Bytes()
 if subtle.ConstantTimeCompare(edPub,v.Public.EdPublic)!=1||
  subtle.ConstantTimeCompare(pqPub,v.Public.PQPublic)!=1||
  v.Public.EdKeyID!=fingerprint("ed-",edPub)||
  v.Public.PQKeyID!=fingerprint("pq-",pqPub){
  return nil,empty,errors.New("public key binding invalid")
 }
 return &VolatileKeys{ed:ed,pq:pq},v.Public,nil
}
// Open verifies owner, mode, external key, authenticated metadata and epoch floor.
func Open(vault,master string)(*VolatileKeys,PublicBundle,error){
 var empty PublicBundle
 f,k,e:=masterLocked(master,false);if e!=nil{return nil,empty,e}
 defer f.Close();defer clear(k)
 return openWithMaster(vault,k)
}
func Initialize(vault,master string,nodeID int64,purpose string)(PublicBundle,error){
 var empty PublicBundle
 f,k,e:=masterLocked(master,true);if e!=nil{return empty,e}
 defer f.Close();defer clear(k)
 if e:=secureDir(vault);e!=nil{return empty,e}
 _,statErr:=os.Lstat(vault)
 if statErr==nil{return empty,errors.New("vault already exists")}
 if !errors.Is(statErr,os.ErrNotExist){return empty,statErr}
 _,statErr=os.Lstat(floorPath(vault))
 if statErr==nil{return empty,errors.New("vault epoch floor already exists")}
 if !errors.Is(statErr,os.ErrNotExist){return empty,statErr}
 keys,pub,e:=Generate(nodeID,purpose,1);if e!=nil{return empty,e}
 raw,e:=seal(keys,pub,k);if e!=nil{return empty,e}
 if e:=atomicFile(vault,raw);e!=nil{return empty,e}
 if e:=updateFloor(vault,1);e!=nil{return empty,e}
 return pub,nil
}
func Rotate(vault,master string,expectedEpoch uint64)(PublicBundle,error){
 var empty PublicBundle
 f,k,e:=masterLocked(master,true);if e!=nil{return empty,e}
 defer f.Close();defer clear(k)
 _,before,e:=openWithMaster(vault,k);if e!=nil{return empty,e}
 if before.KeyEpoch!=expectedEpoch||expectedEpoch==^uint64(0){
  return empty,errors.New("expected key epoch mismatch")
 }
 keys,next,e:=Generate(before.NodeID,before.Purpose,before.KeyEpoch+1)
 if e!=nil{return empty,e}
 raw,e:=seal(keys,next,k);if e!=nil{return empty,e}
 // Fail-closed on power loss: advance the floor BEFORE swapping the keys.
 // A crash between the two writes rejects the old vault on next start.
 if e:=updateFloor(vault,next.KeyEpoch);e!=nil{return empty,e}
 if e:=atomicFile(vault,raw);e!=nil{return empty,e}
 return next,nil
}
func Description(vault,master string)(PublicBundle,error){
 _,pub,e:=Open(vault,master)
 if e!=nil{return PublicBundle{},fmt.Errorf("cannot open encrypted key bundle: %w",e)}
 return pub,nil
}
