package keyring

import (
 "bytes"
 "crypto/ed25519"
 "crypto/mldsa"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
)

func TestSealedVaultRotatesFailClosedAndDoesNotLeakPrivateSeeds(t *testing.T){
 root:=t.TempDir()
 if e:=os.Chmod(root,0700);e!=nil{t.Fatal(e)}
 master:=filepath.Join(root,"master.key")
 vault:=filepath.Join(root,"node.encrypted.json")
 if e:=CreateMasterKey(master);e!=nil{t.Fatal(e)}
 if e:=CreateMasterKey(master);e==nil{t.Fatal("master overwritten")}
 initial,e:=Initialize(vault,master,42,"node_request")
 if e!=nil{t.Fatal(e)}
 if _,e:=Initialize(vault,master,42,"node_request");e==nil{t.Fatal("vault overwritten")}
 original,e:=os.ReadFile(vault);if e!=nil{t.Fatal(e)}
 if len(original)<2000{t.Fatal("missing ciphertext")}
 keys,pub,e:=Open(vault,master);if e!=nil{t.Fatal(e)}
 if pub.NodeID!=42||pub.KeyEpoch!=1||pub.Purpose!="node_request"{
  t.Fatal("wrong enrolled identity")
 }
 msg:=[]byte("test xsp2 canonical input")
 edsig,pqsig,e:=keys.Sign(msg);if e!=nil{t.Fatal(e)}
 pqpub,e:=mldsa.NewPublicKey(mldsa.MLDSA65(),pub.PQPublic);if e!=nil{t.Fatal(e)}
 if !ed25519.Verify(pub.EdPublic,msg,edsig)||mldsa.Verify(pqpub,msg,pqsig,nil)!=nil{
  t.Fatal("ciphertext did not restore valid dual private keys")
 }
 if bytes.Contains(original,keys.ed.Seed())||bytes.Contains(original,keys.pq.Bytes()){
  t.Fatal("plaintext key material leaked to vault")
 }
 if _,e:=Rotate(vault,master,2);e==nil{t.Fatal("accepted mismatched prior epoch")}
 next,e:=Rotate(vault,master,1);if e!=nil{t.Fatal(e)}
 if next.KeyEpoch!=2||next.NodeID!=42||bytes.Equal(next.EdPublic,pub.EdPublic)||
   bytes.Equal(next.PQPublic,pub.PQPublic){t.Fatal("rotation failed to use fresh keys")}
 if _,_,e:=Open(vault,master);e!=nil{t.Fatal(e)}
 if e:=os.WriteFile(vault,original,0600);e!=nil{t.Fatal(e)}
 if _,_,e:=Open(vault,master);e==nil{t.Fatal("accepted rolled back ciphertext")}
 current,e:=json.Marshal(sealedFile{Version:1,Public:pub})
 if e!=nil{t.Fatal(e)}
 if bytes.Contains(current,keys.ed.Seed()){t.Fatal("keys in metadata")}
}
func TestVaultPermissionAndTamperRejections(t *testing.T){
 dir:=t.TempDir()
 if e:=os.Chmod(dir,0700);e!=nil{t.Fatal(e)}
 master:=filepath.Join(dir,"master.key");vault:=filepath.Join(dir,"vault.json")
 if e:=CreateMasterKey(master);e!=nil{t.Fatal(e)}
 if _,e:=Initialize(vault,master,19,"panel_response");e!=nil{t.Fatal(e)}
 if e:=os.Chmod(master,0644);e!=nil{t.Fatal(e)}
 if _,_,e:=Open(vault,master);e==nil{t.Fatal("world-readable master accepted")}
 if e:=os.Chmod(master,0600);e!=nil{t.Fatal(e)}
 if e:=os.Chmod(vault,0644);e!=nil{t.Fatal(e)}
 if _,_,e:=Open(vault,master);e==nil{t.Fatal("world-readable vault accepted")}
 if e:=os.Chmod(vault,0600);e!=nil{t.Fatal(e)}
 raw,e:=os.ReadFile(vault);if e!=nil{t.Fatal(e)}
 var pack sealedFile
 if e:=json.Unmarshal(raw,&pack);e!=nil{t.Fatal(e)}
 pack.Public.Purpose="node_request"
 data,e:=json.Marshal(pack);if e!=nil{t.Fatal(e)}
 if e:=os.WriteFile(vault,data,0600);e!=nil{t.Fatal(e)}
 if _,_,e:=Open(vault,master);e==nil{t.Fatal("accepted authenticated metadata tampering")}
 if e:=os.WriteFile(vault,raw,0600);e!=nil{t.Fatal(e)}
 if e:=os.Chmod(dir,0755);e!=nil{t.Fatal(e)}
 if _,_,e:=Open(vault,master);e==nil{t.Fatal("world-readable vault directory accepted")}
}
