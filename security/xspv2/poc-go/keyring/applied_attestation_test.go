package keyring

import (
 "bytes"
 "os"
 "testing"
)

func TestAttestAppliedRotationRejectsPreparedOnlyAndRolledBackVault(t *testing.T){
 vault,master,prior:=rotationFixture(t)
 next,e:=PrepareRotation(vault,master,prior.KeyEpoch)
 if e!=nil{t.Fatal(e)}
 if _,e=AttestAppliedRotation(vault,master,prior.NodeID,1,2,next.EdKeyID,next.PQKeyID);e==nil{
  t.Fatal("prepared-only vault must not authorize ACK")
 }
 if _,e=ActivatePreparedRotation(vault,master,1,next.EdKeyID,next.PQKeyID);e!=nil{
  t.Fatal(e)
 }
 got,e:=AttestAppliedRotation(vault,master,prior.NodeID,1,2,next.EdKeyID,next.PQKeyID)
 if e!=nil||got.KeyEpoch!=2||!bytes.Equal(got.EdPublic,next.EdPublic)||
  !bytes.Equal(got.PQPublic,next.PQPublic){t.Fatal("properly committed vault not attested",e)}
 if _,e=AttestAppliedRotation(vault,master,prior.NodeID,1,2,"swapped",next.PQKeyID);e==nil{
  t.Fatal("wrong Ed25519 key accepted")
 }
 if _,e=AttestAppliedRotation(vault,master,prior.NodeID,1,2,next.EdKeyID,"swapped");e==nil{
  t.Fatal("wrong ML-DSA key accepted")
 }
 if _,e=AttestAppliedRotation(vault,master,prior.NodeID+1,1,2,next.EdKeyID,next.PQKeyID);e==nil{
  t.Fatal("wrong node accepted")
 }
 if _,e=AttestAppliedRotation(vault,master,prior.NodeID,2,3,next.EdKeyID,next.PQKeyID);e==nil{
  t.Fatal("wrong epoch accepted")
 }
 old,e:=os.ReadFile(previousPath(vault));if e!=nil{t.Fatal(e)}
 if e=os.WriteFile(vault,old,0600);e!=nil{t.Fatal(e)}
 if _,e=AttestAppliedRotation(vault,master,prior.NodeID,1,2,next.EdKeyID,next.PQKeyID);e==nil{
  t.Fatal("restored old ciphertext accepted despite new floor")
 }
 if _,e=RecoverRotation(vault,master);e!=nil{t.Fatal(e)}
 if _,e=AttestAppliedRotation(vault,master,prior.NodeID,1,2,next.EdKeyID,next.PQKeyID);e!=nil{
  t.Fatal("forward-only recovery should restore applied state",e)
 }
 if e=os.WriteFile(stagedPath(vault),[]byte("corrupted"),0600);e!=nil{t.Fatal(e)}
 if _,e=AttestAppliedRotation(vault,master,prior.NodeID,1,2,next.EdKeyID,next.PQKeyID);e==nil{
  t.Fatal("tampered saved pending candidate accepted")
 }
}
