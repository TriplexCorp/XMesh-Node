//go:build linux

package cutover

// The only exported ACK journaling entrypoints in staging require a read-only
// attestation of the already-applied encrypted vault AND a pinned, verified
// signed permit. No function here activates a vault, changes an epoch, emits
// network traffic, or authorizes key retirement.
import (
 "bytes"
 "errors"
 "math"

 "github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

func attestACKVault(vault,master string,permit VerifiedPermit,next PinnedPublic) error {
 p:=permit.Message()
 if permit.PermitDigest()=="" || p.Kind!="permit" || p.NodeID==0 ||
  p.NodeID>math.MaxInt64 || p.ToEpoch==0 || p.ToEpoch!=p.FromEpoch+1 ||
  next.NodeID!=p.NodeID || next.Purpose!="node_request" ||
  next.EdKeyID!=p.ToEdKeyID || next.PQKeyID!=p.ToPQKeyID {
  return errors.New("applied-vault attestation has no trusted pending identity")
 }
 active,e:=keyring.AttestAppliedRotation(vault,master,int64(p.NodeID),
  p.FromEpoch,p.ToEpoch,p.ToEdKeyID,p.ToPQKeyID)
 if e!=nil{return e}
 if !bytes.Equal(active.EdPublic,next.EdPublic) ||
  !bytes.Equal(active.PQPublic,next.PQPublic) {
  return errors.New("decrypted active vault public keys differ from trusted pending signer")
 }
 return nil
}

// PersistACKForCommittedVault requires an authenticated, already-activated new
// encrypted vault and exact protected epoch floor before any signed ACK may
// be recorded for retries. The signer and vault public keys must match byte
// for byte; only then are the ACK's two signatures checked and persisted.
//
// Software-only inspection is not an independently protected monotonic floor.
// Another privileged writer could race changes after inspection. Full cutover
// still requires exclusive lifecycle lock and anti-rollback storage/KMS.
func PersistACKForCommittedVault(dir,vault,master string,raw []byte,
 permit VerifiedPermit,next PinnedPublic,nowMS int64)(Message,error){
 if e:=attestACKVault(vault,master,permit,next);e!=nil{return Message{},e}
 return persistVerifiedAppliedACK(dir,raw,permit,next,nowMS)
}

// ReloadACKForCommittedVault fail-closes after restoration of the old active
// keypair even if the original signed ACK journal remains intact.
func ReloadACKForCommittedVault(dir,vault,master string,
 permit VerifiedPermit,next PinnedPublic,nowMS int64)(Message,error){
 if e:=attestACKVault(vault,master,permit,next);e!=nil{return Message{},e}
 return reloadVerifiedAppliedACK(dir,permit,next,nowMS)
}
