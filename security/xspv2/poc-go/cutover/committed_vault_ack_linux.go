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

func withAttestedACKVault(vault,master string,permit VerifiedPermit,next PinnedPublic,action func()error) error {
 p:=permit.Message()
 if permit.PermitDigest()=="" || p.Kind!="permit" || p.NodeID==0 ||
  p.NodeID>math.MaxInt64 || p.ToEpoch==0 || p.ToEpoch!=p.FromEpoch+1 ||
  next.NodeID!=p.NodeID || next.Purpose!="node_request" ||
  next.EdKeyID!=p.ToEdKeyID || next.PQKeyID!=p.ToPQKeyID {
  return errors.New("applied-vault attestation has no trusted pending identity")
 }
 return keyring.WithAttestedAppliedRotation(vault,master,int64(p.NodeID),
  p.FromEpoch,p.ToEpoch,p.FromEdKeyID,p.FromPQKeyID,p.ToEdKeyID,p.ToPQKeyID,
  func(active keyring.PublicBundle)error{
   if !bytes.Equal(active.EdPublic,next.EdPublic) ||
    !bytes.Equal(active.PQPublic,next.PQPublic) {
    return errors.New("decrypted active vault public keys differ from trusted pending signer")
   }
   return action()
  })
}

// PersistACKForCommittedVault requires an authenticated, already-activated new
// encrypted vault and exact protected epoch floor before any signed ACK may
// be recorded for retries. The signer and vault public keys must match byte
// for byte; only then are the ACK's two signatures checked and persisted.
//
// Software-only inspection is not an independently protected monotonic floor.
// Compliant writers are serialized by the same master-key flock through the
// journal fsync, but privileged out-of-band writes and restores remain risks.
func PersistACKForCommittedVault(dir,vault,master string,raw []byte,
 permit VerifiedPermit,next PinnedPublic,nowMS int64)(Message,error){
 var committed Message
 e:=withAttestedACKVault(vault,master,permit,next,func()error{
  var persistErr error
  committed,persistErr=persistVerifiedAppliedACK(dir,raw,permit,next,nowMS)
  return persistErr
 })
 return committed,e
}

// ReloadACKForCommittedVault fail-closes after restoration of the old active
// keypair even if the original signed ACK journal remains intact.
func ReloadACKForCommittedVault(dir,vault,master string,
 permit VerifiedPermit,next PinnedPublic,nowMS int64)(Message,error){
 var result Message
 e:=withAttestedACKVault(vault,master,permit,next,func()error{
  var reloadErr error
  result,reloadErr=reloadVerifiedAppliedACK(dir,permit,next,nowMS)
  return reloadErr
 })
 return result,e
}
