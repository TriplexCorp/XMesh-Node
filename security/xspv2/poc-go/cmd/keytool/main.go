// keytool is a STAGING-ONLY offline helper. It never prints private seeds.
// It does not install a Node agent or register public keys with Nexus.
// Store the wrapping-key file separately and back up both secrets securely.
package main

import (
 "encoding/json"
 "flag"
 "fmt"
 "os"
 "github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)
func main(){
 if len(os.Args)<2{fmt.Fprintln(os.Stderr,"usage: keytool init-master|create|prepare-rotation|activate-rotation|recover-rotation|abort-rotation|public|prove -key /root/key -vault /root/vault");os.Exit(2)}
 action:=os.Args[1]
 opts:=flag.NewFlagSet(action,flag.ExitOnError)
 master:=opts.String("key","","external AES wrapping-key file (0600)")
 vault:=opts.String("vault","","encrypted Ed25519 + ML-DSA private key file (0600)")
 node:=opts.Int64("node",0,"node identity for create")
 purpose:=opts.String("purpose","node_request","node_request or panel_response")
 expected:=opts.Uint64("expected-epoch",0,"active epoch for staged rotation")
 edID:=opts.String("expected-ed-key-id","","operator-approved next Ed25519 key ID for activation")
 pqID:=opts.String("expected-pq-key-id","","operator-approved next ML-DSA-65 key ID for activation")
 challenge:=opts.String("challenge","","owner-issued 32-byte challenge hex for prove")
 if e:=opts.Parse(os.Args[2:]);e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(2)}
 if *master==""||(*vault==""&&action!="init-master")||opts.NArg()!=0{
  fmt.Fprintln(os.Stderr,"master and vault paths are required (vault not needed for init-master)");os.Exit(2)
 }
 var result any
 var err error
 switch action{
 case "init-master":
  err=keyring.CreateMasterKey(*master)
  result=map[string]any{"created":err==nil,"wrappingKey":"stored in external private file; never printed"}
 case "create":result,err=keyring.Initialize(*vault,*master,*node,*purpose)
 case "rotate":err=fmt.Errorf("unsafe immediate rotation disabled in CLI; use prepare-rotation and activate-rotation")
 case "prepare-rotation":result,err=keyring.PrepareRotation(*vault,*master,*expected)
 case "activate-rotation":result,err=keyring.ActivatePreparedRotation(*vault,*master,*expected,*edID,*pqID)
 case "abort-rotation":err=keyring.AbortPreparedRotation(*vault,*master,*expected);result=map[string]any{"aborted":err==nil}
 case "recover-rotation":result,err=keyring.RecoverRotation(*vault,*master)
 case "public":result,err=keyring.Description(*vault,*master)
 case "prove":result,err=keyring.ProveFromEncryptedVault(*vault,*master,*challenge)
 default:fmt.Fprintln(os.Stderr,"unsupported keytool subcommand");os.Exit(2)
 }
 if err!=nil{fmt.Fprintln(os.Stderr,"XSP staging keytool failed:",err);os.Exit(1)}
 if e:=json.NewEncoder(os.Stdout).Encode(result);e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
}
