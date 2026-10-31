//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/activation"
)

// Release builds MUST override both values with -ldflags. A developer build
// cannot execute production activation because sourceRevision is not canonical
// lowercase 40-hex.
var (
	version = "strict-pq-unreleased"
	sourceRevision = "development"
)

type identity struct {
	Version string `json:"version"`
	SourceRevision string `json:"sourceRevision"`
	ArtifactSHA256 string `json:"artifactSha256"`
}

func fileSHA256(path string)(string,error){
	raw,err:=os.ReadFile(path);if err!=nil{return "",err}
	sum:=sha256.Sum256(raw);return hex.EncodeToString(sum[:]),nil
}
func validRevision(value string)bool{
	if len(value)!=40||strings.ToLower(value)!=value{return false}
	_,err:=hex.DecodeString(value);return err==nil
}
func executableSHA()(string,error){path,err:=os.Executable();if err!=nil{return "",err};return fileSHA256(path)}

func main(){
	config:=flag.String("config","","root/operator-provisioned activation config path")
	recoverMode:=flag.Bool("recover",false,"recover an immutable committed receipt after a lost response/restart")
	showIdentity:=flag.Bool("identity",false,"print exact activation artifact identity")
	flag.Parse()
	if flag.NArg()!=0{fmt.Fprintln(os.Stderr,"positional commands are not supported");os.Exit(2)}
	if !validRevision(sourceRevision){fmt.Fprintln(os.Stderr,"activation binary has no approved source revision");os.Exit(2)}
	artifactSHA,err:=executableSHA();if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
	if *showIdentity{
		if *config!=""||*recoverMode{fmt.Fprintln(os.Stderr,"--identity cannot be combined with activation");os.Exit(2)}
		if err=json.NewEncoder(os.Stdout).Encode(identity{Version:version,SourceRevision:sourceRevision,ArtifactSHA256:artifactSHA});err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
		return
	}
	if *config==""{fmt.Fprintln(os.Stderr,"--config is required");os.Exit(2)}
	mode:=activation.ModeActivate;if *recoverMode{mode=activation.ModeRecover}
	ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel()
	result,err:=activation.Execute(ctx,mode,*config,sourceRevision,artifactSHA,time.Now().UTC())
	if err!=nil{fmt.Fprintln(os.Stderr,"strict-PQ activation rejected:",err);os.Exit(1)}
	if err=json.NewEncoder(os.Stdout).Encode(result);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}
}
