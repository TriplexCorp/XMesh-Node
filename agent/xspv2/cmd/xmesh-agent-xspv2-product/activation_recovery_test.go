package main

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

func TestSavedActivationRequiresBothOriginalSignaturesAndRelease(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	pqPriv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil { t.Fatal(err) }
	release := releaseIdentity{Version:"control-v6.0.27",
		SourceRevision:strings.Repeat("a",40),ArtifactSHA256:strings.Repeat("b",64)}
	cfg := productConfig{NodeID:7,ReleaseIdentity:release}
	pub := keyring.PublicBundle{NodeID:7,KeyEpoch:1,Purpose:"node_request",
		EdKeyID:"ed-test",PQKeyID:"pq-test",
		EdPublic:edPub,PQPublic:pqPriv.PublicKey().Bytes()}
	payload, err := json.Marshal(map[string]any{
		"schema":"xmesh-v6-strict-pq-activation-request-1","nodeId":7,
		"releaseIdentity":release,"automaticClassicalFallback":false})
	if err != nil { t.Fatal(err) }
	issued := time.Now().Add(-10*time.Minute).UnixMilli()
	env := envelope{Protocol:"XSP/2",Suite:suite,Direction:1,MessageType:"node.product.activate",
		IssuerID:"xmesh-node-7",NodeID:7,Method:"POST",Path:"/api/v2/product/activate",
		Ed25519KeyID:pub.EdKeyID,MLDSA65KeyID:pub.PQKeyID,KeyEpoch:1,
		IssuedAtMS:issued,ExpiresAtMS:issued+120000,
		NonceHex:strings.Repeat("0",32),RequestID:strings.Repeat("c",32),
		Revision:release.SourceRevision,PayloadB64:b64.EncodeToString(payload)}
	input, err := signingInput(env,payload)
	if err != nil { t.Fatal(err) }
	env.Signatures.Ed25519=b64.EncodeToString(ed25519.Sign(edPriv,input))
	pqSig, err := pqPriv.Sign(nil,input,nil)
	if err != nil { t.Fatal(err) }
	env.Signatures.MLDSA65=b64.EncodeToString(pqSig)
	raw, err := json.Marshal(env)
	if err != nil { t.Fatal(err) }
	if _,err:=verifySavedActivationRequest(cfg,pub,raw);err!=nil {
		t.Fatal(err)
	}
	bad := env
	bad.Revision = strings.Repeat("d",40)
	badRaw, _ := json.Marshal(bad)
	if _,err:=verifySavedActivationRequest(cfg,pub,badRaw);err==nil {
		t.Fatal("foreign signed source accepted")
	}
	bad = env
	bad.Signatures.Ed25519 = b64.EncodeToString(make([]byte,ed25519.SignatureSize))
	badRaw, _ = json.Marshal(bad)
	if _,err:=verifySavedActivationRequest(cfg,pub,badRaw);err==nil {
		t.Fatal("altered Ed25519 signature accepted")
	}
	bad = env
	bad.Signatures.MLDSA65 = b64.EncodeToString(make([]byte,mldsa.MLDSA65SignatureSize))
	badRaw, _ = json.Marshal(bad)
	if _,err:=verifySavedActivationRequest(cfg,pub,badRaw);err==nil {
		t.Fatal("altered ML-DSA-65 signature accepted")
	}
	bad = env
	bad.PayloadB64 = b64.EncodeToString([]byte(`{"schema":"mismatch"}`))
	badRaw, _ = json.Marshal(bad)
	if _,err:=verifySavedActivationRequest(cfg,pub,badRaw);err==nil {
		t.Fatal("altered activation claims accepted")
	}
}
