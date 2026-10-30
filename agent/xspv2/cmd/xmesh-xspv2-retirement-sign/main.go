//go:build linux

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/recovery"
)

func readPrivatePKCS8(path string) (any, error) {
	clean := filepath.Clean(path)
	if path == "" || !filepath.IsAbs(path) || clean != path {
		return nil, errors.New("owner private-key path must be canonical and absolute")
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("owner private key must be a non-symlink regular file with mode 0600")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("owner private key owner mismatch")
	}
	raw, err := os.ReadFile(clean)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("owner private key must be exactly one unencrypted PKCS#8 PRIVATE KEY PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	clear(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse owner PKCS#8 private key: %w", err)
	}
	return key, nil
}

func run(args []string) error {
	flags := flag.NewFlagSet("xmesh-xspv2-retirement-sign", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	requestPath := flags.String("request", "", "public retirement request JSON")
	checkpointPath := flags.String("checkpoint", "", "signed owner off-host recovery checkpoint JSON")
	edPath := flags.String("owner-ed-key", "", "absolute 0600 Ed25519 PKCS#8 private-key PEM")
	pqPath := flags.String("owner-pq-key", "", "absolute 0600 ML-DSA-65 PKCS#8 private-key PEM")
	ttl := flags.Duration("ttl", time.Minute, "authorization lifetime, maximum 5m")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *requestPath == "" || *checkpointPath == "" || *edPath == "" || *pqPath == "" {
		return errors.New("--request, --checkpoint, --owner-ed-key and --owner-pq-key are required; positional arguments are forbidden")
	}
	lifetimeMS := ttl.Milliseconds()
	if lifetimeMS <= 0 || lifetimeMS > 300_000 {
		return errors.New("--ttl must be greater than zero and no more than 5m")
	}

	rawRequest, err := os.ReadFile(*requestPath)
	if err != nil {
		return fmt.Errorf("read retirement request: %w", err)
	}
	request, err := recovery.DecodeRetirementRequest(rawRequest)
	if err != nil {
		return fmt.Errorf("decode retirement request: %w", err)
	}
	rawCheckpoint, err := os.ReadFile(*checkpointPath)
	if err != nil {
		return fmt.Errorf("read recovery checkpoint: %w", err)
	}
	checkpoint, err := recovery.Decode(rawCheckpoint)
	if err != nil {
		return fmt.Errorf("decode recovery checkpoint: %w", err)
	}

	edAny, err := readPrivatePKCS8(*edPath)
	if err != nil {
		return fmt.Errorf("read owner Ed25519 private key: %w", err)
	}
	edPrivate, ok := edAny.(ed25519.PrivateKey)
	if !ok {
		return errors.New("owner Ed25519 key file is not an Ed25519 PKCS#8 private key")
	}
	defer clear(edPrivate)
	pqAny, err := readPrivatePKCS8(*pqPath)
	if err != nil {
		return fmt.Errorf("read owner ML-DSA-65 private key: %w", err)
	}
	pqPrivate, ok := pqAny.(*mldsa.PrivateKey)
	if !ok || pqPrivate.PublicKey().Parameters().String() != mldsa.MLDSA65().String() {
		return errors.New("owner PQ key file is not an ML-DSA-65 PKCS#8 private key")
	}

	signed, err := recovery.IssueRetirementAuthorization(request, checkpoint, edPrivate, pqPrivate,
		time.Now().UnixMilli(), lifetimeMS)
	if err != nil {
		return fmt.Errorf("issue retirement authorization: %w", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err = encoder.Encode(signed); err != nil {
		return fmt.Errorf("encode retirement authorization: %w", err)
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "xmesh-xspv2-retirement-sign:", err)
		os.Exit(1)
	}
}
