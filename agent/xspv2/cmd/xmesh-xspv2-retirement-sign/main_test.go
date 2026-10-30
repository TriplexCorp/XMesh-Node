//go:build linux

package main

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func writePKCS8(t *testing.T, path string, key any, mode os.FileMode) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err = os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestReadPrivatePKCS8RequiresPrivateCanonicalRealPath(t *testing.T) {
	_, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	good := filepath.Join(root, "owner-ed.pem")
	writePKCS8(t, good, edPrivate, 0o600)
	parsed, err := readPrivatePKCS8(good)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsed.(ed25519.PrivateKey); !ok {
		t.Fatal("Ed25519 PKCS#8 parsed as wrong key type")
	}

	broad := filepath.Join(root, "broad.pem")
	writePKCS8(t, broad, edPrivate, 0o644)
	if _, err = readPrivatePKCS8(broad); err == nil {
		t.Fatal("mode 0644 owner private key accepted")
	}

	relative := filepath.Base(good)
	if _, err = readPrivatePKCS8(relative); err == nil {
		t.Fatal("relative owner private-key path accepted")
	}

	realDir := filepath.Join(root, "real")
	if err = os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(realDir, "key.pem")
	writePKCS8(t, inside, edPrivate, 0o600)
	linkDir := filepath.Join(root, "link")
	if err = os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if _, err = readPrivatePKCS8(filepath.Join(linkDir, "key.pem")); err == nil {
		t.Fatal("owner private key below symlinked directory accepted")
	}
}

func TestReadPrivatePKCS8ParsesMLDSA65AndRejectsMultiplePEMBlocks(t *testing.T) {
	pqPrivate, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	pqPath := filepath.Join(root, "owner-pq.pem")
	writePKCS8(t, pqPath, pqPrivate, 0o600)
	parsed, err := readPrivatePKCS8(pqPath)
	if err != nil {
		t.Fatal(err)
	}
	pq, ok := parsed.(*mldsa.PrivateKey)
	if !ok || pq.PublicKey().Parameters().String() != mldsa.MLDSA65().String() {
		t.Fatal("ML-DSA-65 PKCS#8 parsed as wrong key type")
	}

	raw, err := os.ReadFile(pqPath)
	if err != nil {
		t.Fatal(err)
	}
	double := filepath.Join(root, "double.pem")
	if err = os.WriteFile(double, append(append([]byte(nil), raw...), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = readPrivatePKCS8(double); err == nil {
		t.Fatal("multiple owner private-key PEM blocks accepted")
	}
}
