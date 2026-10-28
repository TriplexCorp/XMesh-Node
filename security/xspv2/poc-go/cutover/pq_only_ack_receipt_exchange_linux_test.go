//go:build linux

package cutover

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func pqReceiptTestServerCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2718),
		Subject:               pkix.Name{CommonName: "nexus.test"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		DNSNames:              []string{"nexus.test"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func pqReceiptTestClientCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(3141),
		Subject:               pkix.Name{CommonName: "node.test"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func pqReceiptClassicalClientCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1618),
		Subject:               pkix.Name{CommonName: "classical-node.test"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func launchPQReceiptServer(
	t *testing.T,
	certificate tls.Certificate,
	clientRoots *x509.CertPool,
	curves []tls.CurveID,
	handler http.Handler,
) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 3 * time.Second,
		TLSConfig: &tls.Config{
			Certificates:           []tls.Certificate{certificate},
			ClientAuth:              tls.RequireAndVerifyClientCert,
			ClientCAs:               clientRoots,
			MinVersion:              tls.VersionTLS13,
			MaxVersion:              tls.VersionTLS13,
			CurvePreferences:        curves,
			SessionTicketsDisabled: true,
		},
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
	return listener.Addr().String()
}

func TestPQOnlyHTTPACKToDurableDualSignedReceipt(t *testing.T) {
	dir, signedReceipt, permit, panel, next, late := receiptJournalFixture(t)
	ack, err := ReadJournaledSignedACK(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, roots := pqReceiptTestServerCertificate(t)
	clientCert, clientRoots := pqReceiptTestClientCertificate(t)
	var requests atomic.Int32
	endpoint := launchPQReceiptServer(t, serverCert, clientRoots, []tls.CurveID{tls.X25519MLKEM768},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests.Add(1)
			if r.Method != http.MethodPost || r.URL.Path != signedACKEndpoint ||
				r.URL.RawQuery != "" || r.Host != "nexus.test" ||
				r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("wrong method/path/authority of ACK: method=%s url=%v host=%q", r.Method, r.URL, r.Host)
				http.Error(w, "unexpected signed request", http.StatusBadRequest)
				return
			}
			if len(r.TLS.PeerCertificates) == 0 {
				t.Error("server did not receive authenticated client certificate")
				http.Error(w, "missing client identity", http.StatusUnauthorized)
				return
			}
			if _, ok := r.TLS.PeerCertificates[0].PublicKey.(*mldsa.PublicKey); !ok {
				t.Error("server received non-ML-DSA client identity")
				http.Error(w, "wrong client identity", http.StatusUnauthorized)
				return
			}
			body, bodyErr := io.ReadAll(io.LimitReader(r.Body, 16*1024+1))
			if bodyErr != nil || !bytes.Equal(body, ack) {
				t.Errorf("signed ACK changed during delivery")
				http.Error(w, "wrong signed ACK", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(signedReceipt)
		}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range 2 {
		result, err := ExchangeSignedACKForReceipt(ctx, endpoint, "nexus.test", roots, clientCert, dir,
			panel, permit, next, permit.Message().ToEpoch, late)
		if err != nil {
			t.Fatalf("authenticated signed ACK exchange rejected: %v", err)
		}
		if result.RequestID != permit.Message().RequestID || result.ToEpoch != permit.Message().ToEpoch {
			t.Fatal("wrong durable receipt correlation")
		}
	}
	if requests.Load() != 2 {
		t.Fatal("did not exercise HTTP idempotent retry")
	}
	row, err := readCommitReceiptRecord(filepath.Join(dir, commitReceiptJournalName))
	if err != nil || !bytes.Equal(row.SignedReceipt, signedReceipt) {
		t.Fatal("dual-signed receipt was not durably journaled")
	}
	if _, err := ReloadVerifiedCommitReceiptForJournal(dir, panel, permit, next,
		permit.Message().ToEpoch, late); err != nil {
		t.Fatalf("restart recovery of signed receipt rejected: %v", err)
	}
}

func TestPQOnlyHTTPExchangeNeverAcceptsDowngradeOrUnsignedResult(t *testing.T) {
	serverCert, roots := pqReceiptTestServerCertificate(t)
	clientCert, clientRoots := pqReceiptTestClientCertificate(t)
	tests := []struct {
		name       string
		curves     []tls.CurveID
		status     int
		response   string
		wrongName  bool
		wrongRoots bool
		redirect   bool
	}{
		{name: "ordinary-X25519", curves: []tls.CurveID{tls.X25519}, status: 200},
		{name: "unsigned-HTTP-200", curves: []tls.CurveID{tls.X25519MLKEM768}, status: 200, response: "{}"},
		{name: "unsigned-HTTP-204", curves: []tls.CurveID{tls.X25519MLKEM768}, status: 204},
		{name: "redirect", curves: []tls.CurveID{tls.X25519MLKEM768}, status: 307, redirect: true},
		{name: "server-error", curves: []tls.CurveID{tls.X25519MLKEM768}, status: 503},
		{name: "hostname-mismatch", curves: []tls.CurveID{tls.X25519MLKEM768}, status: 200, wrongName: true},
		{name: "untrusted-CA", curves: []tls.CurveID{tls.X25519MLKEM768}, status: 200, wrongRoots: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir, _, permit, panel, next, late := receiptJournalFixture(t)
			address := launchPQReceiptServer(t, serverCert, clientRoots, tc.curves, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.redirect {
					w.Header().Set("Location", "/legacy")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.response))
			}))
			name := "nexus.test"
			if tc.wrongName {
				name = "other.example"
			}
			trusted := roots
			if tc.wrongRoots {
				trusted = x509.NewCertPool()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := ExchangeSignedACKForReceipt(ctx, address, name, trusted, clientCert, dir,
				panel, permit, next, permit.Message().ToEpoch, late); err == nil {
				t.Fatal("untrusted / unsigned PQ receipt became authenticated success")
			}
			if _, err := os.Stat(filepath.Join(dir, commitReceiptJournalName)); !os.IsNotExist(err) {
				t.Fatal("receipt persisted despite failed transport or signature verification")
			}
		})
	}
}

func TestPQOnlyHTTPRejectsMissingOrClassicalClientIdentity(t *testing.T) {
	dir, _, permit, panel, next, late := receiptJournalFixture(t)
	serverCert, roots := pqReceiptTestServerCertificate(t)
	_, clientRoots := pqReceiptTestClientCertificate(t)
	address := launchPQReceiptServer(t, serverCert, clientRoots, []tls.CurveID{tls.X25519MLKEM768},
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for name, certificate := range map[string]tls.Certificate{
		"missing":   {},
		"classical": pqReceiptClassicalClientCertificate(t),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ExchangeSignedACKForReceipt(ctx, address, "nexus.test", roots, certificate, dir,
				panel, permit, next, permit.Message().ToEpoch, late); err == nil {
				t.Fatal("non-ML-DSA-65 client identity reached ACK exchange")
			}
		})
	}
}

func TestPQOnlyHTTPRejectsUntrustedEndpointAndWrongFloor(t *testing.T) {
	dir, _, permit, panel, next, late := receiptJournalFixture(t)
	clientCert, _ := pqReceiptTestClientCertificate(t)
	ctx := context.Background()
	for _, endpoint := range []string{
		"https://example.com", "example.com", "example.com:443/legacy", "user@host:443",
		"127.0.0.1:443?allowWeak=1",
	} {
		if _, err := ExchangeSignedACKForReceipt(ctx, endpoint, "nexus.test", nil, clientCert, dir,
			panel, permit, next, permit.Message().ToEpoch, late); err == nil {
			t.Fatalf("untrusted endpoint accepted: %s", endpoint)
		}
	}
	if _, err := ExchangeSignedACKForReceipt(ctx, "127.0.0.1:443", "nexus.test", nil, clientCert,
		dir, panel, permit, next, permit.Message().ToEpoch+1, late); err == nil {
		t.Fatal("unmatched monotonic epoch accepted")
	}
}
