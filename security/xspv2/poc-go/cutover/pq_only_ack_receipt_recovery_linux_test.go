//go:build linux

package cutover

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/tls"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestPQOnlyHistoricalReceiptRecoveryUsesDistinctRouteAndExactACK(t *testing.T) {
	dir, signedReceipt, permit, panel, next, late := receiptJournalFixture(t)
	ack, err := ReadJournaledSignedACK(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, roots := pqReceiptTestServerCertificate(t)
	clientCert, clientRoots := pqReceiptTestClientCertificate(t)
	address := launchPQReceiptServer(t, serverCert, clientRoots, []tls.CurveID{tls.X25519MLKEM768},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != signedACKRecoveryEndpoint || r.URL.RawQuery != "" {
				t.Errorf("historical recovery used wrong HTTP domain: %s %s", r.Method, r.URL.String())
				http.Error(w, "wrong recovery domain", http.StatusBadRequest)
				return
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Error("historical recovery changed media type")
				http.Error(w, "wrong media type", http.StatusUnsupportedMediaType)
				return
			}
			if len(r.TLS.PeerCertificates) == 0 {
				t.Error("historical recovery lacked authenticated client identity")
				http.Error(w, "missing client identity", http.StatusUnauthorized)
				return
			}
			if _, ok := r.TLS.PeerCertificates[0].PublicKey.(*mldsa.PublicKey); !ok {
				t.Error("historical recovery used non-ML-DSA client identity")
				http.Error(w, "wrong client identity", http.StatusUnauthorized)
				return
			}
			body, bodyErr := io.ReadAll(io.LimitReader(r.Body, 16*1024+1))
			if bodyErr != nil || !bytes.Equal(body, ack) {
				t.Error("historical recovery did not retransmit exact journaled ACK bytes")
				http.Error(w, "wrong signed ACK", http.StatusBadRequest)
				return
			}
			decoded, decodeErr := Decode(body)
			if decodeErr != nil || decoded.Message.Path != signedACKEndpoint {
				t.Error("historical recovery changed the signed ACK command binding")
				http.Error(w, "wrong signed command binding", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(signedReceipt)
		}))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := RecoverSignedACKReceipt(ctx, address, "nexus.test", roots, clientCert, dir,
		panel, permit, next, permit.Message().ToEpoch, late)
	if err != nil {
		t.Fatalf("strict historical receipt recovery rejected: %v", err)
	}
	if result.RequestID != permit.Message().RequestID || result.ToEpoch != permit.Message().ToEpoch {
		t.Fatalf("historical recovery returned wrong receipt correlation: %+v", result)
	}
	row, err := readCommitReceiptRecord(filepath.Join(dir, commitReceiptJournalName))
	if err != nil || !bytes.Equal(row.SignedReceipt, signedReceipt) {
		t.Fatal("historical recovery did not preserve exact durable receipt bytes")
	}
}

func TestPQOnlyHistoricalReceiptRecoveryRejectsUnsignedSuccess(t *testing.T) {
	dir, _, permit, panel, next, late := receiptJournalFixture(t)
	serverCert, roots := pqReceiptTestServerCertificate(t)
	clientCert, clientRoots := pqReceiptTestClientCertificate(t)
	address := launchPQReceiptServer(t, serverCert, clientRoots, []tls.CurveID{tls.X25519MLKEM768},
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != signedACKRecoveryEndpoint {
				http.Error(w, "wrong recovery domain", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{}"))
		}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := RecoverSignedACKReceipt(ctx, address, "nexus.test", roots, clientCert, dir,
		panel, permit, next, permit.Message().ToEpoch, late); err == nil {
		t.Fatal("unsigned HTTP 200 became historical receipt recovery success")
	}
}
