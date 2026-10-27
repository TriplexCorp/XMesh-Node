// Package tlsprobe provides a NON-PRODUCTION XSP-v2 strict hybrid TLS handshake probe.
// The production Go 1.23 Node is NOT linked against this Go 1.27 module.
package tlsprobe

import (
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Report confirms only THIS Node-to-TLS-terminator handshake, not any
// terminator-to-origin hop, XSP signatures, key pinning or deployment status.
type Report struct {
	TLSVersion          string `json:"tlsVersion"`
	NegotiatedGroup     string `json:"negotiatedGroup"`
	CertificateVerified bool   `json:"certificateVerified"`
	FullHandshake       bool   `json:"fullHandshake"`
}

// MutualReport additionally confirms that the strict server requested and the
// client presented the configured ML-DSA-65 certificate during this handshake.
type MutualReport struct {
	Report
	ClientCertificateAlgorithm string `json:"clientCertificateAlgorithm"`
	ClientCertificatePresented bool   `json:"clientCertificatePresented"`
}

// VerifyNegotiated applies a strict, fail-closed policy to the observed state.
// Do not use a status flag or configured groups as a substitute for CurveID.
func VerifyNegotiated(state tls.ConnectionState) error {
	if !state.HandshakeComplete {
		return errors.New("TLS handshake incomplete")
	}
	if state.Version != tls.VersionTLS13 {
		return fmt.Errorf("TLS downgrade: version 0x%x", state.Version)
	}
	if state.DidResume {
		return errors.New("resumed handshake cannot prove a fresh hybrid key exchange")
	}
	if state.CurveID != tls.X25519MLKEM768 {
		return fmt.Errorf("TLS downgrade: negotiated group %s (want X25519MLKEM768)", state.CurveID)
	}
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return errors.New("missing verified peer certificate chain")
	}
	return nil
}

func clientCertificateLeaf(cert tls.Certificate) (*x509.Certificate, error) {
	if len(cert.Certificate) == 0 || cert.PrivateKey == nil {
		return nil, errors.New("client certificate and private key are required")
	}
	if cert.Leaf != nil {
		return cert.Leaf, nil
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse client certificate: %w", err)
	}
	return leaf, nil
}

func requireMLDSA65ClientCertificate(cert tls.Certificate) error {
	leaf, err := clientCertificateLeaf(cert)
	if err != nil {
		return err
	}
	public, ok := leaf.PublicKey.(*mldsa.PublicKey)
	if !ok || public.Parameters().String() != mldsa.MLDSA65().String() {
		return errors.New("client certificate must use ML-DSA-65")
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return errors.New("client private key does not implement crypto.Signer")
	}
	privatePublic, ok := signer.Public().(*mldsa.PublicKey)
	if !ok || !privatePublic.Equal(public) {
		return errors.New("client ML-DSA-65 private key does not match certificate")
	}
	return nil
}

// VerifyMutualNegotiated additionally proves that the ML-DSA-65 client
// certificate was actually presented, not merely configured on the client.
// TLS 1.3 server-side acceptance must be observed by a subsequent application
// read/write because a rejecting server alert can arrive after client Finished.
func VerifyMutualNegotiated(state tls.ConnectionState) error {
	if err := VerifyNegotiated(state); err != nil {
		return err
	}
	if len(state.LocalCertificate) == 0 {
		return errors.New("client certificate was not presented during the handshake")
	}
	leaf, err := x509.ParseCertificate(state.LocalCertificate[0])
	if err != nil {
		return fmt.Errorf("parse presented client certificate: %w", err)
	}
	public, ok := leaf.PublicKey.(*mldsa.PublicKey)
	if !ok || public.Parameters().String() != mldsa.MLDSA65().String() {
		return errors.New("presented client certificate is not ML-DSA-65")
	}
	return nil
}

func dialStrict(
	ctx context.Context,
	address, serverName string,
	roots *x509.CertPool,
	certificates []tls.Certificate,
	mutual bool,
) (*tls.Conn, error) {
	if strings.TrimSpace(serverName) == "" || strings.TrimSpace(address) == "" {
		return nil, errors.New("address and serverName are required")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return nil, errors.New("address must be host:port")
	}
	config := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
		ServerName:         serverName,
		RootCAs:            roots,
		Certificates:       certificates,
		ClientSessionCache: nil,
	}
	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 8 * time.Second},
		Config:    config,
	}
	raw, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("mandatory hybrid TLS connection rejected: %w", err)
	}
	conn, ok := raw.(*tls.Conn)
	if !ok {
		_ = raw.Close()
		return nil, errors.New("verified TLS connection state unavailable")
	}
	state := conn.ConnectionState()
	if mutual {
		err = VerifyMutualNegotiated(state)
	} else {
		err = VerifyNegotiated(state)
	}
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("mandatory hybrid TLS connection rejected: %w", err)
	}
	return conn, nil
}

// DialStrict is the sole server-authenticated TLS connection constructor
// intended for a future XSP-v2 secure control client. It has NO "legacy",
// "allow classical" or "disable PQ" parameter. If TLS 1.3 +
// X25519MLKEM768, the verified server identity, or a fresh handshake cannot be
// established, it returns NO connection. Callers must NOT retry with a weaker
// TLS configuration or XMESH1.
//
// This function belongs to the separate Go 1.27 PoC module and is not yet
// linked into the production Go 1.23 agent. roots=nil uses system trust.
// The caller owns the returned connection and must close it.
//
// IMPORTANT: a strict TLS key agreement protects only the examined TLS hop.
// It does not verify XSP/2 dual Ed25519 + ML-DSA-65 message signatures, and
// the HTTPS terminator-to-origin hop needs independent security assessment.
func DialStrict(ctx context.Context, address, serverName string, roots *x509.CertPool) (*tls.Conn, error) {
	return dialStrict(ctx, address, serverName, roots, nil, false)
}

// DialStrictMutual adds a mandatory ML-DSA-65 client certificate to the exact
// same fail-closed hybrid transport policy. It rejects other client key types
// before dialing and verifies after the handshake that the certificate was
// actually presented. A caller that needs proof of server-side acceptance must
// perform an authenticated application roundtrip on the returned connection.
// It does not authorize an application request by itself.
func DialStrictMutual(
	ctx context.Context,
	address, serverName string,
	roots *x509.CertPool,
	clientCertificate tls.Certificate,
) (*tls.Conn, error) {
	if err := requireMLDSA65ClientCertificate(clientCertificate); err != nil {
		return nil, fmt.Errorf("mandatory ML-DSA-65 client identity rejected: %w", err)
	}
	return dialStrict(ctx, address, serverName, roots, []tls.Certificate{clientCertificate}, true)
}

// Probe tests the identical strict dial path used by future XSP/2 clients.
// It closes the connection without sending HTTP traffic or changing Node
// state. A positive result confirms ONLY one authenticated TLS hop.
func Probe(ctx context.Context, address, serverName string, roots *x509.CertPool) (Report, error) {
	conn, err := DialStrict(ctx, address, serverName, roots)
	if err != nil {
		return Report{}, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	return Report{
		TLSVersion:          "TLS1.3",
		NegotiatedGroup:     state.CurveID.String(),
		CertificateVerified: true,
		FullHandshake:       true,
	}, nil
}

// ProbeMutual proves the same strict server-authenticated hybrid TLS hop plus
// actual ML-DSA-65 client-certificate presentation. It sends no HTTP request.
func ProbeMutual(
	ctx context.Context,
	address, serverName string,
	roots *x509.CertPool,
	clientCertificate tls.Certificate,
) (MutualReport, error) {
	conn, err := DialStrictMutual(ctx, address, serverName, roots, clientCertificate)
	if err != nil {
		return MutualReport{}, err
	}
	defer conn.Close()
	state := conn.ConnectionState()
	return MutualReport{
		Report: Report{
			TLSVersion:          "TLS1.3",
			NegotiatedGroup:     state.CurveID.String(),
			CertificateVerified: true,
			FullHandshake:       true,
		},
		ClientCertificateAlgorithm: "ML-DSA-65",
		ClientCertificatePresented: true,
	}, nil
}
