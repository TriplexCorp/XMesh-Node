// Package tlsprobe provides a NON-PRODUCTION XSP-v2 strict hybrid TLS handshake probe.
// The production Go 1.23 Node is NOT linked against this Go 1.27 module.
package tlsprobe

import (
 "context"
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
 TLSVersion string `json:"tlsVersion"`
 NegotiatedGroup string `json:"negotiatedGroup"`
 CertificateVerified bool `json:"certificateVerified"`
 FullHandshake bool `json:"fullHandshake"`
}

// VerifyNegotiated applies a strict, fail-closed policy to the observed state.
// Do not use a status flag or configured groups as a substitute for CurveID.
func VerifyNegotiated(state tls.ConnectionState) error {
 if !state.HandshakeComplete {return errors.New("TLS handshake incomplete")}
 if state.Version!=tls.VersionTLS13 {return fmt.Errorf("TLS downgrade: version 0x%x",state.Version)}
 if state.DidResume {return errors.New("resumed handshake cannot prove a fresh hybrid key exchange")}
 if state.CurveID!=tls.X25519MLKEM768 {return fmt.Errorf("TLS downgrade: negotiated group %s (want X25519MLKEM768)",state.CurveID)}
 if len(state.PeerCertificates)==0||len(state.VerifiedChains)==0 {
  return errors.New("missing verified peer certificate chain")
 }
 return nil
}

// DialStrict is the sole TLS connection constructor intended for a future
// XSP-v2 secure control client. It has NO "legacy", "allow classical" or
// "disable PQ" parameter. If TLS 1.3 + X25519MLKEM768, the verified server
// identity, or a fresh handshake cannot be established, it returns NO
// connection. Callers must NOT retry with a weaker TLS configuration or XMESH1.
//
// This function belongs to the separate Go 1.27 PoC module and is not yet
// linked into the production Go 1.23 agent. roots=nil uses system trust.
// The caller owns the returned connection and must close it.
//
// IMPORTANT: a strict TLS key agreement protects only the examined TLS hop.
// It does not verify XSP/2 dual Ed25519 + ML-DSA-65 message signatures, and
// the HTTPS terminator-to-origin hop needs independent security assessment.
func DialStrict(ctx context.Context, address, serverName string, roots *x509.CertPool) (*tls.Conn, error) {
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
        RootCAs:           roots,
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
    if err := VerifyNegotiated(conn.ConnectionState()); err != nil {
        _ = conn.Close()
        return nil, fmt.Errorf("mandatory hybrid TLS connection rejected: %w", err)
    }
    return conn, nil
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
        TLSVersion:         "TLS1.3",
        NegotiatedGroup:    state.CurveID.String(),
        CertificateVerified: true,
        FullHandshake:      true,
    }, nil
}
