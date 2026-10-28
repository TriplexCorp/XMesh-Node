//go:build linux

package runtime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"

	"github.com/TriplexCorp/XMesh-Node/agent/xspv2/state"
	cutover "github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/cutover"
)

type Endpoint struct {
	Address    string
	ServerName string
}

type Pin = cutover.PinnedPublic
type Permit = cutover.VerifiedPermit
type Receipt = cutover.VerifiedCommitReceipt

func (endpoint Endpoint) Validate() error {
	host, port, err := net.SplitHostPort(endpoint.Address)
	if err != nil || host == "" || port == "" || strings.ContainsAny(endpoint.Address, "/@?#") {
		return errors.New("XSP-v2 address must be a direct host:port")
	}
	if endpoint.ServerName == "" || strings.ContainsAny(endpoint.ServerName, "/:@?#") {
		return errors.New("XSP-v2 server name must be an authenticated DNS authority")
	}
	return nil
}

// Exchange reuses the already-proven cutover implementation. This package is
// deliberately an Agent integration bridge, not another protocol/state machine.
func Exchange(ctx context.Context, endpoint Endpoint, roots *x509.CertPool,
	clientCertificate tls.Certificate, layout state.Layout, panel Pin, permit Permit,
	next Pin, minimumEpoch uint64, nowMS int64,
) (Receipt, error) {
	if err := endpoint.Validate(); err != nil {
		return Receipt{}, err
	}
	if layout.Journal == "" {
		return Receipt{}, errors.New("private Agent journal is required")
	}
	return cutover.ExchangeSignedACKForReceipt(ctx, endpoint.Address, endpoint.ServerName,
		roots, clientCertificate, layout.Journal, panel, permit, next, minimumEpoch, nowMS)
}

// Recover is the exact historical immutable-receipt path. It never creates a
// new ACK, advances an epoch, retires keys, or falls back to XMESH1.
func Recover(ctx context.Context, endpoint Endpoint, roots *x509.CertPool,
	clientCertificate tls.Certificate, layout state.Layout, panel Pin, permit Permit,
	next Pin, minimumEpoch uint64, nowMS int64,
) (Receipt, error) {
	if err := endpoint.Validate(); err != nil {
		return Receipt{}, err
	}
	if layout.Journal == "" {
		return Receipt{}, errors.New("private Agent journal is required")
	}
	return cutover.RecoverSignedACKReceipt(ctx, endpoint.Address, endpoint.ServerName,
		roots, clientCertificate, layout.Journal, panel, permit, next, minimumEpoch, nowMS)
}
