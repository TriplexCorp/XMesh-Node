// Command tlsprobe verifies only the nominated HTTPS TLS termination hop.
// This is a test/diagnostic utility. It does NOT change Node's live TLS policy.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/tlsprobe"
)

func main() {
	address := flag.String("address", "", "TLS endpoint host:port (required)")
	hostname := flag.String("servername", "", "trusted certificate DNS name / SNI (required)")
	ca := flag.String("ca-file", "", "optional PEM CA bundle for lab; empty means system trust")
	clientCertPath := flag.String("client-cert", "", "optional ML-DSA-65 client certificate PEM; requires -client-key")
	clientKeyPath := flag.String("client-key", "", "optional ML-DSA-65 client private key PEM; requires -client-cert")
	timeout := flag.Duration("timeout", 10*time.Second, "connection timeout")
	flag.Parse()
	if *timeout <= 0 || *timeout > 60*time.Second {
		fmt.Fprintln(os.Stderr, "timeout must be (0,60s]")
		os.Exit(2)
	}
	if (*clientCertPath == "") != (*clientKeyPath == "") {
		fmt.Fprintln(os.Stderr, "-client-cert and -client-key must be provided together")
		os.Exit(2)
	}
	var roots *x509.CertPool
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot read CA bundle")
			os.Exit(2)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			fmt.Fprintln(os.Stderr, "invalid CA PEM")
			os.Exit(2)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	encoder := json.NewEncoder(os.Stdout)
	if *clientCertPath != "" {
		clientCertificate, err := tls.LoadX509KeyPair(*clientCertPath, *clientKeyPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot load ML-DSA client certificate/key")
			os.Exit(2)
		}
		report, err := tlsprobe.ProbeMutual(ctx, *address, *hostname, roots, clientCertificate)
		if err != nil {
			fmt.Fprintln(os.Stderr, "XSP-v2 mutual TLS probe FAILED:", err)
			os.Exit(1)
		}
		if err := encoder.Encode(report); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	report, err := tlsprobe.Probe(ctx, *address, *hostname, roots)
	if err != nil {
		fmt.Fprintln(os.Stderr, "XSP-v2 TLS probe FAILED:", err)
		os.Exit(1)
	}
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
