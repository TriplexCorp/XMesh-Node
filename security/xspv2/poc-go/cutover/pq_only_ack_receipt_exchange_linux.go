//go:build linux

package cutover

// Experimental XSP-v2 request/receipt transport boundary (Go 1.27 only).
// This remains staging-only and is not linked into the production Go 1.23 Agent.
import (
    "bytes"
    "context"
    "crypto/tls"
    "crypto/x509"
    "errors"
    "fmt"
    "io"
    "mime"
    "net"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "syscall"
    "time"

    "github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/tlsprobe"
)

const signedACKEndpoint = "/api/v2/node/keys/rotation/ack"

// ExchangeSignedACKForReceipt binds the real HTTP exchange to the mandatory
// mutual hybrid TLS dialer used by the isolated Node TLS probe. It retransmits
// EXACT durable, dual-signed ACK bytes, accepts ONLY a verified and durably
// saved dual-signed Nexus receipt, and never treats an HTTP status as commit.
//
// This is a staging building block. The caller must independently verify a
// trusted permit, provision pinned panel_response and next Node keys, ensure
// applied vault/monotonic floor, and supply a correct private journal. This
// function does not bootstrap trust, switch a key epoch, retire old keys, or
// implement a legacy fallback.
//
// Network / security constraints:
//   - always TLS 1.3, X25519MLKEM768, verified server certificate/SNI;
//   - always a validated ML-DSA-65 client certificate via DialStrictMutual;
//   - no proxy, redirects, HTTP downgrade, session resumption or alternative
//     cryptographic curves; no user choice to allow insecure operation;
//   - exact journaled ACK is the request body and signed receipt the response;
//   - no unsigned 200/204 success, JSON errors, oversized replies or
//     different receipt; persistence must finish before reporting success.
func ExchangeSignedACKForReceipt(ctx context.Context, address, serverName string,
    roots *x509.CertPool, clientCertificate tls.Certificate, journalDir string,
    panelPin PinnedPublic, permit VerifiedPermit, nextNodeKeys PinnedPublic,
    minimumEpoch uint64, nowMS int64,
) (VerifiedCommitReceipt, error) {
    var empty VerifiedCommitReceipt
    if ctx == nil || address == "" || serverName == "" {
        return empty, errors.New("missing context or authenticated PQ endpoint")
    }
    host, port, err := net.SplitHostPort(address)
    if err != nil || host == "" || port == "" || strings.ContainsAny(address, "/@?#") {
        return empty, errors.New("PQ endpoint must be a direct host:port")
    }
    if minimumEpoch == 0 || minimumEpoch != permit.Message().ToEpoch {
        return empty, errors.New("applied epoch must match the exact pending cutover")
    }
    if err = checkPrivateDir(journalDir); err != nil { return empty, err }
    lock, err := lockPermit(journalDir)
    if err != nil { return empty, err }
    ack, readErr := checkSavedACKForReceipt(journalDir, permit)
    _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
    _ = lock.Close()
    if readErr != nil { return empty, readErr }
    parsed, err := Decode(ack.SignedACK)
    if err != nil { return empty, fmt.Errorf("saved signed ACK not parseable: %w", err) }
    if parsed.Message.Path != signedACKEndpoint || parsed.Message.Method != http.MethodPost {
        return empty, errors.New("ACK not bound to the expected signed endpoint")
    }
    if _, err = VerifyAppliedACK(ack.SignedACK, permit, nextNodeKeys, parsed.Message.IssuedAtMS); err != nil {
        return empty, fmt.Errorf("saved signed ACK did not reverify: %w", err)
    }
    if ack.ToEpoch != minimumEpoch { return empty, errors.New("ACK epoch not applied") }

    endpoint := "https://" + address + signedACKEndpoint
    request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(ack.SignedACK))
    if err != nil { return empty, err }
    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("Accept", "application/json")
    request.Header.Set("Accept-Encoding", "identity")
    transport := &http.Transport{
        Proxy: nil,
        DisableKeepAlives: true,
        DisableCompression: true,
        ForceAttemptHTTP2: false,
        DialTLSContext: func(dialCtx context.Context, network, target string) (net.Conn, error) {
            if network != "tcp" || target != address {
                return nil, errors.New("unexpected PQ endpoint / redirect")
            }
            return tlsprobe.DialStrictMutual(dialCtx, address, serverName, roots, clientCertificate)
        },
    }
    defer transport.CloseIdleConnections()
    client := &http.Client{
        Transport: transport,
        Timeout: 15 * time.Second,
        CheckRedirect: func(*http.Request, []*http.Request) error {
            return errors.New("XSP-v2 signed ACK redirection forbidden")
        },
    }
    response, err := client.Do(request)
    if err != nil { return empty, fmt.Errorf("PQ-only ACK request failed: %w", err) }
    defer response.Body.Close()
    if response.StatusCode != http.StatusOK {
        return empty, fmt.Errorf("no dual-signed receipt: HTTP %d", response.StatusCode)
    }
    mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
    if err != nil || mediaType != "application/json" || response.Header.Get("Content-Encoding") != "" {
        return empty, errors.New("unsigned or transformed receipt media type")
    }
    signedReceipt, err := io.ReadAll(io.LimitReader(response.Body, 16*1024+1))
    if err != nil { return empty, err }
    if len(signedReceipt) == 0 || len(signedReceipt) > 16*1024 {
        return empty, errors.New("receipt body missing or oversized")
    }
    return PersistVerifiedCommitReceiptForJournal(journalDir, signedReceipt,
        panelPin, permit, nextNodeKeys, minimumEpoch, nowMS)
}

// ReadJournaledSignedACK is not a network authorization primitive. Used by
// staging diagnostics only; it intentionally returns no private keys.
func ReadJournaledSignedACK(dir string) ([]byte, error) {
    if err := checkPrivateDir(dir); err != nil { return nil, err }
    lock, err := lockPermit(dir)
    if err != nil { return nil, err }
    defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() }()
    row, err := readACKRecord(filepath.Join(dir, ackJournalName))
    if err != nil {
        if errors.Is(err, os.ErrNotExist) { return nil, errors.New("no persisted ACK") }
        return nil, err
    }
    return append([]byte(nil), row.SignedACK...), nil
}
