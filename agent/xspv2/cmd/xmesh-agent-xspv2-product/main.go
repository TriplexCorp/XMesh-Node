package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

var (
	version        = "dev"
	sourceRevision = "unknown"
)

const (
	stateRoot         = "/var/lib/xmesh-agent/product"
	vaultRoot         = "/var/lib/xmesh-agent/xsp-v2/keys"
	vaultFile         = vaultRoot + "/node-request.vault"
	masterFile        = vaultRoot + "/node-request.master"
	clientKeyFile     = stateRoot + "/client-key.pem"
	clientCertFile    = stateRoot + "/client.pem"
	serverCAFile      = stateRoot + "/server-ca.pem"
	panelPinFile      = stateRoot + "/panel-pin.json"
	configFile        = stateRoot + "/config.json"
	activeFile        = stateRoot + "/active.json"
	activationRequest = stateRoot + "/activation-request.json"
	activationReceipt = stateRoot + "/activation-receipt.json"
	maxEnvelopeBytes  = 1024 * 1024
	maxPayloadBytes   = 768 * 1024
	suite             = "Ed25519+ML-DSA-65"
	enrollmentDomain  = "XSP2-PRODUCT-ENROLL-V1"
)

var b64 = base64.StdEncoding

type releaseIdentity struct {
	Version        string `json:"version"`
	SourceRevision string `json:"sourceRevision"`
	ArtifactSHA256 string `json:"artifactSha256"`
}

type panelPin struct {
	IssuerID         string `json:"issuerId"`
	Ed25519KeyID     string `json:"ed25519KeyId"`
	MLDSA65KeyID     string `json:"mldsa65KeyId"`
	Ed25519PublicB64 string `json:"ed25519PublicB64"`
	MLDSA65PublicB64 string `json:"mldsa65PublicB64"`
}

type productConfig struct {
	Schema          string          `json:"schema"`
	PanelURL        string          `json:"panelUrl"`
	NodeID          int64           `json:"nodeId"`
	EndpointAddress string          `json:"endpointAddress"`
	ServerName      string          `json:"serverName"`
	TLSSPKISHA256   string          `json:"tlsSpkiSha256"`
	PanelPin        panelPin        `json:"panelPin"`
	ReleaseIdentity releaseIdentity `json:"releaseIdentity"`
}

type activeState struct {
	Schema                     string          `json:"schema"`
	NodeID                     int64           `json:"nodeId"`
	KeyEpoch                   uint64          `json:"keyEpoch"`
	RequestID                  string          `json:"requestId"`
	RequestBindingSHA256       string          `json:"requestBindingSha256"`
	ReceiptSHA256              string          `json:"receiptSha256"`
	ProductionActivation       bool            `json:"productionActivation"`
	StrictPQEnabled            bool            `json:"strictPQEnabled"`
	AutomaticClassicalFallback bool            `json:"automaticClassicalFallback"`
	ReleaseIdentity            releaseIdentity `json:"releaseIdentity"`
	ActivatedAt                string          `json:"activatedAt"`
}

type enrollRequest struct {
	Token               string          `json:"token"`
	NodeID              int64           `json:"nodeId"`
	Purpose             string          `json:"purpose"`
	KeyEpoch            uint64          `json:"keyEpoch"`
	ChallengeHex        string          `json:"challengeHex"`
	Ed25519KeyID        string          `json:"ed25519KeyId"`
	MLDSA65KeyID        string          `json:"mldsa65KeyId"`
	Ed25519PublicB64    string          `json:"ed25519PublicB64"`
	MLDSA65PublicB64    string          `json:"mldsa65PublicB64"`
	Ed25519SignatureB64 string          `json:"ed25519SignatureB64"`
	MLDSA65SignatureB64 string          `json:"mldsa65SignatureB64"`
	TLSPublicKeyB64     string          `json:"tlsPublicKeyB64"`
	ReleaseIdentity     releaseIdentity `json:"releaseIdentity"`
}

type enrollResponse struct {
	NodeID               int64    `json:"nodeId"`
	State                string   `json:"state"`
	StrictPQEnabled      bool     `json:"strictPQEnabled"`
	TLSSPKISHA256        string   `json:"tlsSpkiSha256"`
	ClientCertificatePEM string   `json:"clientCertificatePem"`
	ServerCAPEM          string   `json:"serverCaPem"`
	EndpointAddress      string   `json:"endpointAddress"`
	ServerName           string   `json:"serverName"`
	PanelPin             panelPin `json:"panelPin"`
}

type signatures struct {
	Ed25519 string `json:"ed25519"`
	MLDSA65 string `json:"mldsa65"`
}

type envelope struct {
	Protocol     string     `json:"protocol"`
	Suite        string     `json:"suite"`
	Direction    uint8      `json:"direction"`
	MessageType  string     `json:"messageType"`
	IssuerID     string     `json:"issuerId"`
	NodeID       int64      `json:"nodeId"`
	Method       string     `json:"method"`
	Path         string     `json:"path"`
	Ed25519KeyID string     `json:"ed25519KeyId"`
	MLDSA65KeyID string     `json:"mldsa65KeyId"`
	KeyEpoch     int64      `json:"keyEpoch"`
	IssuedAtMS   int64      `json:"issuedAtMs"`
	ExpiresAtMS  int64      `json:"expiresAtMs"`
	NonceHex     string     `json:"nonceHex"`
	RequestID    string     `json:"requestId"`
	Revision     string     `json:"revision"`
	PayloadB64   string     `json:"payloadB64"`
	Signatures   signatures `json:"signatures"`
}

type parsedEnvelope struct {
	Env          envelope
	Payload      []byte
	SigningInput []byte
	EdSig        []byte
	PQSig        []byte
}

type activationReceiptPayload struct {
	Schema                     string `json:"schema"`
	NodeID                     int64  `json:"nodeId"`
	KeyEpoch                   int64  `json:"keyEpoch"`
	RequestBindingSHA256       string `json:"requestBindingSha256"`
	ProductionActivation       bool   `json:"productionActivation"`
	StrictPQEnabled            bool   `json:"strictPQEnabled"`
	AutomaticClassicalFallback bool   `json:"automaticClassicalFallback"`
	ActivatedAt                string `json:"activatedAt"`
}

type tunnelPayload struct {
	Path    string `json:"path"`
	BodyB64 string `json:"bodyB64"`
}

type tunnelResponsePayload struct {
	Status  int    `json:"status"`
	BodyB64 string `json:"bodyB64"`
}

func selfDigest() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func identity() (releaseIdentity, error) {
	digest, err := selfDigest()
	if err != nil {
		return releaseIdentity{}, err
	}
	if version != "control-v6.0.0" || len(sourceRevision) != 40 || len(digest) != 64 {
		return releaseIdentity{}, errors.New("non-production XMesh v6 identity")
	}
	if _, err := hex.DecodeString(sourceRevision); err != nil {
		return releaseIdentity{}, errors.New("invalid production source revision")
	}
	return releaseIdentity{Version: version, SourceRevision: sourceRevision, ArtifactSHA256: digest}, nil
}

func ensureDirs() error {
	for _, path := range []string{"/var/lib/xmesh-agent", "/var/lib/xmesh-agent/xsp-v2", vaultRoot, stateRoot} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return err
		}
		if err := os.Chmod(path, 0o700); err != nil {
			return err
		}
	}
	return nil
}

func syncParent(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".xmesh-product-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err == nil {
		_, err = tmp.Write(data)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncParent(path)
}

func atomicJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return atomicWrite(path, append(data, '\n'), 0o600)
}

func strictFile(path string, mode os.FileMode) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		return nil, fmt.Errorf("unsafe file mode for %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, fmt.Errorf("unsafe file owner for %s", path)
	}
	return os.ReadFile(path)
}

func randomHex(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func putU64(out *bytes.Buffer, value uint64) {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	out.Write(raw[:])
}

func ascii(out *bytes.Buffer, value string, max int, optional bool) error {
	if len(value) > max || (!optional && value == "") {
		return errors.New("metadata length")
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return errors.New("non-ASCII metadata")
		}
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	out.Write(length[:])
	out.WriteString(value)
	return nil
}

func signingInput(env envelope, payload []byte) ([]byte, error) {
	if env.Protocol != "XSP/2" || env.Suite != suite || env.NodeID <= 0 || env.KeyEpoch <= 0 || env.Method != "POST" ||
		env.IssuedAtMS <= 0 || env.ExpiresAtMS <= env.IssuedAtMS || env.ExpiresAtMS-env.IssuedAtMS > 300000 {
		return nil, errors.New("invalid XSP/2 metadata")
	}
	if len(env.NonceHex) != 32 || strings.ToLower(env.NonceHex) != env.NonceHex {
		return nil, errors.New("invalid XSP/2 nonce")
	}
	nonce, err := hex.DecodeString(env.NonceHex)
	if err != nil || len(nonce) != 16 {
		return nil, errors.New("invalid XSP/2 nonce")
	}
	out := bytes.NewBuffer(make([]byte, 0, 384))
	out.WriteString("XSP2-SIGNED-MESSAGE")
	out.WriteByte(0)
	out.Write([]byte{2, 1, env.Direction})
	for _, field := range []struct {
		value    string
		max      int
		optional bool
	}{
		{env.MessageType, 64, false},
		{env.IssuerID, 64, false},
	} {
		if err := ascii(out, field.value, field.max, field.optional); err != nil {
			return nil, err
		}
	}
	putU64(out, uint64(env.NodeID))
	for _, field := range []struct {
		value    string
		max      int
		optional bool
	}{
		{env.Method, 8, false},
		{env.Path, 256, false},
		{env.Ed25519KeyID, 64, false},
		{env.MLDSA65KeyID, 64, false},
	} {
		if err := ascii(out, field.value, field.max, field.optional); err != nil {
			return nil, err
		}
	}
	putU64(out, uint64(env.KeyEpoch))
	putU64(out, uint64(env.IssuedAtMS))
	putU64(out, uint64(env.ExpiresAtMS))
	out.Write(nonce)
	if err := ascii(out, env.RequestID, 64, false); err != nil {
		return nil, err
	}
	if err := ascii(out, env.Revision, 128, true); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	out.Write(digest[:])
	return out.Bytes(), nil
}

func strictB64(value string, exact, max int) ([]byte, error) {
	decoded, err := b64.Strict().DecodeString(value)
	if err != nil || b64.EncodeToString(decoded) != value || len(decoded) > max {
		return nil, errors.New("noncanonical base64")
	}
	if exact >= 0 && len(decoded) != exact {
		return nil, errors.New("base64 length")
	}
	return decoded, nil
}

func checkUniqueJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	var walk func(int) error
	walk = func(depth int) error {
		nodes++
		if nodes > 512 || depth > 16 {
			return errors.New("JSON complexity limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok || seen[key] {
					return errors.New("duplicate JSON key")
				}
				seen[key] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return errors.New("unbalanced JSON object")
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return errors.New("unbalanced JSON array")
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func parseEnvelope(raw []byte, messageType, path string, direction uint8) (parsedEnvelope, error) {
	var zero parsedEnvelope
	if len(raw) == 0 || len(raw) > maxEnvelopeBytes || checkUniqueJSONKeys(raw) != nil {
		return zero, errors.New("invalid envelope")
	}
	var env envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&env); err != nil {
		return zero, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return zero, errors.New("trailing envelope")
	}
	if env.MessageType != messageType || env.Path != path || env.Direction != direction || env.Method != "POST" {
		return zero, errors.New("endpoint binding")
	}
	payload, err := strictB64(env.PayloadB64, -1, maxPayloadBytes)
	if err != nil {
		return zero, err
	}
	edSig, err := strictB64(env.Signatures.Ed25519, ed25519.SignatureSize, ed25519.SignatureSize)
	if err != nil {
		return zero, err
	}
	pqSig, err := strictB64(env.Signatures.MLDSA65, mldsa.MLDSA65SignatureSize, mldsa.MLDSA65SignatureSize)
	if err != nil {
		return zero, err
	}
	input, err := signingInput(env, payload)
	if err != nil {
		return zero, err
	}
	return parsedEnvelope{Env: env, Payload: payload, SigningInput: input, EdSig: edSig, PQSig: pqSig}, nil
}

func makeEnvelope(keys *keyring.VolatileKeys, pub keyring.PublicBundle, messageType, path, requestID, revision string, payload []byte) ([]byte, error) {
	nonce, err := randomHex(16)
	if err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	env := envelope{
		Protocol:     "XSP/2",
		Suite:        suite,
		Direction:    1,
		MessageType:  messageType,
		IssuerID:     fmt.Sprintf("xmesh-node-%d", pub.NodeID),
		NodeID:       pub.NodeID,
		Method:       "POST",
		Path:         path,
		Ed25519KeyID: pub.EdKeyID,
		MLDSA65KeyID: pub.PQKeyID,
		KeyEpoch:     int64(pub.KeyEpoch),
		IssuedAtMS:   now,
		ExpiresAtMS:  now + 120000,
		NonceHex:     nonce,
		RequestID:    requestID,
		Revision:     revision,
		PayloadB64:   b64.EncodeToString(payload),
	}
	input, err := signingInput(env, payload)
	if err != nil {
		return nil, err
	}
	edSignature, pqSignature, err := keys.Sign(input)
	if err != nil {
		return nil, err
	}
	env.Signatures = signatures{Ed25519: b64.EncodeToString(edSignature), MLDSA65: b64.EncodeToString(pqSignature)}
	return json.Marshal(env)
}

func validatePin(pin panelPin) ([]byte, []byte, error) {
	if pin.IssuerID == "" {
		return nil, nil, errors.New("missing panel issuer")
	}
	edPublic, err := strictB64(pin.Ed25519PublicB64, ed25519.PublicKeySize, ed25519.PublicKeySize)
	if err != nil {
		return nil, nil, err
	}
	pqPublic, err := strictB64(pin.MLDSA65PublicB64, mldsa.MLDSA65PublicKeySize, mldsa.MLDSA65PublicKeySize)
	if err != nil {
		return nil, nil, err
	}
	edHash := sha256.Sum256(edPublic)
	pqHash := sha256.Sum256(pqPublic)
	if pin.Ed25519KeyID != "ed-"+hex.EncodeToString(edHash[:12]) || pin.MLDSA65KeyID != "pq-"+hex.EncodeToString(pqHash[:12]) {
		return nil, nil, errors.New("panel pin key ID mismatch")
	}
	return edPublic, pqPublic, nil
}

func verifyPanelEnvelope(raw []byte, cfg productConfig, messageType, path, requestID string) (parsedEnvelope, error) {
	return verifyPanelEnvelopeWithFreshness(raw, cfg, messageType, path, requestID, true)
}

func verifyDurablePanelEnvelope(raw []byte, cfg productConfig, messageType, path, requestID string) (parsedEnvelope, error) {
	return verifyPanelEnvelopeWithFreshness(raw, cfg, messageType, path, requestID, false)
}

func verifyPanelEnvelopeWithFreshness(raw []byte, cfg productConfig, messageType, path, requestID string, requireFreshness bool) (parsedEnvelope, error) {
	parsed, err := parseEnvelope(raw, messageType, path, 2)
	if err != nil {
		return parsedEnvelope{}, err
	}
	edPublic, pqPublic, err := validatePin(cfg.PanelPin)
	if err != nil {
		return parsedEnvelope{}, err
	}
	if parsed.Env.NodeID != cfg.NodeID || parsed.Env.RequestID != requestID || parsed.Env.IssuerID != cfg.PanelPin.IssuerID ||
		parsed.Env.Ed25519KeyID != cfg.PanelPin.Ed25519KeyID || parsed.Env.MLDSA65KeyID != cfg.PanelPin.MLDSA65KeyID || parsed.Env.KeyEpoch != 1 {
		return parsedEnvelope{}, errors.New("panel response binding rejected")
	}
	if requireFreshness {
		now := time.Now().UnixMilli()
		if now > parsed.Env.ExpiresAtMS || parsed.Env.IssuedAtMS > now+120000 || now > parsed.Env.IssuedAtMS+120000 {
			return parsedEnvelope{}, errors.New("panel response freshness rejected")
		}
	}
	if !ed25519.Verify(edPublic, parsed.SigningInput, parsed.EdSig) {
		return parsedEnvelope{}, errors.New("panel Ed25519 signature rejected")
	}
	pqKey, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pqPublic)
	if err != nil {
		return parsedEnvelope{}, err
	}
	if err := mldsa.Verify(pqKey, parsed.SigningInput, parsed.PQSig, nil); err != nil {
		return parsedEnvelope{}, errors.New("panel ML-DSA-65 signature rejected")
	}
	return parsed, nil
}

func loadTLSKey() (*mldsa.PrivateKey, error) {
	raw, err := strictFile(clientKeyFile, 0o600)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid TLS private key PEM")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := keyAny.(*mldsa.PrivateKey)
	if !ok {
		return nil, errors.New("TLS key is not ML-DSA-65")
	}
	return key, nil
}

func loadConfig() (productConfig, error) {
	var cfg productConfig
	raw, err := strictFile(configFile, 0o600)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Schema != "xmesh-v6-strict-pq-product-config-1" || cfg.NodeID <= 0 || cfg.EndpointAddress == "" || cfg.ServerName == "" {
		return cfg, errors.New("invalid product config")
	}
	if _, _, err := validatePin(cfg.PanelPin); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func hybridClient(cfg productConfig) (*http.Client, error) {
	caRaw, err := strictFile(serverCAFile, 0o600)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caRaw) {
		return nil, errors.New("invalid server CA")
	}
	certRaw, err := strictFile(clientCertFile, 0o600)
	if err != nil {
		return nil, err
	}
	keyRaw, err := strictFile(clientKeyFile, 0o600)
	if err != nil {
		return nil, err
	}
	clientCertificate, err := tls.X509KeyPair(certRaw, keyRaw)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		ServerName:       cfg.ServerName,
		RootCAs:          roots,
		Certificates:     []tls.Certificate{clientCertificate},
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}
	transport := &http.Transport{
		TLSClientConfig:   tlsConfig,
		ForceAttemptHTTP2: false,
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1}).DialContext,
	}
	return &http.Client{Transport: transport, Timeout: 25 * time.Second}, nil
}

func postJSON(client *http.Client, endpoint string, body []byte) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2*1024*1024+1))
	if err != nil {
		return nil, response.StatusCode, err
	}
	if len(raw) > 2*1024*1024 {
		return nil, response.StatusCode, errors.New("response too large")
	}
	return raw, response.StatusCode, nil
}

func enrollmentChallenge(token string, nodeID int64) (string, error) {
	if len(token) != 64 || strings.ToLower(token) != token {
		return "", errors.New("invalid token")
	}
	tokenBytes, err := hex.DecodeString(token)
	if err != nil || len(tokenBytes) != 32 {
		return "", errors.New("invalid token")
	}
	hash := sha256.New()
	hash.Write([]byte(enrollmentDomain))
	hash.Write([]byte{0})
	hash.Write(tokenBytes)
	var nodeRaw [8]byte
	binary.BigEndian.PutUint64(nodeRaw[:], uint64(nodeID))
	hash.Write(nodeRaw[:])
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func bootstrap(panel string, nodeID int64, tokenPath string) error {
	if os.Geteuid() != 0 {
		return errors.New("strict-PQ bootstrap requires root")
	}
	panelHost := strings.TrimPrefix(panel, "https://")
	if !strings.HasPrefix(panel, "https://") || panelHost == "" || strings.ContainsAny(panelHost, "/?#@") || nodeID <= 0 {
		return errors.New("invalid panel origin or node ID")
	}
	if err := ensureDirs(); err != nil {
		return err
	}
	id, err := identity()
	if err != nil {
		return err
	}
	if _, err := os.Stat(activeFile); err == nil {
		return verifyActive(panel, nodeID)
	}
	tokenRaw, err := strictFile(tokenPath, 0o600)
	if err != nil {
		return err
	}
	token := strings.TrimSpace(string(tokenRaw))
	if len(token) != 64 {
		return errors.New("invalid enrollment token")
	}
	if _, err := os.Stat(masterFile); errors.Is(err, os.ErrNotExist) {
		if err := keyring.CreateMasterKey(masterFile); err != nil {
			return err
		}
	}
	var public keyring.PublicBundle
	if _, err := os.Stat(vaultFile); errors.Is(err, os.ErrNotExist) {
		public, err = keyring.Initialize(vaultFile, masterFile, nodeID, "node_request")
	} else {
		public, err = keyring.Description(vaultFile, masterFile)
	}
	if err != nil || public.NodeID != nodeID || public.KeyEpoch != 1 || public.Purpose != "node_request" {
		return errors.New("node dual-key vault identity mismatch")
	}
	challenge, err := enrollmentChallenge(token, nodeID)
	if err != nil {
		return err
	}
	proof, err := keyring.ProveFromEncryptedVault(vaultFile, masterFile, challenge)
	if err != nil {
		return err
	}

	var tlsKey *mldsa.PrivateKey
	if _, err := os.Stat(clientKeyFile); errors.Is(err, os.ErrNotExist) {
		tlsKey, err = mldsa.GenerateKey(mldsa.MLDSA65())
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(tlsKey)
		if err != nil {
			return err
		}
		if err := atomicWrite(clientKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return err
		}
	} else {
		tlsKey, err = loadTLSKey()
		if err != nil {
			return err
		}
	}
	publicDER, err := x509.MarshalPKIXPublicKey(tlsKey.PublicKey())
	if err != nil {
		return err
	}
	request := enrollRequest{
		Token:               token,
		NodeID:              nodeID,
		Purpose:             public.Purpose,
		KeyEpoch:            public.KeyEpoch,
		ChallengeHex:        challenge,
		Ed25519KeyID:        public.EdKeyID,
		MLDSA65KeyID:        public.PQKeyID,
		Ed25519PublicB64:    b64.EncodeToString(public.EdPublic),
		MLDSA65PublicB64:    b64.EncodeToString(public.PQPublic),
		Ed25519SignatureB64: proof.Ed25519SignatureB64,
		MLDSA65SignatureB64: proof.MLDSA65SignatureB64,
		TLSPublicKeyB64:     b64.EncodeToString(publicDER),
		ReleaseIdentity:     id,
	}
	requestRaw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 25 * time.Second}
	responseRaw, status, err := postJSON(client, panel+"/api/v2/product/enroll", requestRaw)
	if err != nil {
		return err
	}
	if status != http.StatusCreated {
		return fmt.Errorf("strict-PQ enrollment rejected: HTTP %d", status)
	}
	var enrolled enrollResponse
	decoder := json.NewDecoder(bytes.NewReader(responseRaw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&enrolled); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing enrollment response")
	}
	if enrolled.NodeID != nodeID || enrolled.State != "enrolled" || enrolled.StrictPQEnabled || enrolled.EndpointAddress == "" || enrolled.ServerName == "" {
		return errors.New("invalid strict-PQ enrollment response")
	}
	if _, _, err := validatePin(enrolled.PanelPin); err != nil {
		return err
	}
	certificateBlock, rest := pem.Decode([]byte(enrolled.ClientCertificatePEM))
	if certificateBlock == nil || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("invalid client certificate")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		return err
	}
	spki := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	if hex.EncodeToString(spki[:]) != enrolled.TLSSPKISHA256 {
		return errors.New("client certificate SPKI mismatch")
	}
	localPublic := tlsKey.PublicKey().Bytes()
	certificatePublic, ok := certificate.PublicKey.(*mldsa.PublicKey)
	if !ok || !bytes.Equal(certificatePublic.Bytes(), localPublic) {
		return errors.New("issued client certificate does not bind local ML-DSA key")
	}
	if err := atomicWrite(clientCertFile, []byte(enrolled.ClientCertificatePEM), 0o600); err != nil {
		return err
	}
	if err := atomicWrite(serverCAFile, []byte(enrolled.ServerCAPEM), 0o600); err != nil {
		return err
	}
	if err := atomicJSON(panelPinFile, enrolled.PanelPin); err != nil {
		return err
	}
	cfg := productConfig{
		Schema:          "xmesh-v6-strict-pq-product-config-1",
		PanelURL:        panel,
		NodeID:          nodeID,
		EndpointAddress: enrolled.EndpointAddress,
		ServerName:      enrolled.ServerName,
		TLSSPKISHA256:   enrolled.TLSSPKISHA256,
		PanelPin:        enrolled.PanelPin,
		ReleaseIdentity: id,
	}
	if err := atomicJSON(configFile, cfg); err != nil {
		return err
	}
	return activate(cfg)
}

func activate(cfg productConfig) error {
	keys, public, err := keyring.Open(vaultFile, masterFile)
	if err != nil {
		return err
	}
	if public.NodeID != cfg.NodeID || public.KeyEpoch != 1 {
		return errors.New("activation key identity mismatch")
	}
	requestID, err := randomHex(16)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"schema":                     "xmesh-v6-strict-pq-activation-request-1",
		"nodeId":                     cfg.NodeID,
		"releaseIdentity":            cfg.ReleaseIdentity,
		"automaticClassicalFallback": false,
	})
	if err != nil {
		return err
	}
	envelopeRaw, err := makeEnvelope(keys, public, "node.product.activate", "/api/v2/product/activate", requestID, cfg.ReleaseIdentity.SourceRevision, payload)
	if err != nil {
		return err
	}
	if err := atomicWrite(activationRequest, envelopeRaw, 0o600); err != nil {
		return err
	}
	client, err := hybridClient(cfg)
	if err != nil {
		return err
	}
	responseRaw, status, err := postJSON(client, "https://"+cfg.EndpointAddress+"/api/v2/product/activate", envelopeRaw)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("strict-PQ activation rejected: HTTP %d", status)
	}
	parsed, err := verifyPanelEnvelope(responseRaw, cfg, "panel.product.activation-receipt", "/api/v2/product/activate", requestID)
	if err != nil {
		return err
	}
	var receipt activationReceiptPayload
	decoder := json.NewDecoder(bytes.NewReader(parsed.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing activation receipt payload")
	}
	requestHash := sha256.Sum256(envelopeRaw)
	if receipt.Schema != "xmesh-v6-strict-pq-activation-receipt-1" || receipt.NodeID != cfg.NodeID || receipt.KeyEpoch != 1 ||
		receipt.RequestBindingSHA256 != hex.EncodeToString(requestHash[:]) || !receipt.ProductionActivation || !receipt.StrictPQEnabled || receipt.AutomaticClassicalFallback {
		return errors.New("strict-PQ activation receipt claim mismatch")
	}
	receiptHash := sha256.Sum256(responseRaw)
	active := activeState{
		Schema:                     "xmesh-v6-strict-pq-active-1",
		NodeID:                     cfg.NodeID,
		KeyEpoch:                   1,
		RequestID:                  requestID,
		RequestBindingSHA256:       hex.EncodeToString(requestHash[:]),
		ReceiptSHA256:              hex.EncodeToString(receiptHash[:]),
		ProductionActivation:       true,
		StrictPQEnabled:            true,
		AutomaticClassicalFallback: false,
		ReleaseIdentity:            cfg.ReleaseIdentity,
		ActivatedAt:                receipt.ActivatedAt,
	}
	if err := atomicWrite(activationReceipt, responseRaw, 0o600); err != nil {
		return err
	}
	if err := atomicJSON(activeFile, active); err != nil {
		return err
	}
	return verifyActive(cfg.PanelURL, cfg.NodeID)
}

func verifyActive(panel string, nodeID int64) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.PanelURL != panel || cfg.NodeID != nodeID {
		return errors.New("strict-PQ active state belongs to another panel or node")
	}
	activeRaw, err := strictFile(activeFile, 0o600)
	if err != nil {
		return err
	}
	var active activeState
	if err := json.Unmarshal(activeRaw, &active); err != nil {
		return err
	}
	if active.Schema != "xmesh-v6-strict-pq-active-1" || active.NodeID != nodeID || active.KeyEpoch != 1 ||
		!active.ProductionActivation || !active.StrictPQEnabled || active.AutomaticClassicalFallback || active.ReleaseIdentity != cfg.ReleaseIdentity {
		return errors.New("strict-PQ active marker invalid")
	}
	if _, err := loadTLSKey(); err != nil {
		return fmt.Errorf("strict-PQ client key unavailable: %w", err)
	}
	if _, err := hybridClient(cfg); err != nil {
		return fmt.Errorf("strict-PQ transport credentials invalid: %w", err)
	}
	receiptRaw, err := strictFile(activationReceipt, 0o600)
	if err != nil {
		return err
	}
	receiptHash := sha256.Sum256(receiptRaw)
	if active.ReceiptSHA256 != hex.EncodeToString(receiptHash[:]) {
		return errors.New("strict-PQ receipt hash mismatch")
	}
	parsed, err := verifyDurablePanelEnvelope(receiptRaw, cfg, "panel.product.activation-receipt", "/api/v2/product/activate", active.RequestID)
	if err != nil {
		return err
	}
	var payload activationReceiptPayload
	if err := json.Unmarshal(parsed.Payload, &payload); err != nil {
		return err
	}
	if payload.Schema != "xmesh-v6-strict-pq-activation-receipt-1" || payload.KeyEpoch != int64(active.KeyEpoch) ||
		!payload.ProductionActivation || !payload.StrictPQEnabled || payload.AutomaticClassicalFallback || payload.NodeID != nodeID ||
		payload.RequestBindingSHA256 != active.RequestBindingSHA256 || payload.ActivatedAt != active.ActivatedAt {
		return errors.New("strict-PQ durable receipt no longer verifies")
	}
	return nil
}

func request(path, bodyPath, outputPath, statusPath string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if err := verifyActive(cfg.PanelURL, cfg.NodeID); err != nil {
		return err
	}
	allowed := map[string]bool{
		"/api/v1/metrics/ingest":      true,
		"/api/v1/node/heartbeat":      true,
		"/api/v1/node/restart/poll":   true,
		"/api/v1/node/restart/ack":    true,
		"/api/v1/node/desired-config": true,
	}
	if !allowed[path] {
		return errors.New("operation is not registered for strict-PQ tunnel")
	}
	body, err := os.ReadFile(bodyPath)
	if err != nil || len(body) > maxPayloadBytes {
		return errors.New("invalid request body")
	}
	keys, public, err := keyring.Open(vaultFile, masterFile)
	if err != nil {
		return err
	}
	innerRaw, err := json.Marshal(tunnelPayload{Path: path, BodyB64: b64.EncodeToString(body)})
	if err != nil {
		return err
	}
	requestID, err := randomHex(16)
	if err != nil {
		return err
	}
	outer, err := makeEnvelope(keys, public, "node.product.tunnel", "/api/v2/product/tunnel", requestID, cfg.ReleaseIdentity.SourceRevision, innerRaw)
	if err != nil {
		return err
	}
	client, err := hybridClient(cfg)
	if err != nil {
		return err
	}
	responseRaw, status, err := postJSON(client, "https://"+cfg.EndpointAddress+"/api/v2/product/tunnel", outer)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("strict-PQ tunnel rejected: HTTP %d", status)
	}
	parsed, err := verifyPanelEnvelope(responseRaw, cfg, "panel.product.tunnel-response", "/api/v2/product/tunnel", requestID)
	if err != nil {
		return err
	}
	var result tunnelResponsePayload
	if err := json.Unmarshal(parsed.Payload, &result); err != nil {
		return err
	}
	responseBody, err := strictB64(result.BodyB64, -1, 2*1024*1024)
	if err != nil {
		return err
	}
	if outputPath != "" {
		if err := atomicWrite(outputPath, responseBody, 0o600); err != nil {
			return err
		}
	} else if _, err := os.Stdout.Write(responseBody); err != nil {
		return err
	}
	if statusPath != "" {
		if err := atomicWrite(statusPath, []byte(fmt.Sprintf("%d\n", result.Status)), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--identity" {
		id, err := identity()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		_ = json.NewEncoder(os.Stdout).Encode(id)
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: xmesh-agent-xspv2-product {bootstrap|verify-active|request}")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "bootstrap":
		flags := flag.NewFlagSet("bootstrap", flag.ExitOnError)
		panel := flags.String("panel", "", "HTTPS panel origin")
		nodeID := flags.Int64("node-id", 0, "node ID")
		tokenFile := flags.String("token-file", "", "root-only token file")
		_ = flags.Parse(os.Args[2:])
		if err := bootstrap(strings.TrimRight(*panel, "/"), *nodeID, *tokenFile); err != nil {
			fmt.Fprintln(os.Stderr, "strict-PQ bootstrap failed:", err)
			os.Exit(1)
		}
		fmt.Println(`{"status":"strict-pq-active","strictPQEnabled":true,"automaticClassicalFallback":false}`)
	case "verify-active":
		flags := flag.NewFlagSet("verify-active", flag.ExitOnError)
		panel := flags.String("panel", "", "HTTPS panel origin")
		nodeID := flags.Int64("node-id", 0, "node ID")
		_ = flags.Parse(os.Args[2:])
		if err := verifyActive(strings.TrimRight(*panel, "/"), *nodeID); err != nil {
			fmt.Fprintln(os.Stderr, "strict-PQ verification failed:", err)
			os.Exit(1)
		}
		fmt.Println(`{"strictPQEnabled":true,"automaticClassicalFallback":false}`)
	case "request":
		flags := flag.NewFlagSet("request", flag.ExitOnError)
		path := flags.String("path", "", "registered panel path")
		body := flags.String("body-file", "", "request body file")
		output := flags.String("output-file", "", "response body file")
		status := flags.String("status-file", "", "HTTP status file")
		_ = flags.Parse(os.Args[2:])
		if err := request(*path, *body, *output, *status); err != nil {
			fmt.Fprintln(os.Stderr, "strict-PQ request failed:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}
