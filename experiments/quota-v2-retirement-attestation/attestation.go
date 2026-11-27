// Package retirementattestation binds archived retirement bytes to an enrolled
// Node's Ed25519 key. It is deliberately dormant: no executable or server
// endpoint calls this package. A signature proves possession of the archive,
// NOT the truth of local kernel observations, current liveness, byte delivery,
// terminal accounting or any authorization to release reserve.
package retirementattestation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

const (
	Domain      = "XMESH_QUOTA_V2_HISTORICAL_RETIREMENT_ARCHIVE_POSSESSION_V1\x00"
	nexusDomain = "XMESH_QUOTA_V2_PUBLIC_TLS_WAL_HEAD_V2\x00"
	maxArchive  = 8192
)

// Scope must come from independent verified enrollment and the pinned Nexus
// policy key, never from the archive or a caller-supplied unverified key.
type Scope struct {
	NodeID                  int64
	ActivationReceiptSHA256 string
	NodePublicKey           ed25519.PublicKey
	NexusPublicKey          ed25519.PublicKey
}

func hexString(value any, size int) bool {
	s, ok := value.(string)
	if !ok || len(s) != size {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func digest(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// All three stored JSON objects have canonical encodings. Round-trip the
// parsed tree with exact integer tokens: duplicate keys, alternative escapes,
// whitespace and additional trailing values cannot become signed aliases.
func object(raw []byte, newline bool) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > maxArchive {
		return nil, errors.New("invalid historical object size")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return nil, errors.New("invalid historical object")
	}
	encoded, err := json.Marshal(obj)
	if newline {
		encoded = append(encoded, '\n')
	}
	if err != nil || !bytes.Equal(raw, encoded) {
		return nil, errors.New("noncanonical or ambiguous historical object")
	}
	return obj, nil
}

func shape(obj map[string]any, names string) bool {
	fields := strings.Fields(names)
	if len(obj) != len(fields) {
		return false
	}
	for _, name := range fields {
		if _, ok := obj[name]; !ok {
			return false
		}
	}
	return true
}

func str(obj map[string]any, key string) string {
	s, _ := obj[key].(string)
	return s
}

func integer(obj map[string]any, key string) int64 {
	n, ok := obj[key].(json.Number)
	if !ok {
		return -1
	}
	v, err := n.Int64()
	if err != nil || strconv.FormatInt(v, 10) != n.String() {
		return -1
	}
	return v
}

func flags(obj map[string]any, keys string, expected bool) bool {
	for _, key := range strings.Fields(keys) {
		b, ok := obj[key].(bool)
		if !ok || b != expected {
			return false
		}
	}
	return true
}

func digests(obj map[string]any, keys string) bool {
	for _, key := range strings.Fields(keys) {
		if !hexString(obj[key], 64) {
			return false
		}
	}
	return true
}

func validateObservation(obs map[string]any, scope Scope) bool {
	if !shape(obs, "schemaVersion kind nodeId runtimeId containerId startedAt signedWalReadbackSha256 inventorySha256 committedChargeHeadsSha256 durableUserDenials originalMeterPidfdExited lifetimeLockReleased finalMeterVerified settlementEligible canResume refundableBytes retiredLedgerSha256 deliveredBytesVerified nodeSignatureVerified canServePublic canStart") ||
		integer(obs, "schemaVersion") != 1 || integer(obs, "nodeId") != scope.NodeID ||
		str(obs, "kind") != "xmesh.quota-v2.nonfinal-first-meter-retirement" ||
		!digests(obs, "runtimeId containerId signedWalReadbackSha256 inventorySha256 committedChargeHeadsSha256 retiredLedgerSha256") ||
		!flags(obs, "originalMeterPidfdExited lifetimeLockReleased", true) ||
		!flags(obs, "finalMeterVerified settlementEligible canResume deliveredBytesVerified nodeSignatureVerified canServePublic canStart", false) ||
		integer(obs, "refundableBytes") != 0 {
		return false
	}
	started := str(obs, "startedAt")
	if len(started) < 20 || len(started) > 64 || !strings.HasSuffix(started, "Z") {
		return false
	}
	if _, err := time.Parse(time.RFC3339Nano, started); err != nil {
		return false
	}
	denials, ok := obs["durableUserDenials"].(map[string]any)
	if !ok || len(denials) == 0 || len(denials) > 4096 {
		return false
	}
	for user, hash := range denials {
		id, err := strconv.ParseInt(user, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != user || !hexString(hash, 64) {
			return false
		}
	}
	return true
}

func validateNexus(raw []byte, obs map[string]any, scope Scope) (map[string]any, error) {
	outer, err := object(raw, false)
	if err != nil || !shape(outer, "signedEnvelope") || digest(raw) != str(obs, "signedWalReadbackSha256") {
		return nil, errors.New("foreign historical Nexus response")
	}
	doc, err := object([]byte(str(outer, "signedEnvelope")), true)
	if err != nil || !shape(doc, "algorithm payload signature") ||
		str(doc, "algorithm") != "Ed25519" || !hexString(doc["signature"], 128) {
		return nil, errors.New("invalid historical Nexus envelope")
	}
	p, ok := doc["payload"].(map[string]any)
	if !ok || !shape(p, "schemaVersion kind nodeId userId activationReceiptSha256 genesisPolicySha256 runtimeId profileRevision capRosterSha256 challenge containerId hostPid startedAt issuedAtMs validUntilMs historyState inventorySequence inventorySha256 inventoryTailDigest committedChargeStreamCount committedChargeHeadsSha256 preBootstrapHistoryCompletenessVerified liveMeterVerified finalMeterVerified canServePublic canSpend canStart canResume authorizedBytes refundableBytes") ||
		integer(p, "schemaVersion") != 2 || str(p, "kind") != "xmesh.quota-v2.public-tls-wal-head" ||
		integer(p, "nodeId") != scope.NodeID || integer(p, "userId") <= 0 || integer(p, "hostPid") <= 1 ||
		str(p, "activationReceiptSha256") != scope.ActivationReceiptSHA256 ||
		!digests(p, "activationReceiptSha256 genesisPolicySha256 runtimeId profileRevision capRosterSha256 challenge containerId inventorySha256 inventoryTailDigest committedChargeHeadsSha256") ||
		!flags(p, "preBootstrapHistoryCompletenessVerified liveMeterVerified finalMeterVerified canServePublic canSpend canStart canResume", false) ||
		integer(p, "authorizedBytes") != 0 || integer(p, "refundableBytes") != 0 {
		return nil, errors.New("foreign or authorizing historical Nexus payload")
	}
	for _, key := range strings.Fields("runtimeId containerId startedAt inventorySha256 committedChargeHeadsSha256") {
		if str(p, key) != str(obs, key) {
			return nil, errors.New("historical Nexus payload differs from archived observation")
		}
	}
	denials := obs["durableUserDenials"].(map[string]any)
	if _, ok := denials[strconv.FormatInt(integer(p, "userId"), 10)]; !ok {
		return nil, errors.New("Nexus witness user absent from archived denials")
	}
	seq, count := integer(p, "inventorySequence"), integer(p, "committedChargeStreamCount")
	history := str(p, "historyState")
	if seq < 0 || seq > 4096 || count != seq ||
		(seq == 0 && history != "empty_remote_history") ||
		(seq > 0 && history != "committed_birth_index") {
		return nil, errors.New("incomplete historical Nexus committed charge heads")
	}
	if seq == 0 && (str(p, "inventorySha256") != digest(nil) ||
		str(p, "inventoryTailDigest") != strings.Repeat("0", 64) ||
		str(p, "committedChargeHeadsSha256") != digest([]byte("[]"))) {
		return nil, errors.New("inconsistent signed empty history")
	}
	issued, expires := integer(p, "issuedAtMs"), integer(p, "validUntilMs")
	if issued <= 0 || expires <= issued || expires-issued > 7000 {
		return nil, errors.New("invalid historical signature lifetime")
	}
	// Historical replay is intentional here. This is not a present-time
	// freshness check and cannot reconstruct the live pidfd observation.
	payload, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(str(doc, "signature"))
	if err != nil || !ed25519.Verify(scope.NexusPublicKey, append([]byte(nexusDomain), payload...), sig) {
		return nil, errors.New("historical Nexus signature verification failed")
	}
	return p, nil
}

// Message reconstructs a domain-separated, nonauthorizing statement bound to
// the exact archived bytes and independently enrolled identities. The result
// never asserts that the Node key verified the kernel/WAL facts themselves.
func Message(archive []byte, scope Scope) ([]byte, error) {
	if scope.NodeID <= 0 || !hexString(scope.ActivationReceiptSHA256, 64) ||
		len(scope.NodePublicKey) != ed25519.PublicKeySize ||
		len(scope.NexusPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("independently verified enrollment scope required")
	}
	record, err := object(archive, true)
	if err != nil || !shape(record, "observation nexusResponse") {
		return nil, errors.New("invalid historical retirement archive")
	}
	obs, ok := record["observation"].(map[string]any)
	if !ok || !validateObservation(obs, scope) {
		return nil, errors.New("invalid nonfinal retirement observation")
	}
	nexus, err := validateNexus([]byte(str(record, "nexusResponse")), obs, scope)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{
		"schemaVersion":             1,
		"kind":                      "xmesh.quota-v2.historical-retirement-archive-possession",
		"nodeId":                    scope.NodeID,
		"activationReceiptSha256":   scope.ActivationReceiptSHA256,
		"nodePublicKey":             hex.EncodeToString(scope.NodePublicKey),
		"nexusPublicKey":            hex.EncodeToString(scope.NexusPublicKey),
		"runtimeId":                 str(obs, "runtimeId"),
		"archiveSha256":             digest(archive),
		"signedWalReadbackSha256":   str(obs, "signedWalReadbackSha256"),
		"nexusIssuedAtMs":           integer(nexus, "issuedAtMs"),
		"nexusValidUntilMs":         integer(nexus, "validUntilMs"),
		"archivePossessionOnly":     true,
		"localObservationsVerified": false,
		"liveMeterVerified":         false,
		"deliveredBytesVerified":    false,
		"finalMeterVerified":        false,
		"settlementEligible":        false,
		"canServePublic":            false,
		"canSpend":                  false,
		"canStart":                  false,
		"canResume":                 false,
		"authorizedBytes":           0,
		"refundableBytes":           0,
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return append([]byte(Domain), raw...), nil
}

// Sign accepts a future enrolled-key signer, not raw private key material.
// It validates the resulting signature against the independently pinned Node
// key, so an accidental compatibility-key signer cannot produce a receipt.
func Sign(archive []byte, scope Scope, signer func([]byte) ([]byte, error)) ([]byte, error) {
	// Freeze pinned identities before invoking external signer code.
	scope.NodePublicKey = bytes.Clone(scope.NodePublicKey)
	scope.NexusPublicKey = bytes.Clone(scope.NexusPublicKey)
	message, err := Message(archive, scope)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, errors.New("missing enrolled Node signer")
	}
	signature, err := signer(bytes.Clone(message))
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(scope.NodePublicKey, message, signature) {
		return nil, errors.New("signer did not use enrolled Node key")
	}
	return bytes.Clone(signature), nil
}

// Verify re-derives the entire message from the archive and external scope.
// The caller must separately verify physical exit and committed SQL evidence.
func Verify(archive []byte, scope Scope, signature []byte) error {
	message, err := Message(archive, scope)
	if err != nil {
		return err
	}
	if !ed25519.Verify(scope.NodePublicKey, message, signature) {
		return errors.New("archive possession signature verification failed")
	}
	return nil
}
