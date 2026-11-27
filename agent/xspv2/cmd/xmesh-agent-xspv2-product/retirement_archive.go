package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	retirement "github.com/TriplexCorp/XMesh-Node/experiments/quota-v2-retirement-attestation"
	"github.com/TriplexCorp/XMesh-Node/security/xspv2/poc-go/keyring"
)

const (
	retirementArchiveDir = "/var/lib/xmesh-ci-first-meter-retirement"
	retirementPolicyDir  = "/var/lib/xmesh-xray-sync"
	retirementMaxBytes   = 8192
)

// Read only the private historical archive and the already pinned original
// policy key. The command cannot accept an alternate path or caller key.
func openRetirementPrivateDir(path string, owner uint32) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	if err := checkRetirementDir(dir, owner); err != nil {
		dir.Close()
		return nil, err
	}
	return dir, nil
}

func checkRetirementDir(dir *os.File, owner uint32) error {
	var st, name syscall.Stat_t
	if err := syscall.Fstat(int(dir.Fd()), &st); err != nil {
		return err
	}
	if err := syscall.Lstat(dir.Name(), &name); err != nil {
		return err
	}
	if st.Mode != syscall.S_IFDIR|0700 || st.Uid != owner ||
		name.Dev != st.Dev || name.Ino != st.Ino || name.Mode != st.Mode || name.Uid != owner {
		return errors.New("historical evidence directory changed or is not private")
	}
	return nil
}

func sameRetirementFile(a, b syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Nlink == b.Nlink &&
		a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size &&
		a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func readRetirementPrivate(dir *os.File, name string, maximum int64, owner uint32) ([]byte, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || maximum <= 0 {
		return nil, errors.New("invalid historical evidence filename")
	}
	if err := checkRetirementDir(dir, owner); err != nil {
		return nil, err
	}
	const flags = syscall.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC | syscall.O_NONBLOCK
	fd, err := syscall.Openat(int(dir.Fd()), name, flags, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var before, after, named syscall.Stat_t
	if err := syscall.Fstat(fd, &before); err != nil {
		return nil, err
	}
	if before.Mode != syscall.S_IFREG|0600 || before.Uid != owner || before.Nlink != 1 ||
		before.Size <= 0 || before.Size > maximum {
		return nil, errors.New("invalid private historical evidence inode or size")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != before.Size {
		return nil, errors.New("historical evidence changed during bounded read")
	}
	if err := syscall.Fstat(fd, &after); err != nil {
		return nil, err
	}
	reopened, err := syscall.Openat(int(dir.Fd()), name, flags, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(reopened)
	if err := syscall.Fstat(reopened, &named); err != nil {
		return nil, err
	}
	if !sameRetirementFile(before, after) || !sameRetirementFile(before, named) {
		return nil, errors.New("historical evidence inode changed")
	}
	if err := checkRetirementDir(dir, owner); err != nil {
		return nil, err
	}
	return raw, nil
}

func retirementRecordName(runtime string) (string, error) {
	raw, err := hex.DecodeString(runtime)
	if err != nil || len(raw) != 32 || hex.EncodeToString(raw) != runtime {
		return "", errors.New("invalid exact retired runtime digest")
	}
	return "retired-" + runtime + ".json", nil
}

func retirementPolicyKey(raw []byte) (ed25519.PublicKey, error) {
	if len(raw) != 65 || raw[64] != '\n' {
		return nil, errors.New("invalid original private Nexus policy pin")
	}
	key, err := hex.DecodeString(string(raw[:64]))
	if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != string(raw[:64]) {
		return nil, errors.New("noncanonical Nexus policy pin")
	}
	return ed25519.PublicKey(key), nil
}

func retirementEnrollment(cfg productConfig, bundle keyring.PublicBundle, activeRaw, requestRaw, receiptRaw []byte) (string, error) {
	if len(bundle.EdPublic) != ed25519.PublicKeySize {
		return "", errors.New("invalid enrolled public key")
	}
	// Verify both ORIGINAL request signatures using the actual opened
	// encrypted vault, then both durable Nexus receipt signatures and exact
	// receipt/request byte binding. This cannot enroll a replacement key.
	request, err := verifySavedActivationRequest(cfg, bundle, requestRaw)
	if err != nil {
		return "", err
	}
	expected, err := validateRecoveredActivationReceipt(cfg, requestRaw, request, receiptRaw)
	if err != nil {
		return "", err
	}
	var actual activeState
	if checkUniqueJSONKeys(activeRaw) != nil || json.Unmarshal(activeRaw, &actual) != nil || actual != expected {
		return "", errors.New("active marker does not exactly bind original signed enrollment")
	}
	canonical, err := json.Marshal(expected)
	if err != nil || !bytes.Equal(activeRaw, append(canonical, '\n')) {
		return "", errors.New("noncanonical active enrollment marker")
	}
	return expected.ReceiptSHA256, nil
}

type retirementPossessionEnvelope struct {
	Algorithm string          `json:"algorithm"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
}

func signRetirementArchive(archive []byte, runtime string, scope retirement.Scope, signer func([]byte) ([]byte, error)) (retirementPossessionEnvelope, error) {
	var zero retirementPossessionEnvelope
	message, err := retirement.Message(archive, scope)
	if err != nil {
		return zero, err
	}
	payload := json.RawMessage(message[len(retirement.Domain):])
	var binding struct {
		RuntimeID string `json:"runtimeId"`
	}
	if json.Unmarshal(payload, &binding) != nil || binding.RuntimeID != runtime {
		return zero, errors.New("archive runtime differs from private record name")
	}
	signature, err := retirement.Sign(archive, scope, signer)
	if err != nil {
		return zero, err
	}
	return retirementPossessionEnvelope{
		Algorithm: "Ed25519", Payload: payload, Signature: hex.EncodeToString(signature),
	}, nil
}

// Explicit root command only; no service, tunnel route, ledger mutation,
// grant or terminal assertion. The archive remains historical and unsigned;
// this detached statement proves enrolled key possession of its exact bytes.
func retirementArchivePossession(panel string, nodeID int64, runtime string) error {
	if os.Geteuid() != 0 {
		return errors.New("historical retirement signing requires root")
	}
	name, err := retirementRecordName(runtime)
	if err != nil {
		return err
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if cfg.PanelURL != panel || cfg.NodeID != nodeID || nodeID <= 0 {
		return errors.New("foreign product enrollment")
	}
	if _, err := operationalRelease(cfg); err != nil {
		return err
	}
	state, err := openRetirementPrivateDir(stateRoot, 0)
	if err != nil {
		return err
	}
	defer state.Close()
	pinDir, err := openRetirementPrivateDir(retirementPolicyDir, 0)
	if err != nil {
		return err
	}
	defer pinDir.Close()
	archiveDir, err := openRetirementPrivateDir(retirementArchiveDir, 0)
	if err != nil {
		return err
	}
	defer archiveDir.Close()
	// The publisher takes an exclusive directory lock through fsync and
	// refuses pending records. Retain a shared lock through signing/output.
	if err := syscall.Flock(int(archiveDir.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		return err
	}
	entries, err := archiveDir.ReadDir(4097)
	if (err != nil && err != io.EOF) || len(entries) > 4096 {
		return errors.New("invalid retirement archive directory inventory")
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".retirement-pending-") {
			return errors.New("interrupted immutable retirement publication")
		}
	}
	type snapshot struct {
		dir     *os.File
		name    string
		maximum int64
		raw     []byte
	}
	files := []snapshot{
		{state, "active.json", maxEnvelopeBytes, nil},
		{state, "activation-request.json", maxEnvelopeBytes, nil},
		{state, "activation-receipt.json", maxEnvelopeBytes, nil},
		{pinDir, "policy-public-key", 65, nil},
		{archiveDir, name, retirementMaxBytes, nil},
	}
	for i := range files {
		file := &files[i]
		file.raw, err = readRetirementPrivate(file.dir, file.name, file.maximum, 0)
		if err != nil {
			return err
		}
	}
	keys, bundle, err := keyring.Open(vaultFile, masterFile)
	if err != nil {
		return err
	}
	activation, err := retirementEnrollment(cfg, bundle, files[0].raw, files[1].raw, files[2].raw)
	if err != nil {
		return err
	}
	pin, err := retirementPolicyKey(files[3].raw)
	if err != nil {
		return err
	}
	scope := retirement.Scope{
		NodeID: nodeID, ActivationReceiptSHA256: activation,
		NodePublicKey: bundle.EdPublic, NexusPublicKey: pin,
	}
	envelope, err := signRetirementArchive(files[4].raw, runtime, scope, func(message []byte) ([]byte, error) {
		edSignature, _, err := keys.Sign(message)
		return edSignature, err
	})
	if err != nil {
		return err
	}
	// Do not emit evidence if the original enrollment or any of the input
	// bytes changed while signing. The panel must independently verify it.
	if err := verifyActive(panel, nodeID); err != nil {
		return err
	}
	for _, file := range files {
		raw, err := readRetirementPrivate(file.dir, file.name, file.maximum, 0)
		if err != nil || !bytes.Equal(raw, file.raw) {
			return errors.New("historical evidence changed before signature export")
		}
	}
	return json.NewEncoder(os.Stdout).Encode(envelope)
}
