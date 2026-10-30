package keyring

// TEST/STAGING only. Root-owned, mode-0600 AES-256-GCM wrapping-key file is
// separate from the encrypted Ed25519/ML-DSA seed file. NOT an HSM/KMS.
// Deleting/restoring both files as root can roll back epochs. Never deploy
// without independent rollback protection and reviewed recovery procedures.
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

type sealedFile struct {
	Version    int          `json:"version"`
	Public     PublicBundle `json:"public"`
	Nonce      string       `json:"nonce"`
	Ciphertext string       `json:"ciphertext"`
}

const vaultVersion = 1

func secureFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return nil, errors.New("private file must be regular mode 0600")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("private file owner mismatch")
	}
	return os.ReadFile(path)
}

func secureDir(file string) error {
	dir, err := os.Lstat(filepath.Dir(file))
	if err != nil {
		return err
	}
	if !dir.IsDir() || dir.Mode().Perm() != 0o700 {
		return errors.New("vault directory must be mode 0700")
	}
	stat, ok := dir.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("vault directory owner mismatch")
	}
	return nil
}

func syncParentDir(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func atomicFile(path string, raw []byte) error {
	if err := secureDir(path); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".xsp-sealed-")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0o600); err == nil {
		_, err = tmp.Write(raw)
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
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	return syncParentDir(path)
}

func floorPath(vault string) string { return vault + ".min-epoch" }

func readFloor(path string) (uint64, error) {
	data, err := secureFile(floorPath(path))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	number, err := strconv.ParseUint(string(data), 10, 64)
	if err != nil || number == 0 {
		return 0, errors.New("invalid persisted key epoch floor")
	}
	return number, nil
}

func updateFloor(path string, epoch uint64) error {
	prior, err := readFloor(path)
	if err != nil {
		return err
	}
	if epoch < prior || epoch == 0 {
		return errors.New("key epoch rollback refused")
	}
	return atomicFile(floorPath(path), []byte(strconv.FormatUint(epoch, 10)))
}

// CreateMasterKey creates ONLY an external, random root-owner wrapping key.
// It will never replace an existing wrapping key. Losing it loses access.
func CreateMasterKey(path string) error {
	if err := secureDir(path); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	raw := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, raw)
	if err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	clear(raw)
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
		if err != nil {
			return err
		}
		return closeErr
	}
	// A successful file fsync alone does not guarantee that the newly created
	// directory entry survives abrupt power loss on every supported filesystem.
	// Do not report provisioning success until the parent directory is durable.
	if err = syncParentDir(path); err != nil {
		return err
	}
	return nil
}

func masterLocked(path string, exclusive bool) (*os.File, []byte, error) {
	if err := secureDir(path); err != nil {
		return nil, nil, err
	}
	if _, err := secureFile(path); err != nil {
		return nil, nil, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, err
	}
	lock := syscall.LOCK_SH
	if exclusive {
		lock = syscall.LOCK_EX
	}
	if err = syscall.Flock(int(file.Fd()), lock); err != nil {
		file.Close()
		return nil, nil, err
	}
	// Re-check to reject a replaced, symlinked or relaxed-permissions master.
	content, err := secureFile(path)
	if err != nil || len(content) != 32 {
		file.Close()
		return nil, nil, errors.New("master key invalid")
	}
	return file, content, nil
}

func seal(keys *VolatileKeys, pub PublicBundle, master []byte) ([]byte, error) {
	if keys == nil || len(keys.ed) != ed25519.PrivateKeySize || keys.pq == nil {
		return nil, errors.New("missing key material")
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	payload := append(append([]byte(nil), keys.ed.Seed()...), keys.pq.Bytes()...)
	defer clear(payload)
	aad, err := json.Marshal(pub)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, payload, aad)
	return json.Marshal(sealedFile{
		Version:    vaultVersion,
		Public:     pub,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	})
}

func openWithMaster(path string, master []byte) (*VolatileKeys, PublicBundle, error) {
	var empty PublicBundle
	raw, err := secureFile(path)
	if err != nil {
		return nil, empty, err
	}
	if len(raw) > 16384 {
		return nil, empty, errors.New("oversized vault")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value sealedFile
	if err = decoder.Decode(&value); err != nil {
		return nil, empty, err
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return nil, empty, errors.New("trailing vault data")
	}
	if value.Version != vaultVersion || value.Public.NodeID <= 0 || value.Public.KeyEpoch == 0 ||
		(value.Public.Purpose != "node_request" && value.Public.Purpose != "panel_response") {
		return nil, empty, errors.New("invalid vault metadata")
	}
	floor, err := readFloor(path)
	if err != nil {
		return nil, empty, err
	}
	if value.Public.KeyEpoch < floor {
		return nil, empty, errors.New("persisted epoch floor rejected old vault")
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(value.Nonce)
	if err != nil {
		return nil, empty, err
	}
	ciphertext, err := base64.StdEncoding.Strict().DecodeString(value.Ciphertext)
	if err != nil {
		return nil, empty, err
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, empty, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, empty, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, empty, errors.New("invalid nonce length")
	}
	aad, err := json.Marshal(value.Public)
	if err != nil {
		return nil, empty, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, empty, errors.New("vault authentication failed")
	}
	defer clear(plaintext)
	if len(plaintext) != 64 {
		return nil, empty, errors.New("invalid decrypted seed length")
	}
	ed := ed25519.NewKeyFromSeed(plaintext[:32])
	pq, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), plaintext[32:])
	if err != nil {
		return nil, empty, err
	}
	edPublic := ed.Public().(ed25519.PublicKey)
	pqPublic := pq.PublicKey().Bytes()
	if subtle.ConstantTimeCompare(edPublic, value.Public.EdPublic) != 1 ||
		subtle.ConstantTimeCompare(pqPublic, value.Public.PQPublic) != 1 ||
		value.Public.EdKeyID != fingerprint("ed-", edPublic) ||
		value.Public.PQKeyID != fingerprint("pq-", pqPublic) {
		return nil, empty, errors.New("public key binding invalid")
	}
	return &VolatileKeys{ed: ed, pq: pq}, value.Public, nil
}

// Open verifies owner, mode, external key, authenticated metadata, epoch floor
// and any persistent authenticated old-key retirement floor.
func Open(vault, master string) (*VolatileKeys, PublicBundle, error) {
	var empty PublicBundle
	lock, key, err := masterLocked(master, false)
	if err != nil {
		return nil, empty, err
	}
	defer lock.Close()
	defer clear(key)
	keys, pub, err := openWithMaster(vault, key)
	if err != nil {
		return nil, empty, err
	}
	if err = enforceRetirementFloorLocked(vault, key, pub); err != nil {
		return nil, empty, err
	}
	return keys, pub, nil
}

func Initialize(vault, master string, nodeID int64, purpose string) (PublicBundle, error) {
	var empty PublicBundle
	lock, key, err := masterLocked(master, true)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	defer clear(key)
	if err = secureDir(vault); err != nil {
		return empty, err
	}
	if _, statErr := os.Lstat(retirementPath(vault)); statErr == nil {
		return empty, errors.New("retirement history exists; vault reinitialization refused")
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return empty, statErr
	}
	if _, statErr := os.Lstat(vault); statErr == nil {
		return empty, errors.New("vault already exists")
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return empty, statErr
	}
	if _, statErr := os.Lstat(floorPath(vault)); statErr == nil {
		return empty, errors.New("vault epoch floor already exists")
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return empty, statErr
	}
	keys, pub, err := Generate(nodeID, purpose, 1)
	if err != nil {
		return empty, err
	}
	raw, err := seal(keys, pub, key)
	if err != nil {
		return empty, err
	}
	if err = atomicFile(vault, raw); err != nil {
		return empty, err
	}
	if err = updateFloor(vault, 1); err != nil {
		return empty, err
	}
	return pub, nil
}

func Rotate(vault, master string, expectedEpoch uint64) (PublicBundle, error) {
	var empty PublicBundle
	lock, key, err := masterLocked(master, true)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	defer clear(key)
	_, before, err := openWithMaster(vault, key)
	if err != nil {
		return empty, err
	}
	if err = enforceRetirementFloorLocked(vault, key, before); err != nil {
		return empty, err
	}
	if before.KeyEpoch != expectedEpoch || expectedEpoch == ^uint64(0) {
		return empty, errors.New("expected key epoch mismatch")
	}
	keys, next, err := Generate(before.NodeID, before.Purpose, before.KeyEpoch+1)
	if err != nil {
		return empty, err
	}
	raw, err := seal(keys, next, key)
	if err != nil {
		return empty, err
	}
	// Fail-closed on power loss: advance the floor BEFORE swapping the keys.
	// A crash between the two writes rejects the old vault on next start.
	if err = updateFloor(vault, next.KeyEpoch); err != nil {
		return empty, err
	}
	if err = atomicFile(vault, raw); err != nil {
		return empty, err
	}
	return next, nil
}

func Description(vault, master string) (PublicBundle, error) {
	_, pub, err := Open(vault, master)
	if err != nil {
		return PublicBundle{}, fmt.Errorf("cannot open encrypted key bundle: %w", err)
	}
	return pub, nil
}
