//go:build linux

package cutover

// Experimental durable journal for an independently verified Nexus commit
// receipt. This does not contact the panel, activate a keypair, lower a floor,
// retire old keys or integrate with the production Go 1.23 agent.
import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const commitReceiptJournalName = "xsp2-verified-commit-receipt.json"

type commitReceiptRecord struct {
	Schema                  string `json:"schema"`
	SignedReceipt           []byte `json:"signedReceipt"`
	ReceiptEnvelopeSHA256   string `json:"receiptEnvelopeSha256"`
	SignedACKEnvelopeSHA256 string `json:"signedACKEnvelopeSha256"`
	PermitDigest            string `json:"permitDigest"`
	NodeID                  uint64 `json:"nodeId"`
	ToEpoch                 uint64 `json:"toEpoch"`
	RequestID               string `json:"requestId"`
}

// VerifiedCommitReceiptEnvelope is an opaque, already reverified journal
// witness. Callers may read a defensive copy of the exact signed envelope, but
// cannot construct a trusted value without passing the full permit/ACK/panel
// verification path in this package.
type VerifiedCommitReceiptEnvelope struct {
	verified VerifiedCommitReceipt
	raw      []byte
}

func (v VerifiedCommitReceiptEnvelope) Receipt() VerifiedCommitReceipt { return v.verified }

func (v VerifiedCommitReceiptEnvelope) Bytes() []byte {
	return append([]byte(nil), v.raw...)
}

func readCommitReceiptRecord(path string) (commitReceiptRecord, error) {
	var record commitReceiptRecord
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 32*1024 {
		return record, errors.New("unsafe commit receipt journal file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	if err := uniqueFields(raw); err != nil {
		return record, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return commitReceiptRecord{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return commitReceiptRecord{}, errors.New("trailing commit receipt journal bytes")
	}
	if record.Schema != "xsp2-verified-commit-receipt-journal-1" ||
		len(record.SignedReceipt) == 0 || len(record.SignedReceipt) > 16*1024 ||
		record.ReceiptEnvelopeSHA256 != sha(record.SignedReceipt) ||
		len(record.SignedACKEnvelopeSHA256) != 64 || len(record.PermitDigest) != 64 ||
		record.NodeID == 0 || record.ToEpoch == 0 ||
		len(record.RequestID) == 0 || len(record.RequestID) > 64 {
		return commitReceiptRecord{}, errors.New("corrupt commit receipt journal")
	}
	return record, nil
}

func checkSavedACKForReceipt(dir string, permit VerifiedPermit) (appliedACKRecord, error) {
	var empty appliedACKRecord
	ack, err := readACKRecord(filepath.Join(dir, ackJournalName))
	if err != nil {
		return empty, fmt.Errorf("missing or invalid durable signed ACK: %w", err)
	}
	p := permit.Message()
	if permit.PermitDigest() == "" ||
		ack.PermitDigest != permit.PermitDigest() ||
		ack.NodeID != p.NodeID || ack.ToEpoch != p.ToEpoch ||
		ack.RequestID != p.RequestID {
		return empty, errors.New("saved signed ACK is not bound to trusted permit")
	}
	return ack, nil
}

func verifyReceiptJournalRow(record commitReceiptRecord, ack appliedACKRecord,
	receiptPin PinnedPublic, permit VerifiedPermit, next PinnedPublic,
	minEpoch uint64, nowMS int64) (VerifiedCommitReceipt, error) {
	var empty VerifiedCommitReceipt
	if record.SignedACKEnvelopeSHA256 != ack.EnvelopeSHA256 ||
		record.PermitDigest != permit.PermitDigest() ||
		record.NodeID != ack.NodeID || record.ToEpoch != ack.ToEpoch ||
		record.RequestID != ack.RequestID {
		return empty, errors.New("receipt journal is not bound to saved ACK")
	}
	verified, err := VerifyCommitReceipt(record.SignedReceipt, receiptPin,
		permit, ack.SignedACK, next, minEpoch, nowMS)
	if err != nil {
		return empty, err
	}
	if verified.NodeID != record.NodeID || verified.ToEpoch != record.ToEpoch ||
		verified.RequestID != record.RequestID ||
		verified.SignedACKSHA256Hex != record.SignedACKEnvelopeSHA256 {
		return empty, errors.New("verified receipt differs from saved journal")
	}
	return verified, nil
}

// PersistVerifiedCommitReceiptForJournal verifies BOTH Nexus signatures against
// independently pinned panel_response keys, and binds the receipt to the exact
// locally journaled signed ACK and permit. It then writes private, fsynced
// immutable receipt bytes under the same advisory lock as permit/ACK journals.
//
// Retries accept only the same byte-for-byte signed envelope. No "latest wins"
// update and no alternate/Ed-only receipt. The caller must independently ensure
// the NEW encrypted vault and protected monotonic floor are active; the journal
// alone does not prove that, or protect against a privileged disk rollback.
func PersistVerifiedCommitReceiptForJournal(dir string, raw []byte,
	receiptPin PinnedPublic, permit VerifiedPermit, next PinnedPublic,
	minEpoch uint64, nowMS int64) (VerifiedCommitReceipt, error) {
	var empty VerifiedCommitReceipt
	if err := checkPrivateDir(dir); err != nil {
		return empty, err
	}
	lock, err := lockPermit(dir)
	if err != nil {
		return empty, err
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() }()

	ack, err := checkSavedACKForReceipt(dir, permit)
	if err != nil {
		return empty, err
	}
	verified, err := VerifyCommitReceipt(raw, receiptPin,
		permit, ack.SignedACK, next, minEpoch, nowMS)
	if err != nil {
		return empty, err
	}

	path := filepath.Join(dir, commitReceiptJournalName)
	old, err := readCommitReceiptRecord(path)
	if err == nil {
		if !bytes.Equal(old.SignedReceipt, raw) ||
			old.ReceiptEnvelopeSHA256 != sha(raw) {
			return empty, errors.New("different signed commit receipt already persisted")
		}
		return verifyReceiptJournalRow(old, ack, receiptPin, permit, next, minEpoch, nowMS)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return empty, fmt.Errorf("invalid prior commit receipt journal: %w", err)
	}
	row := commitReceiptRecord{
		Schema:                  "xsp2-verified-commit-receipt-journal-1",
		SignedReceipt:           append([]byte(nil), raw...),
		ReceiptEnvelopeSHA256:   sha(raw),
		SignedACKEnvelopeSHA256: ack.EnvelopeSHA256,
		PermitDigest:            permit.PermitDigest(),
		NodeID:                  verified.NodeID,
		ToEpoch:                 verified.ToEpoch,
		RequestID:               verified.RequestID,
	}
	// Shared ACK journal persistence primitive uses 0600, fsync(file),
	// atomic rename to a previously absent name, and fsync(parent directory).
	if err := persistSignedReceiptFile(dir, path, row); err != nil {
		return empty, err
	}
	return verified, nil
}

// persistACKFile's serialization is restricted to appliedACKRecord. A receipt
// has its own strict record and must never be coerced into the ACK schema.
// This function performs the same durability sequence for receipt records.
func persistSignedReceiptFile(dir, path string, record commitReceiptRecord) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".xsp2-receipt-tmp-")
	if err != nil {
		return err
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
	if err = tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err = tmp.Write(raw); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if _, err = os.Lstat(path); err == nil {
		return errors.New("commit receipt journal already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirFile.Close()
	return dirFile.Sync()
}

// ReloadVerifiedCommitReceiptEnvelopeForJournal re-authenticates the precise
// stored permit/ACK/receipt chain and returns an opaque witness carrying a
// defensive copy of the exact signed receipt envelope. This is the only
// supported path for recovery code that needs receipt bytes as anti-rollback
// evidence; callers must not substitute arbitrary bytes and hash them.
func ReloadVerifiedCommitReceiptEnvelopeForJournal(dir string,
	receiptPin PinnedPublic, permit VerifiedPermit, next PinnedPublic,
	minEpoch uint64, nowMS int64) (VerifiedCommitReceiptEnvelope, error) {
	var empty VerifiedCommitReceiptEnvelope
	if err := checkPrivateDir(dir); err != nil {
		return empty, err
	}
	lock, err := lockPermit(dir)
	if err != nil {
		return empty, err
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); _ = lock.Close() }()
	ack, err := checkSavedACKForReceipt(dir, permit)
	if err != nil {
		return empty, err
	}
	row, err := readCommitReceiptRecord(filepath.Join(dir, commitReceiptJournalName))
	if err != nil {
		return empty, err
	}
	verified, err := verifyReceiptJournalRow(row, ack, receiptPin, permit, next, minEpoch, nowMS)
	if err != nil {
		return empty, err
	}
	return VerifiedCommitReceiptEnvelope{
		verified: verified,
		raw:      append([]byte(nil), row.SignedReceipt...),
	}, nil
}

// ReloadVerifiedCommitReceiptForJournal preserves the original public API while
// delegating to the stronger exact-envelope reload path used by recovery code.
func ReloadVerifiedCommitReceiptForJournal(dir string,
	receiptPin PinnedPublic, permit VerifiedPermit, next PinnedPublic,
	minEpoch uint64, nowMS int64) (VerifiedCommitReceipt, error) {
	envelope, err := ReloadVerifiedCommitReceiptEnvelopeForJournal(
		dir, receiptPin, permit, next, minEpoch, nowMS,
	)
	if err != nil {
		return VerifiedCommitReceipt{}, err
	}
	return envelope.Receipt(), nil
}
