//go:build linux

package cutover

import (
    "bytes"
    "os"
    "path/filepath"
    "sync"
    "testing"
)

func receiptJournalFixture(t *testing.T) (string, []byte, VerifiedPermit, PinnedPublic, PinnedPublic, int64) {
    t.Helper()
    f := load(t)
    panelEd, panelPQ, panel := pair(t)
    nodeEd, nodePQ, next := pair(t)
    panel.Purpose, panel.IssuerID, panel.NodeID = "panel_response", f.Permit.IssuerID, f.Permit.NodeID
    next.Purpose, next.IssuerID, next.NodeID = "node_request", f.Ack.IssuerID, f.Ack.NodeID
    f.Permit.SignerEdKeyID, f.Permit.SignerPQKeyID = panel.EdKeyID, panel.PQKeyID
    f.Permit.ToEdKeyID, f.Permit.ToPQKeyID = next.EdKeyID, next.PQKeyID
    permit, err := VerifyPermit(mustSign(t, f.Permit, panelEd, panelPQ), panel, ExpectedPermit{
        NodeID: f.Permit.NodeID, FromEpoch: f.Permit.FromEpoch, ToEpoch: f.Permit.ToEpoch,
        RequestID: f.Permit.RequestID, FromEdKeyID: f.Permit.FromEdKeyID,
        FromPQKeyID: f.Permit.FromPQKeyID, ToEdKeyID: f.Permit.ToEdKeyID,
        ToPQKeyID: f.Permit.ToPQKeyID, CandidateSHA256Hex: f.Permit.CandidateSHA256Hex,
    }, f.Permit.IssuedAtMS+1)
    if err != nil { t.Fatal(err) }
    f.Ack.ToEdKeyID, f.Ack.ToPQKeyID = next.EdKeyID, next.PQKeyID
    f.Ack.SignerEdKeyID, f.Ack.SignerPQKeyID = next.EdKeyID, next.PQKeyID
    f.Ack.PermitSHA256Hex = permit.PermitDigest()
    ack := mustSign(t, f.Ack, nodeEd, nodePQ)
    dir := privateJournalTestDir(t)
    if _, err := persistVerifiedAppliedACK(dir, ack, permit, next, f.Ack.IssuedAtMS+1); err != nil {
        t.Fatalf("persist independently signed ACK: %v", err)
    }
    committed := f.Ack.IssuedAtMS+1000
    receipt := signReceiptForTest(t, CommitReceipt{
        Protocol: "XSP/2", Kind: "commit_receipt",
        IssuerID: panel.IssuerID, SignerEdKeyID: panel.EdKeyID, SignerPQKeyID: panel.PQKeyID,
        NodeID: f.Ack.NodeID, FromEpoch: f.Ack.FromEpoch, ToEpoch: f.Ack.ToEpoch,
        RequestID: f.Ack.RequestID, CommittedAtMS: committed,
        AckNonceHex: f.Ack.NonceHex, CandidateSHA256Hex: f.Ack.CandidateSHA256Hex,
        PermitSHA256Hex: permit.PermitDigest(), SignedACKSHA256Hex: sha(ack),
    }, panelEd, panelPQ)
    return dir, receipt, permit, panel, next, f.Ack.ExpiresAtMS + 86400000
}

func TestCommitReceiptJournalConcurrentIdempotentRestart(t *testing.T) {
    dir, receipt, permit, panel, next, late := receiptJournalFixture(t)
    var wg sync.WaitGroup
    errCh := make(chan error, 4)
    for i := 0; i < 4; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            _, err := PersistVerifiedCommitReceiptForJournal(dir, receipt, panel, permit, next, permit.Message().ToEpoch, late)
            errCh <- err
        }()
    }
    wg.Wait()
    close(errCh)
    for err := range errCh {
        if err != nil { t.Fatalf("identical receipt retry rejected: %v", err) }
    }
    path := filepath.Join(dir, commitReceiptJournalName)
    stat, err := os.Lstat(path)
    if err != nil { t.Fatal(err) }
    if !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 {
        t.Fatal("persisted receipt must be a private regular file")
    }
    row, err := readCommitReceiptRecord(path)
    if err != nil { t.Fatal(err) }
    if !bytes.Equal(row.SignedReceipt, receipt) { t.Fatal("receipt bytes not preserved") }
    verified, err := ReloadVerifiedCommitReceiptForJournal(dir, panel, permit, next, permit.Message().ToEpoch, late)
    if err != nil { t.Fatal(err) }
    if verified.RequestID != permit.Message().RequestID || verified.ToEpoch != permit.Message().ToEpoch {
        t.Fatal("receipt lost committed request/epoch binding")
    }
    if _, err := ReloadVerifiedCommitReceiptForJournal(dir, panel, permit, next,
        permit.Message().ToEpoch+1, late); err == nil {
        t.Fatal("rolled-back epoch accepted")
    }
    wrongPin := panel
    wrongPin.Purpose = "node_request"
    if _, err := ReloadVerifiedCommitReceiptForJournal(dir, wrongPin, permit, next,
        permit.Message().ToEpoch, late); err == nil {
        t.Fatal("wrong panel signer purpose accepted")
    }
    changed := append(append([]byte(nil), receipt...), byte(' '))
    if _, err := PersistVerifiedCommitReceiptForJournal(dir, changed, panel, permit, next,
        permit.Message().ToEpoch, late); err == nil {
        t.Fatal("changed signed receipt overwrote earlier journal")
    }
    // A fresh receipt cannot be accepted if the original ACK is altered,
    // even when the stored receipt has two valid signatures.
    if err := os.Remove(filepath.Join(dir, ackJournalName)); err != nil { t.Fatal(err) }
    if _, err := ReloadVerifiedCommitReceiptForJournal(dir, panel, permit, next,
        permit.Message().ToEpoch, late); err == nil {
        t.Fatal("receipt accepted without original ACK")
    }
}

func TestCommitReceiptJournalFailsClosedOnUnsafeExistingState(t *testing.T) {
    t.Run("missing-ack", func(t *testing.T) {
        dir, receipt, permit, panel, next, late := receiptJournalFixture(t)
        if err := os.Remove(filepath.Join(dir, ackJournalName)); err != nil { t.Fatal(err) }
        if _, err := PersistVerifiedCommitReceiptForJournal(dir, receipt, panel, permit, next,
            permit.Message().ToEpoch, late); err == nil { t.Fatal("receipt without saved ACK accepted") }
    })
    t.Run("symlink", func(t *testing.T) {
        dir, receipt, permit, panel, next, late := receiptJournalFixture(t)
        if err := os.Symlink("/dev/null", filepath.Join(dir, commitReceiptJournalName)); err != nil { t.Fatal(err) }
        if _, err := PersistVerifiedCommitReceiptForJournal(dir, receipt, panel, permit, next,
            permit.Message().ToEpoch, late); err == nil { t.Fatal("symlink journal accepted") }
    })
    t.Run("corruption", func(t *testing.T) {
        dir, receipt, permit, panel, next, late := receiptJournalFixture(t)
        path := filepath.Join(dir, commitReceiptJournalName)
        if _, err := PersistVerifiedCommitReceiptForJournal(dir, receipt, panel, permit, next,
            permit.Message().ToEpoch, late); err != nil { t.Fatal(err) }
        if err := os.WriteFile(path, []byte("{corrupt"), 0600); err != nil { t.Fatal(err) }
        if _, err := ReloadVerifiedCommitReceiptForJournal(dir, panel, permit, next,
            permit.Message().ToEpoch, late); err == nil { t.Fatal("corrupt receipt accepted") }
        if _, err := PersistVerifiedCommitReceiptForJournal(dir, receipt, panel, permit, next,
            permit.Message().ToEpoch, late); err == nil { t.Fatal("corrupt journal silently repaired") }
    })
    t.Run("no-receipt", func(t *testing.T) {
        dir, _, permit, panel, next, late := receiptJournalFixture(t)
        if _, err := ReloadVerifiedCommitReceiptForJournal(dir, panel, permit, next,
            permit.Message().ToEpoch, late); err == nil { t.Fatal("missing receipt treated as commit") }
    })
}
