//go:build linux

package cutover

import (
	"bytes"
	"testing"
)

func TestVerifiedCommitReceiptEnvelopeRequiresFullJournalReverification(t *testing.T) {
	dir, receipt, permit, panel, next, late := receiptJournalFixture(t)
	if _, err := PersistVerifiedCommitReceiptForJournal(
		dir, receipt, panel, permit, next, permit.Message().ToEpoch, late,
	); err != nil {
		t.Fatal(err)
	}
	envelope, err := ReloadVerifiedCommitReceiptEnvelopeForJournal(
		dir, panel, permit, next, permit.Message().ToEpoch, late,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(envelope.Bytes(), receipt) {
		t.Fatal("verified recovery envelope did not preserve exact signed receipt bytes")
	}
	verified := envelope.Receipt()
	if verified.NodeID != permit.Message().NodeID ||
		verified.ToEpoch != permit.Message().ToEpoch ||
		verified.RequestID != permit.Message().RequestID ||
		verified.ToEdKeyID != permit.Message().ToEdKeyID ||
		verified.ToPQKeyID != permit.Message().ToPQKeyID {
		t.Fatal("verified recovery envelope lost receipt or active-key identity")
	}
	copyBytes := envelope.Bytes()
	copyBytes[0] ^= 0xff
	if bytes.Equal(copyBytes, envelope.Bytes()) {
		t.Fatal("verified recovery envelope leaked mutable internal receipt bytes")
	}
}
