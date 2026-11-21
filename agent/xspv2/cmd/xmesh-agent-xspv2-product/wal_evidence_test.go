package main

import (
	"bytes"
	"testing"
)

func TestWALWitnessMessageBindsDomainAndNode(t *testing.T) {
	payload := []byte(`{"kind":"xmesh.quota-v2.offhost-wal-birth-witness","nodeId":42,"schemaVersion":1}`)
	message, err := walWitnessMessage(payload, 42)
	if err != nil || !bytes.Equal(message, append([]byte(walWitnessDomain), payload...)) {
		t.Fatalf("unexpected WAL signature input: %q, %v", message, err)
	}
	duplicate := []byte(`{"kind":"xmesh.quota-v2.offhost-wal-birth-witness","nodeId":43,"nodeId":42,"schemaVersion":1}`)
	if _, err := walWitnessMessage(duplicate, 42); err == nil {
		t.Fatal("ambiguous identity accepted")
	}
	if _, err := walWitnessMessage(payload, 43); err == nil {
		t.Fatal("foreign identity accepted")
	}
}
