package keyring

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestRetirementFloorRejectsActiveAndEpochRollback(t *testing.T) {
	vault, master, previous, candidate, previousRaw, _ := appliedRetirementFixture(t)
	retireExact(t, vault, master, previous, candidate, strings.Repeat("33", 32))

	// Simulate a local restore of the old active vault together with the old
	// persisted epoch floor while preserving the authenticated retirement marker.
	if err := atomicFile(vault, previousRaw); err != nil {
		t.Fatal(err)
	}
	if err := atomicFile(floorPath(vault), []byte(strconv.FormatUint(previous.KeyEpoch, 10))); err != nil {
		t.Fatal(err)
	}
	if _, err := Description(vault, master); err == nil {
		t.Fatal("retirement marker did not reject rolled-back active vault and epoch floor")
	}
	if _, err := PrepareRotation(vault, master, previous.KeyEpoch); err == nil {
		t.Fatal("rolled-back active identity was allowed to start another rotation")
	}
}

func TestRetirementFloorRejectsPersistedFloorRollbackAlone(t *testing.T) {
	vault, master, previous, candidate, _, _ := appliedRetirementFixture(t)
	retireExact(t, vault, master, previous, candidate, strings.Repeat("44", 32))
	if err := atomicFile(floorPath(vault), []byte(strconv.FormatUint(previous.KeyEpoch, 10))); err != nil {
		t.Fatal(err)
	}
	if _, err := Description(vault, master); err == nil {
		t.Fatal("retirement marker did not reject rolled-back persisted epoch floor")
	}
}

func TestRetirementHistoryBlocksVaultReinitialization(t *testing.T) {
	vault, master, previous, candidate, _, _ := appliedRetirementFixture(t)
	retireExact(t, vault, master, previous, candidate, strings.Repeat("55", 32))

	// Removing active/floor does not erase retirement history and therefore must
	// not turn the same state root into a fresh epoch-1 enrollment.
	if err := os.Remove(vault); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(floorPath(vault)); err != nil {
		t.Fatal(err)
	}
	if err := syncParent(vault); err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(vault, master, previous.NodeID, "node_request"); err == nil {
		t.Fatal("vault reinitialization ignored persistent retirement history")
	}
}
