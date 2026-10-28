//go:build linux

package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrepareCreatesPrivateCanonicalLayout(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent-state")
	layout, err := Prepare(root)
	if err != nil {
		t.Fatal(err)
	}
	if layout.Root != root || layout.Journal != filepath.Join(root, "cutover") {
		t.Fatalf("unexpected layout: %+v", layout)
	}
	for _, path := range []string{layout.Root, layout.Journal} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Fatalf("%s mode = %04o", path, info.Mode().Perm())
		}
	}
}

func TestPrepareRejectsRelativeAndSymlinkRoots(t *testing.T) {
	if _, err := Prepare("relative/state"); err == nil {
		t.Fatal("relative state root accepted")
	}
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(filepath.Join(link, "state")); err == nil {
		t.Fatal("symlinked state path accepted")
	}
}

func TestPrepareRepairsPrivateModeButNotOwnership(t *testing.T) {
	root := filepath.Join(t.TempDir(), "agent-state")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	layout, err := Prepare(root)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(layout.Root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("state root remained too broad: %04o", info.Mode().Perm())
	}
}
