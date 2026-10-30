//go:build linux

package state

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenExistingStateIsReadOnly(t *testing.T) {
	layout, _, _ := appliedRotation(t)
	paths := []string{
		layout.MasterKey,
		layout.Vault,
		layout.Vault + ".min-epoch",
		layout.Vault + ".previous",
		layout.Vault + ".next",
	}
	before := make(map[string][]byte, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = raw
	}

	opened, err := Open(layout.Root)
	if err != nil {
		t.Fatal(err)
	}
	if opened != layout {
		t.Fatalf("Open changed layout: before=%+v after=%+v", layout, opened)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before[path], raw) {
			t.Fatalf("Open rewrote durable state: %s", path)
		}
	}
}

func TestOpenRejectsMissingBroadOrSymlinkedState(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "missing")
		if _, err := Open(root); err == nil {
			t.Fatal("missing state root accepted")
		}
	})

	t.Run("broad-mode", func(t *testing.T) {
		layout, _, _ := appliedRotation(t)
		if err := os.Chmod(layout.Keys, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(layout.Root); err == nil {
			t.Fatal("over-broad state directory mode accepted")
		}
		info, err := os.Stat(layout.Keys)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Fatal("Open repaired mode instead of failing read-only")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		base := t.TempDir()
		realRoot := filepath.Join(base, "real")
		if _, err := Prepare(realRoot); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink(realRoot, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(link); err == nil {
			t.Fatal("symlinked state root accepted")
		}
	})
}
