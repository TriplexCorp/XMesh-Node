//go:build linux

package keyring

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateMasterKeyLeavesSyncablePrivateDurableEntry(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	master := filepath.Join(root, "master.key")
	if err := CreateMasterKey(master); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(master)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != 32 {
		t.Fatalf("unexpected master-key file metadata: mode=%v size=%d", info.Mode(), info.Size())
	}

	// Keep the directory durability primitive directly covered so a future
	// refactor cannot silently replace it with a no-op or an unsupported path.
	if err := syncParentDir(master); err != nil {
		t.Fatalf("parent directory is not syncable: %v", err)
	}

	if err := CreateMasterKey(master); err == nil {
		t.Fatal("existing master key was overwritten")
	}
}
