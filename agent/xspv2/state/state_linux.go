//go:build linux

package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const DefaultRoot = "/var/lib/xmesh-agent/xsp-v2"

type Layout struct {
	Root    string
	Journal string
}

func rejectSymlinkComponents(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return errors.New("state path must be absolute")
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect state path component: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("state path contains symlink component: %s", current)
		}
	}
	return nil
}

func validatePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("state path must be a real directory")
	}
	if info.Mode().Perm() != 0o700 {
		return fmt.Errorf("state directory must be mode 0700, got %04o", info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return errors.New("state directory must be owned by the agent uid")
	}
	return nil
}

// Prepare creates the production-style private state boundary used by the
// future Agent integration. It intentionally does not perform enrollment,
// network I/O, epoch changes, key retirement, or legacy fallback.
func Prepare(root string) (Layout, error) {
	clean := filepath.Clean(root)
	if root == "" || !filepath.IsAbs(root) || clean != root {
		return Layout{}, errors.New("state root must be a canonical absolute path")
	}
	if err := rejectSymlinkComponents(clean); err != nil {
		return Layout{}, err
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return Layout{}, fmt.Errorf("create state root: %w", err)
	}
	if err := os.Chmod(clean, 0o700); err != nil {
		return Layout{}, fmt.Errorf("harden state root: %w", err)
	}
	if err := validatePrivateDir(clean); err != nil {
		return Layout{}, fmt.Errorf("validate state root: %w", err)
	}
	journal := filepath.Join(clean, "cutover")
	if err := rejectSymlinkComponents(journal); err != nil {
		return Layout{}, err
	}
	if err := os.Mkdir(journal, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return Layout{}, fmt.Errorf("create cutover journal: %w", err)
	}
	if err := os.Chmod(journal, 0o700); err != nil {
		return Layout{}, fmt.Errorf("harden cutover journal: %w", err)
	}
	if err := validatePrivateDir(journal); err != nil {
		return Layout{}, fmt.Errorf("validate cutover journal: %w", err)
	}
	return Layout{Root: clean, Journal: journal}, nil
}
