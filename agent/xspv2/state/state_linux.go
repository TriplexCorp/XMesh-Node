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
	Root      string
	Journal   string
	Keys      string
	Vault     string
	MasterKey string
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

func preparePrivateDir(path string) error {
	if err := rejectSymlinkComponents(path); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	return validatePrivateDir(path)
}

func expectedLayout(root string) Layout {
	keys := filepath.Join(root, "keys")
	return Layout{
		Root:      root,
		Journal:   filepath.Join(root, "cutover"),
		Keys:      keys,
		Vault:     filepath.Join(keys, "node-request.vault"),
		MasterKey: filepath.Join(keys, "node-request.master"),
	}
}

func canonicalRoot(root string) (string, error) {
	clean := filepath.Clean(root)
	if root == "" || !filepath.IsAbs(root) || clean != root {
		return "", errors.New("state root must be a canonical absolute path")
	}
	if err := rejectSymlinkComponents(clean); err != nil {
		return "", err
	}
	return clean, nil
}

// Open validates and returns an already-existing production state layout.
// It never creates directories, chmods paths, repairs state or writes files.
func Open(root string) (Layout, error) {
	clean, err := canonicalRoot(root)
	if err != nil {
		return Layout{}, err
	}
	layout := expectedLayout(clean)
	for _, dir := range []string{layout.Root, layout.Journal, layout.Keys} {
		if err = validatePrivateDir(dir); err != nil {
			return Layout{}, fmt.Errorf("validate existing Agent state directory %s: %w", dir, err)
		}
	}
	for _, path := range []string{layout.Vault, layout.MasterKey} {
		if err = rejectSymlinkComponents(path); err != nil {
			return Layout{}, err
		}
		if _, err = os.Lstat(path); err != nil {
			return Layout{}, fmt.Errorf("required Agent security file missing: %w", err)
		}
	}
	return layout, nil
}

// Prepare creates only the production-style private directory boundaries.
// Existing enrollment identities, epoch floors, cutover journals and package
// state are never created, replaced, reset or removed here.
func Prepare(root string) (Layout, error) {
	clean, err := canonicalRoot(root)
	if err != nil {
		return Layout{}, err
	}
	if err = os.MkdirAll(clean, 0o700); err != nil {
		return Layout{}, fmt.Errorf("create state root: %w", err)
	}
	if err = os.Chmod(clean, 0o700); err != nil {
		return Layout{}, fmt.Errorf("harden state root: %w", err)
	}
	if err = validatePrivateDir(clean); err != nil {
		return Layout{}, fmt.Errorf("validate state root: %w", err)
	}

	layout := expectedLayout(clean)
	if err = preparePrivateDir(layout.Journal); err != nil {
		return Layout{}, fmt.Errorf("prepare cutover journal: %w", err)
	}
	if err = preparePrivateDir(layout.Keys); err != nil {
		return Layout{}, fmt.Errorf("prepare key state: %w", err)
	}
	for _, path := range []string{layout.Vault, layout.MasterKey} {
		if err = rejectSymlinkComponents(path); err != nil {
			return Layout{}, err
		}
	}
	return layout, nil
}
