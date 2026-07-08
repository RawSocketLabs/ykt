package main

// Filesystem helpers that honor --dry-run centrally, so the dry-run guarantee
// ("no files will be touched") does not depend on every call site remembering
// to check. Writes are atomic (temp + rename) so a crash mid-write cannot
// leave a half-written file that later breaks sshd -t or KRL parsing.

import (
	"os"
	"path/filepath"
)

// fileExists reports whether path is an existing regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// ensureDir creates a directory tree unless in dry-run.
func ensureDir(dir string) error {
	if dryRun {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

// writeFileAtomic writes via a temp file in the same directory then renames.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if dryRun {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// copyFile copies src to dst atomically, preserving nothing but content.
func copyFile(src, dst string, mode os.FileMode) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return writeFileAtomic(dst, b, mode)
}

// removeIfPresent deletes a file, ignoring "not found", honoring dry-run.
func removeIfPresent(path string) error {
	if dryRun {
		return nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
