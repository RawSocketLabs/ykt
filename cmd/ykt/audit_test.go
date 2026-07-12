package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestReadLogLines(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ykt.log")
	if err := os.WriteFile(p+".1", []byte("old1\nold2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("new1\nnew2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, err := readLogLines(p)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(lines, []string{"old1", "old2", "new1", "new2"}) {
		t.Errorf("readLogLines = %v (rotated generation must come first)", lines)
	}
	if _, err := readLogLines(filepath.Join(dir, "nope.log")); !os.IsNotExist(err) {
		t.Errorf("missing log should report ErrNotExist, got %v", err)
	}
}

func TestRotateLogIfLarge(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ykt.log")

	if err := os.WriteFile(p, []byte("small\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rotateLogIfLarge(p)
	if _, err := os.Stat(p + ".1"); !os.IsNotExist(err) {
		t.Error("a small log should not rotate")
	}

	if err := os.WriteFile(p, make([]byte, maxLogBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	rotateLogIfLarge(p)
	if _, err := os.Stat(p + ".1"); err != nil {
		t.Error("a log at the cap should rotate to .1")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("the current log should be moved aside after rotation")
	}
}
