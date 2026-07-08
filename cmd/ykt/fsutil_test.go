package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteFileAtomic: writes content + mode, creates parent dirs, leaves no
// temp file behind.
func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "f.txt") // nested → exercises MkdirAll
	if err := writeFileAtomic(p, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || string(b) != "hello" {
		t.Fatalf("content = %q, err = %v", b, err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// TestFsutilDryRun: the central dry-run guarantee — no writes touch the disk.
func TestFsutilDryRun(t *testing.T) {
	dir := t.TempDir()
	old := dryRun
	dryRun = true
	defer func() { dryRun = old }()

	p := filepath.Join(dir, "nope.txt")
	if err := writeFileAtomic(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fileExists(p) {
		t.Error("dry-run writeFileAtomic must not create the file")
	}
	if err := ensureDir(filepath.Join(dir, "d")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "d")); err == nil {
		t.Error("dry-run ensureDir must not create the dir")
	}
}

// TestCopyAndRemove: copyFile duplicates content; removeIfPresent is idempotent.
func TestCopyAndRemove(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	if err := copyFile(src, dst, 0o640); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "data" {
		t.Errorf("copyFile content = %q, want data", b)
	}
	if err := removeIfPresent(dst); err != nil || fileExists(dst) {
		t.Fatalf("removeIfPresent failed: err=%v exists=%v", err, fileExists(dst))
	}
	if err := removeIfPresent(dst); err != nil {
		t.Errorf("removeIfPresent(missing) = %v, want nil", err)
	}
}

// TestNaming pins the queue/dist/installed filename scheme certs are looked up by.
func TestNaming(t *testing.T) {
	for _, tc := range []struct{ got, want string }{
		{queueHostKeyName("web1"), "host_web1.pub"},
		{distHostCertName("web1"), "host_web1-cert.pub"},
		{installedSSHCertName("work"), "id_work-cert.pub"},
	} {
		if tc.got != tc.want {
			t.Errorf("naming = %q, want %q", tc.got, tc.want)
		}
	}
}
