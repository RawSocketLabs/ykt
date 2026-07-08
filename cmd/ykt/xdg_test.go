package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestXDGLogPath: the audit log resolves under XDG_STATE_HOME and logLine
// actually writes there (machine-local, not the synced trust store).
func TestXDGLogPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_STATE_HOME", filepath.Join(tmp, "state"))
	want := filepath.Join(tmp, "state", "ykt", "ykt.log")
	if got := logFilePath(); got != want {
		t.Fatalf("logFilePath = %q, want %q", got, want)
	}
	logLine("shakedown entry")
	b, err := os.ReadFile(want)
	if err != nil || !strings.Contains(string(b), "shakedown entry") {
		t.Fatalf("log not written to XDG state dir: err=%v content=%q", err, b)
	}
}

// TestHomePointer: readHomePointer returns a recorded store only when it holds a
// config.toml, so a stale/wrong pointer is ignored rather than trusted.
func TestHomePointer(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, "config"))

	if got := readHomePointer(); got != "" {
		t.Fatalf("no pointer yet, want \"\", got %q", got)
	}

	store := filepath.Join(tmp, "store")
	if err := os.MkdirAll(store, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "config.toml"), []byte("# test"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(homePointerPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(homePointerPath(), []byte(store+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readHomePointer(); got != store {
		t.Fatalf("readHomePointer = %q, want %q", got, store)
	}

	// a pointer to a dir WITHOUT config.toml must be rejected
	if err := os.WriteFile(homePointerPath(), []byte(tmp+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readHomePointer(); got != "" {
		t.Fatalf("pointer without config.toml should be rejected, got %q", got)
	}
}
