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

// TestXDGRelativeEnvIgnored: per the XDG spec, a relative XDG_*_HOME must be
// ignored (else the log/pointer path resolves against the CWD and scatters).
func TestXDGRelativeEnvIgnored(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "relative/config")
	if d := xdgConfigDir(); d != "" && !filepath.IsAbs(d) {
		t.Fatalf("relative XDG_CONFIG_HOME must be ignored; got non-absolute %q", d)
	}
	t.Setenv("XDG_STATE_HOME", "relative/state")
	if s := xdgStateDir(); s != "" && !filepath.IsAbs(s) {
		t.Fatalf("relative XDG_STATE_HOME must be ignored; got non-absolute %q", s)
	}
}

// TestStoreDiscovery: isTrustStore + storeFromEnvOrCWD (the "where am I" resolver
// that setup-home no-arg relies on, and which must NOT consult the pointer).
func TestStoreDiscovery(t *testing.T) {
	dir := t.TempDir()
	if isTrustStore(dir) {
		t.Fatal("empty dir must not be a trust store")
	}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[domains.test]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !isTrustStore(dir) {
		t.Fatal("dir with config.toml must be a trust store")
	}

	t.Setenv("YKT_HOME", dir)
	if got := storeFromEnvOrCWD(); got != dir {
		t.Fatalf("YKT_HOME resolution = %q, want %q", got, dir)
	}

	// Walk up from a nested CWD (no YKT_HOME). Compare via EvalSymlinks because
	// macOS temp dirs are symlinked and Getwd returns the resolved path.
	t.Setenv("YKT_HOME", "")
	sub := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(sub)
	got := storeFromEnvOrCWD()
	gotR, _ := filepath.EvalSymlinks(got)
	wantR, _ := filepath.EvalSymlinks(dir)
	if gotR != wantR {
		t.Fatalf("CWD walk resolution = %q, want %q", got, dir)
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
	if err := os.WriteFile(filepath.Join(store, "config.toml"), []byte("[domains.test]\n"), 0o644); err != nil {
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
