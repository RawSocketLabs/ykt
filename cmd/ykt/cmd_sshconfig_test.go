package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMigrateOldLayoutOrphan: a ykt-marked host conf migrates even when the
// 00-defaults.conf that used to mark the folder is gone (no orphaned entries).
func TestMigrateOldLayoutOrphan(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir uses USERPROFILE on Windows
	oldDir := filepath.Join(home, ".ssh", "work")
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(oldDir, "web1.conf"), []byte("# work/web1 — managed by ykt\nHost web1\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	migrateOldLayout([]string{"work"})

	if _, err := os.Stat(filepath.Join(home, ".ssh", "ykt", "work", "web1.conf")); err != nil {
		t.Fatalf("orphaned host conf was not migrated into ~/.ssh/ykt/: %v", err)
	}
	if _, err := os.Stat(oldDir); !os.IsNotExist(err) {
		t.Error("emptied old dir should be removed")
	}
}

// TestMigrateOldLayoutLeavesUserDir: a same-named dir WITHOUT our marker is left
// untouched.
func TestMigrateOldLayoutLeavesUserDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir uses USERPROFILE on Windows
	userDir := filepath.Join(home, ".ssh", "work")
	if err := os.MkdirAll(userDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDir, "mine.conf"), []byte("Host mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	migrateOldLayout([]string{"work"})
	if _, err := os.Stat(filepath.Join(userDir, "mine.conf")); err != nil {
		t.Error("a user's own ~/.ssh/work/ must not be touched")
	}
}

// TestUpsertManagedIncludes: top/bottom placement + preserve, idempotent, and
// namespaced Include paths — this is lockout-adjacent config munging.
func TestUpsertManagedIncludes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir uses USERPROFILE on Windows
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(home, ".ssh", "config")
	if err := os.WriteFile(cfg, []byte("Host myserver\n    HostName 1.2.3.4\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	read := func() string { b, _ := os.ReadFile(cfg); return string(b) }

	if err := upsertManagedIncludes([]string{"work"}, includeBottom); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(read(), "Host myserver") {
		t.Error("bottom placement should keep the user's entry first")
	}
	if !strings.Contains(read(), "Include ykt/work/*.conf") {
		t.Error("namespaced Include line missing")
	}

	// preserve keeps the block at the bottom while adding a domain
	if err := upsertManagedIncludes([]string{"work", "home"}, includePreserve); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(read(), "Host myserver") {
		t.Error("preserve should not move the block to the top")
	}
	if !strings.Contains(read(), "Include ykt/home/*.conf") {
		t.Error("re-upsert should add the new domain's Include")
	}

	// top moves it first; still exactly one managed block (idempotent)
	if err := upsertManagedIncludes([]string{"work"}, includeTop); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(read(), sshBeginMarker) {
		t.Error("top placement should put the managed block first")
	}
	if n := strings.Count(read(), sshBeginMarker); n != 1 {
		t.Errorf("expected exactly one managed block, got %d", n)
	}
}
