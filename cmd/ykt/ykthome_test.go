package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStoreFromEnvYKTHome(t *testing.T) {
	// A valid YKT_HOME (has config.toml with a domain) is returned.
	store := t.TempDir()
	if err := os.WriteFile(filepath.Join(store, "config.toml"), []byte("[domains.x]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("YKT_HOME", store)
	if got := storeFromEnvOrCWD(); got != store {
		t.Errorf("valid YKT_HOME = %q, want %q", got, store)
	}

	// A bogus YKT_HOME (no config.toml) yields "" — it is NOT returned, and it
	// does not fall back to the CWD walk (which could pick a different store).
	t.Setenv("YKT_HOME", t.TempDir())
	if got := storeFromEnvOrCWD(); got != "" {
		t.Errorf("bogus YKT_HOME should yield \"\", got %q", got)
	}
}
