package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRepoInit: `ykt repo init` makes a git repo, writes the data .gitignore,
// tracks config.toml, and commits — without needing a fork of the tool.
func TestRepoInit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	// deterministic identity so `git commit` works without global git config
	t.Setenv("GIT_AUTHOR_NAME", "ykt test")
	t.Setenv("GIT_AUTHOR_EMAIL", "test@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "ykt test")
	t.Setenv("GIT_COMMITTER_EMAIL", "test@example.com")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("# test"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	cmdRepoInit(nil, "")

	if !gitOK(dir, "rev-parse", "--is-inside-work-tree") {
		t.Fatal("expected a git repo after `repo init`")
	}
	gi, err := os.ReadFile(filepath.Join(dir, ".gitignore"))
	if err != nil || !strings.Contains(string(gi), "*.key") || !strings.Contains(string(gi), "*.puk") {
		t.Fatalf("data .gitignore missing secret patterns: err=%v", err)
	}
	if !gitOK(dir, "ls-files", "--error-unmatch", "config.toml") {
		t.Fatal("config.toml should be tracked")
	}
}
