package main

import (
	"slices"
	"testing"
)

func TestMissingGitignoreSecrets(t *testing.T) {
	// invariant: the bundled default .gitignore covers every secret pattern.
	if m := missingGitignoreSecrets(repoGitignore); len(m) != 0 {
		t.Errorf("default repoGitignore should cover all secret patterns, missing: %v", m)
	}
	// a user .gitignore that ignores only *.key is missing the rest.
	if m := missingGitignoreSecrets("*.key\nnode_modules/\n"); !slices.Equal(m, []string{"*.age", "*.puk", "info.json"}) {
		t.Errorf("missing = %v", m)
	}
	// empty → every secret pattern is missing.
	if m := missingGitignoreSecrets(""); len(m) != len(gitignoreSecretPatterns) {
		t.Errorf("empty .gitignore should miss all secret patterns, got %v", m)
	}
}
