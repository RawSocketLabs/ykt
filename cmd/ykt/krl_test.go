package main

// Validates our PROTOCOL.krl writer against OpenSSH itself: the test harness
// (scripts outside this file) signs a cert with a known serial and asks
// `ssh-keygen -Q` whether our KRL revokes it.

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestBuildKRLDoesNotMutateInput(t *testing.T) {
	serials := []uint64{300, 100, 200}
	orig := slices.Clone(serials)
	if _, err := buildKRL([]krlCAGroup{{caPub: mustSSHPubLine(t), serials: serials}}, 1, "test"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(serials, orig) {
		t.Errorf("buildKRL reordered the caller's serials: got %v, want %v", serials, orig)
	}
}

func TestWriteKRLFromEnv(t *testing.T) {
	caPubPath := os.Getenv("KRL_TEST_CA_PUB")
	outPath := os.Getenv("KRL_TEST_OUT")
	if caPubPath == "" || outPath == "" {
		t.Skip("KRL_TEST_CA_PUB / KRL_TEST_OUT not set (integration harness only)")
	}
	caPub, err := os.ReadFile(caPubPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeKRL(outPath, []krlCAGroup{{caPub: caPub, serials: []uint64{42, 1007}}}, 1, "test"); err != nil {
		t.Fatal(err)
	}
}
