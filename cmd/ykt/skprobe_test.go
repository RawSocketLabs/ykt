package main

import "testing"

func TestSkOutputIncapable(t *testing.T) {
	// These are the fast-fail signatures of a toolchain that can't do sk keys.
	incapable := []string{
		"No FIDO SecurityKeyProvider specified\nKey enrollment failed: invalid format", // macOS Apple ssh-keygen
		"unknown key type ed25519-sk",
		"ssh-keygen: unknown option -- O",
		"unsupported option",
	}
	for _, s := range incapable {
		if !skOutputIncapable(s) {
			t.Errorf("should flag an incapable toolchain: %q", s)
		}
	}
	// A capable toolchain proceeds to a touch prompt; empty output means we killed
	// it at the deadline (also capable). Neither should be flagged.
	capable := []string{
		"Generating public/private ed25519-sk key pair.\nYou may need to touch your authenticator to authorize key generation.",
		"",
	}
	for _, s := range capable {
		if skOutputIncapable(s) {
			t.Errorf("should NOT flag capable/inconclusive output: %q", s)
		}
	}
}
