package main

// Signing-path test: an in-memory ECDSA P-256 key stands in for the PIV slot
// (both are crypto.Signer), so the exact production code path is exercised.
// The harness then verifies the output with ssh-keygen -L.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSignSSHCertFromEnv(t *testing.T) {
	pubPath := os.Getenv("SIGN_TEST_PUB")
	outPath := os.Getenv("SIGN_TEST_OUT")
	caOutPath := os.Getenv("SIGN_TEST_CA_OUT")
	if pubPath == "" || outPath == "" {
		t.Skip("SIGN_TEST_* not set (integration harness only)")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := signSSHCert(caKey, certSpec{
		certType:   ssh.UserCert,
		keyID:      "work:test",
		principals: []string{"alice"},
		serial:     1001,
		validity:   "+13w",
	}, pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outPath, cert, 0o644); err != nil {
		t.Fatal(err)
	}
	if caOutPath != "" {
		line, err := sshPubFromCryptoPub(caKey.Public(), "test-ca")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(caOutPath, line, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
