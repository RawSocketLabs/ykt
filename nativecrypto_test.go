package main

// Two more externally-judged tests:
//   1. Signing a certificate for an sk-ed25519 (FIDO2) public key — the type
//      our real daily keys use. Judged by ssh-keygen -L via the harness.
//   2. The full X.509 chain: client CA (CA:TRUE) → CSR → clientAuth cert.
//      Judged by `openssl verify` via the harness.
// In-memory ECDSA P-256 signers stand in for PIV slots (both are
// crypto.Signer, so the exact production code paths run).

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"
)

// buildSKEd25519AuthorizedKey constructs an sk-ssh-ed25519@openssh.com
// public key in authorized_keys format, as ssh-keygen -t ed25519-sk emits.
func buildSKEd25519AuthorizedKey(t *testing.T, application string) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blob := ssh.Marshal(struct {
		Type        string
		PubKey      []byte
		Application string
	}{"sk-ssh-ed25519@openssh.com", pub, application})
	line := "sk-ssh-ed25519@openssh.com " + base64.StdEncoding.EncodeToString(blob) + " test-sk\n"
	return []byte(line)
}

func TestSignSKEd25519CertFromEnv(t *testing.T) {
	outPath := os.Getenv("SK_TEST_OUT")
	if outPath == "" {
		t.Skip("SK_TEST_OUT not set (integration harness only)")
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := buildSKEd25519AuthorizedKey(t, "ssh:yk")
	cert, err := signSSHCert(caKey, certSpec{
		certType:   ssh.UserCert,
		keyID:      "work:alice@daily",
		principals: []string{"alice"},
		serial:     1002,
		validity:   "+13w",
	}, pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outPath, cert, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestX509ChainFromEnv(t *testing.T) {
	caOut := os.Getenv("X509_TEST_CA_OUT")
	clientOut := os.Getenv("X509_TEST_CLIENT_OUT")
	if caOut == "" || clientOut == "" {
		t.Skip("X509_TEST_* not set (integration harness only)")
	}
	// CA key stands in for the anchor's TLS slot
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := makeClientCACert(caKey, "ykt work client CA test")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCertPEM(caOut, caCert); err != nil {
		t.Fatal(err)
	}
	// user key stands in for a daily key's 9a slot
	userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := makeCSR(userKey, "alice")
	if err != nil {
		t.Fatal(err)
	}
	clientPEM, err := signClientCert(caCert, caKey, csr, 365, 1001)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(clientOut, clientPEM, 0o644); err != nil {
		t.Fatal(err)
	}
}
