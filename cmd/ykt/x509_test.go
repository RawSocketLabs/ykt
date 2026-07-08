package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestClientCertFlow: the whole mTLS issuance path with a software CA — make a
// CA, make a CSR, sign it, and confirm the leaf chains to the CA with the right
// subject/serial/validity.
func TestClientCertFlow(t *testing.T) {
	caKey := mustEd25519(t)
	caCert, err := makeClientCACert(caKey, "work client CA")
	if err != nil {
		t.Fatal(err)
	}
	if !caCert.IsCA {
		t.Error("client CA cert must have IsCA set")
	}

	csr, err := makeCSR(mustEd25519(t), "alice@work")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := signClientCert(caCert, caKey, csr, 90, 1005)
	if err != nil {
		t.Fatal(err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("signClientCert did not return a PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "alice@work" {
		t.Errorf("CN = %q", leaf.Subject.CommonName)
	}
	if leaf.SerialNumber.Uint64() != 1005 {
		t.Errorf("serial = %v", leaf.SerialNumber)
	}
	if err := leaf.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("leaf must be signed by the CA: %v", err)
	}
	if d := leaf.NotAfter.Sub(leaf.NotBefore); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Errorf("validity = %v, want ~90d", d)
	}
	if fp := certSHA256Full(leaf); len(fp) < 10 {
		t.Errorf("certSHA256Full = %q", fp)
	}

	// loadCertPEM round-trips a written cert; garbage fails.
	p := filepath.Join(t.TempDir(), "c.pem")
	if err := os.WriteFile(p, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCertPEM(p); err != nil {
		t.Errorf("loadCertPEM: %v", err)
	}
	if _, err := loadCertPEM(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("loadCertPEM of a missing file should error")
	}
}

func TestRandomSerialUnique(t *testing.T) {
	a, b := randomSerial(), randomSerial()
	if a.Sign() <= 0 || b.Sign() <= 0 {
		t.Error("serials must be positive")
	}
	if a.Cmp(b) == 0 {
		t.Error("two random serials collided")
	}
}
