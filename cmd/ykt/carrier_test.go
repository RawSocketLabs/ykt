package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// TestCarrierRoundTrip: bytes stashed in a carrier cert come back byte-identical
// after a DER marshal/parse cycle — the same path a PIV slot subjects them to.
func TestCarrierRoundTrip(t *testing.T) {
	payloads := [][]byte{
		[]byte("sk-ssh-ed25519-cert-v01@openssh.com AAAAB3Nz... alice@laptop\n"),
		{0x00, 0xff, 0x10, 0x53, 0x70}, // binary incl. bytes that collide with PIV TLV tags
		{},                             // empty
	}
	for i, p := range payloads {
		cert, err := buildCarrier("test", p)
		if err != nil {
			t.Fatalf("payload %d: build: %v", i, err)
		}
		// Force the exact round trip a PIV slot does: keep only cert.Raw, reparse.
		reparsed, err := x509.ParseCertificate(cert.Raw)
		if err != nil {
			t.Fatalf("payload %d: reparse: %v", i, err)
		}
		got, err := payloadFromCarrier(reparsed)
		if err != nil {
			t.Fatalf("payload %d: extract: %v", i, err)
		}
		if !bytes.Equal(got, p) {
			t.Fatalf("payload %d: round trip changed bytes: got %v want %v", i, got, p)
		}
	}
}

// TestPayloadFromNonCarrier: a slot holding an unrelated cert (no carrier
// extension) is rejected, not silently returned as garbage.
func TestPayloadFromNonCarrier(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "not a carrier"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Unix(1<<33, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	if _, err := payloadFromCarrier(cert); err == nil {
		t.Fatal("expected error extracting payload from a non-carrier cert")
	}
}
