package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

func TestNewKnownHostsLines(t *testing.T) {
	ca := "# ykt work host CA trust\n" +
		"@cert-authority *.work.internal ssh-ed25519 AAA\n" +
		"@cert-authority *.home.internal ssh-ed25519 BBB\n"

	// work already present → only the home line is new; comments skipped.
	got := newKnownHostsLines("@cert-authority *.work.internal ssh-ed25519 AAA\n", ca)
	if len(got) != 1 || !strings.Contains(got[0], "home.internal") {
		t.Errorf("newKnownHostsLines = %v (want only the new home line)", got)
	}
	// nothing present → both CA lines, no comments.
	if all := newKnownHostsLines("", ca); len(all) != 2 {
		t.Errorf("empty existing should add both CA lines, got %v", all)
	}
}

// TestEnrollTLSCSR queues a valid mTLS CSR from the daily key's client slot, both
// on a fresh enroll (pub given) and a --keep re-enroll (pub recovered from slot).
func TestEnrollTLSCSR(t *testing.T) {
	dir := t.TempDir()
	withTrustHome(t, dir)
	f := newFakePIV(t)
	const slot = "9d"
	pub, err := f.GenerateKey(f.mgmt, mustSlot(t, slot), piv.Key{})
	if err != nil {
		t.Fatal(err)
	}

	if err := enrollTLSCSR(f, "654321", "alice", "laptop", "work", slot, pub); err != nil {
		t.Fatal(err)
	}
	csrBytes, err := os.ReadFile(trustPath("queue", "work", queueTLSName("alice", "laptop")))
	if err != nil {
		t.Fatalf("CSR not queued: %v", err)
	}
	blk, _ := pem.Decode(csrBytes)
	if blk == nil {
		t.Fatal("queued CSR is not PEM")
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "alice@work" {
		t.Errorf("CSR CN = %q", csr.Subject.CommonName)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature invalid: %v", err)
	}

	// --keep: pub == nil → recover the slot key via attestation.
	if err := enrollTLSCSR(f, "654321", "bob", "desktop", "work", slot, nil); err != nil {
		t.Errorf("--keep enroll should recover the slot key: %v", err)
	}
}
