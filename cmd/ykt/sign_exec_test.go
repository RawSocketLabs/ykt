package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"
)

func TestClassifyQueueEntry(t *testing.T) {
	for _, c := range []struct {
		name, kind, id string
		ok             bool
	}{
		{"user_alice.pub", "user", "alice", true},
		{"host_web1.pub", "host", "web1", true},
		{"tls_web1.csr", "tls", "web1", true},
		{"user_a.b.c.pub", "user", "a.b.c", true},
		{"random.txt", "", "", false},
		{"user_x.csr", "", "", false}, // right prefix, wrong extension
		{"host_x.pem", "", "", false},
	} {
		k, id, ok := classifyQueueEntry(c.name)
		if k != c.kind || id != c.id || ok != c.ok {
			t.Errorf("classifyQueueEntry(%q) = (%q,%q,%v), want (%q,%q,%v)", c.name, k, id, ok, c.kind, c.id, c.ok)
		}
	}
}

// fakeWithCASlot generates a CA key in the named slot and installs a cert object
// so slotPublicKey can read the CA pub back (as genesis would).
func fakeWithCASlot(t *testing.T, f *fakePIV, slotName string) piv.Slot {
	t.Helper()
	slot := mustSlot(t, slotName)
	if _, err := f.GenerateKey(f.mgmt, slot, piv.Key{}); err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, f.keys[slot].Public(), f.keys[slot])
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	if err := f.SetCertificate(f.mgmt, slot, cert); err != nil {
		t.Fatal(err)
	}
	return slot
}

// TestExecuteSignJobUser drives the SSH signing pipeline against fakePIV: sign →
// write dist → append ledger → move the queue file. No hardware.
func TestExecuteSignJobUser(t *testing.T) {
	dir := t.TempDir()
	withTrustHome(t, dir)
	f := newFakePIV(t)
	slot := fakeWithCASlot(t, f, "9a")

	subj := mustSSHPubLine(t)
	writeFixture(t, dir, filepath.Join("queue", "work", "user_alice.pub"), string(subj))
	qfile := filepath.Join(dir, "queue", "work", "user_alice.pub")

	j := signJob{domain: "work", d: Domain{UserSlot: "9a"}, kind: "user", id: "alice",
		qfile: qfile, payload: subj, principals: "alice,root", validity: "+13w"}
	anchor := Anchor{YubikeySerial: "12345678", SerialBase: 1000}

	if !executeSignJob(f, "a1", anchor, "654321", j) {
		t.Fatal("executeSignJob should report success")
	}

	certOut, err := os.ReadFile(filepath.Join(dir, "dist", "work", "user_alice-cert.pub"))
	if err != nil {
		t.Fatalf("dist cert not written: %v", err)
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey(certOut)
	if err != nil {
		t.Fatal(err)
	}
	sc := pk.(*ssh.Certificate)
	if sc.KeyId != "work:alice" {
		t.Errorf("keyID = %q", sc.KeyId)
	}
	if !reflect.DeepEqual(sc.ValidPrincipals, []string{"alice", "root"}) {
		t.Errorf("principals = %v", sc.ValidPrincipals)
	}
	// verifies against the CA slot key
	caSSH, _ := ssh.NewPublicKey(f.keys[slot].Public())
	checker := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool { return string(k.Marshal()) == string(caSSH.Marshal()) }}
	if err := checker.CheckCert("alice", sc); err != nil {
		t.Errorf("cert should verify against the CA slot key: %v", err)
	}

	// ledger recorded serial base+1
	le := loadLedger("work")
	if len(le) != 1 || le[0].Serial != 1001 || le[0].Type != "user" || le[0].Identity != "alice" {
		t.Errorf("ledger entry = %+v", le)
	}
	// queue file moved into done/
	if _, err := os.Stat(qfile); !os.IsNotExist(err) {
		t.Error("queue file should have moved out of queue/work/")
	}
	if _, err := os.Stat(filepath.Join(dir, "queue", "work", "done", "user_alice.pub")); err != nil {
		t.Error("queue file should be in queue/work/done/")
	}
}

// TestExecuteSignJobTLS drives the mTLS signing pipeline against fakePIV.
func TestExecuteSignJobTLS(t *testing.T) {
	dir := t.TempDir()
	withTrustHome(t, dir)
	f := newFakePIV(t)
	slot := mustSlot(t, "9c")
	if _, err := f.GenerateKey(f.mgmt, slot, piv.Key{}); err != nil {
		t.Fatal(err)
	}
	// the published client-CA cert must be issued by the slot key (it's the CA)
	caCert, err := makeClientCACert(f.keys[slot], "work client CA")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.SetCertificate(f.mgmt, slot, caCert); err != nil {
		t.Fatal(err)
	}
	if err := writeCertPEM(clientCACertPath("work", "a1"), caCert); err != nil {
		t.Fatal(err)
	}

	csr, err := makeCSR(mustEd25519(t), "alice@work")
	if err != nil {
		t.Fatal(err)
	}
	writeFixture(t, dir, filepath.Join("queue", "work", "tls_alice.csr"), string(csr))
	qfile := filepath.Join(dir, "queue", "work", "tls_alice.csr")

	j := signJob{domain: "work", d: Domain{TLSSlot: "9c", TLSValidityDays: 90}, kind: "tls", id: "alice",
		qfile: qfile, payload: csr, principals: "-", validity: "+90d"}
	if !executeSignJob(f, "a1", Anchor{YubikeySerial: "12345678", SerialBase: 1000}, "654321", j) {
		t.Fatal("executeSignJob(tls) should report success")
	}

	pemBytes, err := os.ReadFile(filepath.Join(dir, "dist", "work", "tls_alice.crt"))
	if err != nil {
		t.Fatalf("dist TLS cert not written: %v", err)
	}
	leaf, err := loadCertPEMBytes(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("issued mTLS leaf should chain to the client CA: %v", err)
	}
	if le := loadLedger("work"); len(le) != 1 || le[0].Type != "tls" || le[0].Serial != 1001 {
		t.Errorf("ledger entry = %+v", le)
	}
}

func loadCertPEMBytes(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	return x509.ParseCertificate(blk.Bytes)
}
