package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"
)

// fakePIV is a software stand-in for *piv.YubiKey. It generates real ECDSA P-256
// keys in memory (so signing/attestation exercise the production code path), but
// needs no hardware. Attestations chain to a FAKE device CA — good enough to test
// the genesis/enroll/sign/stash orchestration, but not the Yubico-root check in
// `verify attestation` (that's covered against real store material).
type fakePIV struct {
	serial     uint32
	pin, puk   string
	mgmt       []byte
	keys       map[piv.Slot]*ecdsa.PrivateKey
	certs      map[piv.Slot]*x509.Certificate
	attCA      *ecdsa.PrivateKey
	attCert    *x509.Certificate
	resetCount int
}

func newFakePIV(t *testing.T) *fakePIV {
	t.Helper()
	attCA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "fake yubikey attestation"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, attCA.Public(), attCA)
	if err != nil {
		t.Fatal(err)
	}
	attCert, _ := x509.ParseCertificate(der)
	return &fakePIV{
		serial:  12345678,
		mgmt:    piv.DefaultManagementKey,
		keys:    map[piv.Slot]*ecdsa.PrivateKey{},
		certs:   map[piv.Slot]*x509.Certificate{},
		attCA:   attCA,
		attCert: attCert,
	}
}

func (f *fakePIV) Close() error                       { return nil }
func (f *fakePIV) Version() piv.Version               { return piv.Version{Major: 5, Minor: 7, Patch: 0} }
func (f *fakePIV) Serial() (uint32, error)            { return f.serial, nil }
func (f *fakePIV) Retries() (int, error)              { return 3, nil }
func (f *fakePIV) SetPIN(_, n string) error           { f.pin = n; return nil }
func (f *fakePIV) SetPUK(_, n string) error           { f.puk = n; return nil }
func (f *fakePIV) SetManagementKey(_, n []byte) error { f.mgmt = n; return nil }

func (f *fakePIV) Reset() error {
	f.resetCount++
	f.keys = map[piv.Slot]*ecdsa.PrivateKey{}
	f.certs = map[piv.Slot]*x509.Certificate{}
	f.pin, f.puk = "", ""
	f.mgmt = piv.DefaultManagementKey
	return nil
}

func (f *fakePIV) VerifyPIN(pin string) error {
	if f.pin != "" && pin != f.pin {
		return fmt.Errorf("wrong PIN")
	}
	return nil
}

func (f *fakePIV) Metadata(string) (*piv.Metadata, error) {
	mk := f.mgmt
	return &piv.Metadata{ManagementKey: &mk}, nil
}

func (f *fakePIV) SetMetadata(_ []byte, m *piv.Metadata) error {
	if m.ManagementKey != nil {
		f.mgmt = *m.ManagementKey
	}
	return nil
}

func (f *fakePIV) GenerateKey(_ []byte, slot piv.Slot, _ piv.Key) (crypto.PublicKey, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	f.keys[slot] = k
	return k.Public(), nil
}

func (f *fakePIV) PrivateKey(slot piv.Slot, _ crypto.PublicKey, _ piv.KeyAuth) (crypto.PrivateKey, error) {
	k, ok := f.keys[slot]
	if !ok {
		return nil, fmt.Errorf("no key in slot")
	}
	return k, nil
}

func (f *fakePIV) Attest(slot piv.Slot) (*x509.Certificate, error) {
	k, ok := f.keys[slot]
	if !ok {
		return nil, fmt.Errorf("no key to attest")
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fake slot attestation"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.attCert, k.Public(), f.attCA)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

func (f *fakePIV) AttestationCertificate() (*x509.Certificate, error) { return f.attCert, nil }

func (f *fakePIV) Certificate(slot piv.Slot) (*x509.Certificate, error) {
	c, ok := f.certs[slot]
	if !ok {
		return nil, fmt.Errorf("no certificate in slot")
	}
	return c, nil
}

func (f *fakePIV) SetCertificate(_ []byte, slot piv.Slot, cert *x509.Certificate) error {
	f.certs[slot] = cert
	return nil
}

// compile-time check that the fake satisfies the interface the code uses.
var _ pivKey = (*fakePIV)(nil)

// --- ceremony tests against the fake ----------------------------------------

func TestResetAndProvisionPIV(t *testing.T) {
	f := newFakePIV(t)
	var mk []byte
	if err := resetAndProvisionPIV(f, "654321", "87654321", &mk); err != nil {
		t.Fatal(err)
	}
	if f.resetCount != 1 {
		t.Error("PIV should have been reset exactly once")
	}
	if f.pin != "654321" || f.puk != "87654321" {
		t.Errorf("creds = pin %q puk %q", f.pin, f.puk)
	}
	if len(mk) == 0 || string(mk) == string(piv.DefaultManagementKey) {
		t.Error("a fresh random management key should be set (not the factory default)")
	}
}

func TestGenerateSlotKeyAndSign(t *testing.T) {
	f := newFakePIV(t)
	pub, err := generateOnDevice(f, f.mgmt, "9a")
	if err != nil {
		t.Fatal(err)
	}
	// genesis stores a cert object so slotPublicKey can read the key back.
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "slot"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, f.keys[mustSlot(t, "9a")])
	cert, _ := x509.ParseCertificate(der)
	if err := setSlotCertificate(f, f.mgmt, "9a", cert); err != nil {
		t.Fatal(err)
	}
	got, err := slotPublicKey(f, "9a")
	if err != nil {
		t.Fatal(err)
	}
	gp, _ := ssh.NewPublicKey(got)
	pp, _ := ssh.NewPublicKey(pub)
	if gp.Marshal() == nil || string(gp.Marshal()) != string(pp.Marshal()) {
		t.Error("slotPublicKey should return the generated key")
	}

	// Sign an SSH cert with the slot-backed signer and verify it.
	signer, err := pivSigner(f, "9a", pub, "654321")
	if err != nil {
		t.Fatal(err)
	}
	caLine, _ := sshPubFromCryptoPub(pub, "ca")
	certOut, err := signSSHCert(signer, certSpec{certType: ssh.UserCert, keyID: "work:t", principals: []string{"t"}, serial: 1001, validity: "+13w"}, mustSSHPubLine(t))
	if err != nil {
		t.Fatal(err)
	}
	pk, _, _, _, _ := ssh.ParseAuthorizedKey(certOut)
	caPub, _, _, _, _ := ssh.ParseAuthorizedKey(caLine)
	checker := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool { return string(k.Marshal()) == string(caPub.Marshal()) }}
	if err := checker.CheckCert("t", pk.(*ssh.Certificate)); err != nil {
		t.Errorf("slot-signed cert should verify against the slot key: %v", err)
	}
}

func TestAttestSlotKey(t *testing.T) {
	f := newFakePIV(t)
	pub, err := generateOnDevice(f, f.mgmt, "82")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := attest(f, "82")
	if err != nil {
		t.Fatal(err)
	}
	cp, _ := ssh.NewPublicKey(cert.PublicKey)
	pp, _ := ssh.NewPublicKey(pub)
	if string(cp.Marshal()) != string(pp.Marshal()) {
		t.Error("attestation must vouch for the generated slot key")
	}
}

func TestStashAndRetrieveOnCard(t *testing.T) {
	f := newFakePIV(t)
	payload := []byte("id_yk-cert.pub carrier payload")
	if err := stashOnCard(f, f.mgmt, "9a", "id_yk", payload); err != nil {
		t.Fatal(err)
	}
	cert, err := slotCertificate(f, "9a")
	if err != nil {
		t.Fatal(err)
	}
	got, err := payloadFromCarrier(cert)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Errorf("round-tripped payload = %q, want %q", got, payload)
	}
}

func TestMgmtKeyFromMetadata(t *testing.T) {
	f := newFakePIV(t)
	custom := randomManagementKey()
	if err := f.SetMetadata(nil, &piv.Metadata{ManagementKey: &custom}); err != nil {
		t.Fatal(err)
	}
	if got := mgmtKey(f, "654321"); string(got) != string(custom) {
		t.Error("mgmtKey should return the PIN-protected management key from metadata")
	}
}

func mustSlot(t *testing.T, name string) piv.Slot {
	t.Helper()
	s, err := slotByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
