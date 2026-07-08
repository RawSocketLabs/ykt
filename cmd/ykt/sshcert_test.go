package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func mustEd25519(t *testing.T) crypto.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// mustSSHPubLine returns a fresh ed25519 public key in authorized_keys format.
func mustSSHPubLine(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return ssh.MarshalAuthorizedKey(sp)
}

func TestParseValidity(t *testing.T) {
	for _, tc := range []struct {
		in    string
		hours float64
		bad   bool
	}{
		{"+13w", 13 * 7 * 24, false},
		{"+90d", 90 * 24, false},
		{"+12h", 12, false},
		{"13w", 13 * 7 * 24, false}, // leading + optional
		{"+1y", 0, true},            // unknown unit
		{"+w", 0, true},             // no number
		{"", 0, true},
		{"+abcd", 0, true},
	} {
		d, err := parseValidity(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("parseValidity(%q) should error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseValidity(%q) = %v", tc.in, err)
			continue
		}
		if d.Hours() != tc.hours {
			t.Errorf("parseValidity(%q) = %v hours, want %v", tc.in, d.Hours(), tc.hours)
		}
	}
}

func TestSignSSHCertUser(t *testing.T) {
	ca := mustEd25519(t)
	spec := certSpec{certType: ssh.UserCert, keyID: "work:alice", principals: []string{"alice", "root"}, serial: 1042, validity: "+13w"}
	out, err := signSSHCert(ca, spec, mustSSHPubLine(t))
	if err != nil {
		t.Fatal(err)
	}
	pk, comment, _, _, err := ssh.ParseAuthorizedKey(out)
	if err != nil {
		t.Fatal(err)
	}
	cert, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatal("output is not an SSH certificate")
	}
	if cert.CertType != ssh.UserCert {
		t.Error("wrong cert type")
	}
	if cert.KeyId != "work:alice" || comment != "work:alice" {
		t.Errorf("keyID/comment = %q / %q", cert.KeyId, comment)
	}
	if cert.Serial != 1042 {
		t.Errorf("serial = %d", cert.Serial)
	}
	if !reflect.DeepEqual(cert.ValidPrincipals, []string{"alice", "root"}) {
		t.Errorf("principals = %v", cert.ValidPrincipals)
	}
	if _, ok := cert.Extensions["permit-pty"]; !ok {
		t.Error("user cert should carry default extensions")
	}
	if span := cert.ValidBefore - cert.ValidAfter; span < uint64(13*7*24*3600-3600) {
		t.Errorf("validity span %d too short", span)
	}

	// The certificate must actually verify against the CA key that signed it.
	caPub, _ := ssh.NewPublicKey(ca.Public())
	checker := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool {
		return bytes.Equal(k.Marshal(), caPub.Marshal())
	}}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Errorf("signed cert should verify: %v", err)
	}
}

func TestSignSSHCertHostHasNoUserExtensions(t *testing.T) {
	out, err := signSSHCert(mustEd25519(t), certSpec{
		certType: ssh.HostCert, keyID: "host:web1", principals: []string{"web1.work.internal"}, serial: 2001, validity: "+54w",
	}, mustSSHPubLine(t))
	if err != nil {
		t.Fatal(err)
	}
	pk, _, _, _, _ := ssh.ParseAuthorizedKey(out)
	cert := pk.(*ssh.Certificate)
	if cert.CertType != ssh.HostCert {
		t.Error("wrong cert type")
	}
	if len(cert.Extensions) != 0 {
		t.Errorf("host cert must not carry user extensions, got %v", cert.Extensions)
	}
}

func TestSignSSHCertBadValidity(t *testing.T) {
	if _, err := signSSHCert(mustEd25519(t), certSpec{certType: ssh.UserCert, validity: "nonsense"}, mustSSHPubLine(t)); err == nil {
		t.Error("a bad validity should fail signing")
	}
}

func TestSSHHelpers(t *testing.T) {
	line := mustSSHPubLine(t)
	if err := validSSHPublicKey(line); err != nil {
		t.Errorf("valid key rejected: %v", err)
	}
	if err := validSSHPublicKey([]byte("not a key")); err == nil {
		t.Error("garbage should be rejected")
	}
	if fp := sshFingerprint(line); !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("fingerprint = %q, want SHA256: prefix", fp)
	}
	if sshFingerprint([]byte("garbage")) != "(unparseable key)" {
		t.Error("unparseable key should report so")
	}
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	l, err := sshPubFromCryptoPub(pub, "my-comment")
	if err != nil || !strings.Contains(string(l), "my-comment") {
		t.Errorf("sshPubFromCryptoPub = %q, err=%v", l, err)
	}
}

// TestAssembleTrustFiles: builds the trusted-user-CA + @cert-authority files from
// the configured anchors, and refuses to silently drop a provisioned anchor.
func TestAssembleTrustFiles(t *testing.T) {
	dir := t.TempDir()
	withTrustHome(t, dir)
	reg := &Registry{
		Anchors: map[string]Anchor{"a1": {YubikeySerial: "9749071"}},
		Domains: map[string]Domain{"work": {Anchors: []string{"a1"}, HostPattern: "*.work.internal"}},
	}
	// write the a1 user + host CA pubs
	writeFixture(t, dir, filepath.Join("pub", "work_user_ca_a1.pub"), string(mustSSHPubLine(t)))
	writeFixture(t, dir, filepath.Join("pub", "work_host_ca_a1.pub"), string(mustSSHPubLine(t)))

	if err := assembleTrustFiles(reg, "work"); err != nil {
		t.Fatalf("assembleTrustFiles: %v", err)
	}
	tu, err := readFixture(trustedUserCAPath("work"))
	if err != nil || !strings.Contains(tu, "ssh-ed25519") {
		t.Errorf("trusted user CA not assembled: %q err=%v", tu, err)
	}
	kh, _ := readFixture(certAuthorityKnownHostsPath("work"))
	if !strings.Contains(kh, "@cert-authority *.work.internal,work.internal ") {
		t.Errorf("@cert-authority line missing/incorrect: %q", kh)
	}

	// a provisioned anchor whose user CA is absent must be a hard error.
	reg.Anchors["a2"] = Anchor{YubikeySerial: "35204661"}
	d := reg.Domains["work"]
	d.Anchors = []string{"a1", "a2"}
	reg.Domains["work"] = d
	if err := assembleTrustFiles(reg, "work"); err == nil {
		t.Error("a provisioned anchor with a missing CA pub must fail, not silently drop it")
	}
}
