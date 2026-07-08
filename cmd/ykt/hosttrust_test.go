package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestTrustedDomains: primary first, additional Trust domains appended, deduped,
// empties dropped.
func TestTrustedDomains(t *testing.T) {
	m := Machine{Domain: "work", Trust: []string{"home", "work", "", "lab"}}
	if got, want := m.trustedDomains(), []string{"work", "home", "lab"}; !slices.Equal(got, want) {
		t.Errorf("trustedDomains = %v, want %v", got, want)
	}
	if got := (Machine{Domain: "solo"}).trustedDomains(); !slices.Equal(got, []string{"solo"}) {
		t.Errorf("single-domain host = %v, want [solo]", got)
	}
}

// TestIsTrustStore: only a config.toml that declares a domain counts as a store.
func TestIsTrustStore(t *testing.T) {
	dir := t.TempDir()
	if isTrustStore(dir) {
		t.Error("no config.toml → not a store")
	}
	cfg := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfg, []byte("name = \"some-other-project\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if isTrustStore(dir) {
		t.Error("a config.toml without [domains.*] must not be treated as a ykt store")
	}
	if err := os.WriteFile(cfg, []byte("[domains.work]\nuser_slot = \"82\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !isTrustStore(dir) {
		t.Error("a config.toml with a domain is a store")
	}
}

// TestBuildHostDropIn: the drop-in reflects the trusted domains, cert, KRL, and
// log level — and omits directives whose material is absent.
func TestBuildHostDropIn(t *testing.T) {
	old := sshdLogLevel
	defer func() { sshdLogLevel = old }()
	sshdLogLevel = "VERBOSE"

	full := buildHostDropIn([]string{"work", "home"}, true, true)
	for _, want := range []string{
		"trusts domain(s): work home", "TrustedUserCAKeys " + hostTrustCAFile,
		"HostCertificate " + hostCertFile, "RevokedKeys " + hostTrustKRLFile, "LogLevel VERBOSE",
	} {
		if !strings.Contains(full, want) {
			t.Errorf("drop-in missing %q in:\n%s", want, full)
		}
	}
	bare := buildHostDropIn([]string{"work"}, false, false)
	if strings.Contains(bare, "HostCertificate") || strings.Contains(bare, "RevokedKeys") {
		t.Errorf("drop-in should omit cert/KRL when absent:\n%s", bare)
	}
}

// TestHostKRLBytesMultiDomain: a multi-domain host's KRL merges revoked serials
// from every trusted domain (so revocation reaches multi-domain hosts).
func TestHostKRLBytesMultiDomain(t *testing.T) {
	dir := t.TempDir()
	withTrustHome(t, dir)

	if hostKRLBytes([]string{"d1", "d2"}) != nil {
		t.Fatal("no revocations yet → nil KRL")
	}

	for i, dn := range []string{"d1", "d2"} {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(priv.Public())
		if err != nil {
			t.Fatal(err)
		}
		writeFixture(t, dir, filepath.Join("pub", dn+"_user_ca_a1.pub"), string(ssh.MarshalAuthorizedKey(pub)))
		serial := strconv.Itoa(1001 + i)
		writeFixture(t, dir, filepath.Join("index", dn+".tsv"),
			// a revoked user cert in this domain
			serial+"\tuser\tp\tp\ta1\t2026-01-01\t2027-01-01\tf\tREVOKED\n")
	}

	b := hostKRLBytes([]string{"d1", "d2"})
	if b == nil {
		t.Fatal("expected a merged KRL for revoked serials across both domains")
	}
	if len(b) < 8 || binary.BigEndian.Uint64(b[:8]) != krlMagic {
		t.Fatal("merged KRL doesn't start with the KRL magic")
	}
}
