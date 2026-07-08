package main

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-piv/piv-go/v2/piv"
)

func TestShortHostAndTernary(t *testing.T) {
	if shortHost("web1.work.internal") != "web1" {
		t.Error("shortHost should strip at the first dot")
	}
	if shortHost("web1") != "web1" {
		t.Error("shortHost of a bare name is itself")
	}
	if ternary(true, "a", "b") != "a" || ternary(false, "a", "b") != "b" {
		t.Error("ternary")
	}
	if remoteSuffix("") != "" || !strings.Contains(remoteSuffix("git@x:y.git"), "git@x:y.git") {
		t.Error("remoteSuffix")
	}
}

func TestPolicyNames(t *testing.T) {
	if touchName(piv.TouchPolicyCached) != "cached" || touchName(piv.TouchPolicyAlways) != "always" || touchName(piv.TouchPolicyNever) != "never" {
		t.Error("touchName mapping")
	}
	if pinName(piv.PINPolicyOnce) != "once" || pinName(piv.PINPolicyAlways) != "always" || pinName(piv.PINPolicyNever) != "never" {
		t.Error("pinName mapping")
	}
	if touchName(piv.TouchPolicy(99)) != "?" {
		t.Error("unknown touch policy → ?")
	}
}

func TestPrefixEachAndIncludeBlock(t *testing.T) {
	got := prefixEach([]string{"a", "b"}, "x", "y")
	if !slices.Equal(got, []string{"xay", "xby"}) {
		t.Errorf("prefixEach = %v", got)
	}
	blk := managedIncludeBlock([]string{"work", "home"})
	for _, want := range []string{sshBeginMarker, "Include ykt/work/*.conf", "Include ykt/home/*.conf", sshEndMarker} {
		if !strings.Contains(blk, want) {
			t.Errorf("managedIncludeBlock missing %q", want)
		}
	}
}

func TestHostConfEntry(t *testing.T) {
	reg := &Registry{Domains: map[string]Domain{"work": {HostPattern: "*.work.internal", DefaultPrincipal: "alice"}}}
	// address differs from the FQDN → HostName is the address, verify as the FQDN
	e := hostConfEntry(reg, "work", "web1", "10.0.0.1", "", 2222)
	for _, want := range []string{
		"Host web1 web1.work.internal", "HostName 10.0.0.1", "HostKeyAlias web1.work.internal",
		"User alice", "Port 2222", "CertificateFile ~/.ssh/id_work-cert.pub", "IdentitiesOnly yes",
	} {
		if !strings.Contains(e, want) {
			t.Errorf("hostConfEntry missing %q in:\n%s", want, e)
		}
	}
	// no address → HostName is the FQDN, no HostKeyAlias, default port omitted
	e2 := hostConfEntry(reg, "work", "web1", "", "bob", 22)
	if !strings.Contains(e2, "HostName web1.work.internal") || strings.Contains(e2, "HostKeyAlias") || strings.Contains(e2, "Port ") {
		t.Errorf("hostConfEntry(no address) unexpected:\n%s", e2)
	}
	if !strings.Contains(e2, "User bob") {
		t.Error("explicit user should win")
	}
}

func TestDomainDefaults(t *testing.T) {
	d := domainDefaults(Domain{HostPattern: "*.work.internal"}, "work")
	if !strings.Contains(d, "Match host *.work.internal") || !strings.Contains(d, "CertificateFile ~/.ssh/id_work-cert.pub") {
		t.Errorf("domainDefaults:\n%s", d)
	}
}

func TestBootstrapHelpers(t *testing.T) {
	if !strings.Contains(bootstrapDropIn(), "TrustedUserCAKeys "+hostTrustCAFile) {
		t.Error("bootstrapDropIn")
	}
	stripped := stripCAComment([]byte("ssh-ed25519 AAAAKEY test-user-ca-a1\n"))
	if stripped != "ssh-ed25519 AAAAKEY" {
		t.Errorf("stripCAComment = %q (should drop the identifying comment)", stripped)
	}

	dir := t.TempDir()
	withTrustHome(t, dir)
	writeFixture(t, dir, filepath.Join("pub", "work_trusted_user_ca.pub"), "ssh-ed25519 AAAAKEY work-user-ca-a1\n")
	if got := bootstrapMaterial("work"); got != "ssh-ed25519 AAAAKEY" {
		t.Errorf("bootstrapMaterial = %q", got)
	}
}

func TestPathBuilders(t *testing.T) {
	dir := t.TempDir()
	withTrustHome(t, dir)
	for _, tc := range []struct {
		got, wantSuffix string
	}{
		{caPubPath("work", "user", "a1"), "pub/work_user_ca_a1.pub"},
		{caPubPEMPath("a1", "work", "tls"), "pub/a1_work_tls_pub.pem"},
		{clientCACertPath("work", "a1"), "pub/work_client_ca_a1.crt"},
		{trustedUserCAPath("work"), "pub/work_trusted_user_ca.pub"},
		{krlPath("work"), "pub/work.krl"},
		{caAttestPath("a1", "work", "host"), "pub/a1_work_host_attest.pem"},
	} {
		if !strings.HasSuffix(tc.got, tc.wantSuffix) {
			t.Errorf("path = %q, want suffix %q", tc.got, tc.wantSuffix)
		}
	}
}

func TestGatherHostCAAndSingleKRL(t *testing.T) {
	dir := t.TempDir()
	withTrustHome(t, dir)
	writeFixture(t, dir, filepath.Join("pub", "work_trusted_user_ca.pub"), "ssh-ed25519 AAA work-ca\n")
	writeFixture(t, dir, filepath.Join("pub", "home_trusted_user_ca.pub"), "ssh-ed25519 BBB home-ca\n")

	ca, err := gatherHostCA([]string{"work", "home"})
	if err != nil || !strings.Contains(string(ca), "AAA") || !strings.Contains(string(ca), "BBB") {
		t.Errorf("gatherHostCA should concatenate both: %q err=%v", ca, err)
	}
	if _, err := gatherHostCA([]string{"nope"}); err == nil {
		t.Error("missing CA should error")
	}

	if singleKRL([]string{"work", "home"}) != nil {
		t.Error("multi-domain singleKRL must be nil")
	}
	if singleKRL([]string{"work"}) != nil {
		t.Error("no KRL file → nil")
	}
	writeFixture(t, dir, filepath.Join("pub", "work.krl"), "krl-bytes")
	if got := singleKRL([]string{"work"}); string(got) != "krl-bytes" {
		t.Errorf("singleKRL = %q", got)
	}
}

func TestMarkRevoked(t *testing.T) {
	dir := t.TempDir()
	withTrustHome(t, dir)
	writeFixture(t, dir, filepath.Join("index", "work.tsv"),
		"1001\tuser\talice\talice\ta1\t2026-01-01\t2027-01-01\tf1\n"+
			"1002\tuser\tbob\tbob\ta1\t2026-01-01\t2027-01-01\tf2\n")

	marked, notFound, err := markRevoked("work", []uint64{1001, 9999})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(marked, []uint64{1001}) {
		t.Errorf("marked = %v, want [1001]", marked)
	}
	if !slices.Equal(notFound, []uint64{9999}) {
		t.Errorf("notFound = %v, want [9999]", notFound)
	}
	e := loadLedger("work")
	if !e[0].Revoked || e[1].Revoked {
		t.Errorf("only serial 1001 should be revoked: %+v", e)
	}
	// idempotent: re-revoking 1001 marks nothing new
	if m, _, _ := markRevoked("work", []uint64{1001}); len(m) != 0 {
		t.Error("re-revoking should be a no-op")
	}
}

func TestResolveMachines(t *testing.T) {
	reg := &Registry{Domains: map[string]Domain{"work": {}}}
	inv := &Inventory{Machines: map[string]Machine{
		"web1": {Domain: "work"}, "web2": {Domain: "work"},
	}}
	if all := resolveMachines(reg, inv, "work", nil); len(all) != 2 {
		t.Errorf("no names → all in domain, got %v", all)
	}
	if one := resolveMachines(reg, inv, "work", []string{"web1"}); !slices.Equal(one, []string{"web1"}) {
		t.Errorf("named machine = %v", one)
	}
}
