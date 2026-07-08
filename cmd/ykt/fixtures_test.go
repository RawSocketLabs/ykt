package main

import (
	"os"
	"path/filepath"
	"testing"

	ykt "github.com/RawSocketLabs/ykt"
)

// withTrustHome points the global trustHome at dir for the duration of a test.
func withTrustHome(t *testing.T, dir string) {
	t.Helper()
	old := trustHome
	trustHome = dir
	t.Cleanup(func() { trustHome = old })
}

func writeFixture(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestLoadLedger: TSV parsing — serials, fields, and the REVOKED flag.
func TestLoadLedger(t *testing.T) {
	dir := t.TempDir()
	withTrustHome(t, dir)
	writeFixture(t, dir, "index/work.tsv",
		"# serial\ttype\tidentity\tprincipals\tanchor\tsigned\texpires\tfile\n"+
			"1001\tuser\talice\talice\ta1\t2026-01-01\t2027-01-01\tdist/work/user_alice-cert.pub\n"+
			"1002\ttls\tweb1\t-\ta1\t2026-01-01\t2026-02-01\tdist/work/tls_web1.crt\tREVOKED\n")

	e := loadLedger("work")
	if len(e) != 2 {
		t.Fatalf("got %d entries, want 2", len(e))
	}
	if e[0].Serial != 1001 || e[0].Type != "user" || e[0].Identity != "alice" {
		t.Errorf("row 0 mis-parsed: %+v", e[0])
	}
	if e[0].Revoked {
		t.Error("row 0 should not be revoked")
	}
	if !e[1].Revoked {
		t.Error("row 1 should be REVOKED")
	}
	if loadLedger("nonexistent") != nil {
		t.Error("missing ledger should return nil, not fail")
	}
}

// TestExpiringCerts: only non-revoked certs past the cutoff are surfaced.
func TestExpiringCerts(t *testing.T) {
	dir := t.TempDir()
	withTrustHome(t, dir)
	writeFixture(t, dir, "index/work.tsv",
		"1\tuser\tsoon\tsoon\ta1\t2020-01-01\t2020-02-01\tf1\n"+ // expired → include
			"2\tuser\tlater\tlater\ta1\t2020-01-01\t2099-01-01\tf2\n"+ // future → exclude
			"3\ttls\trevoked\t-\ta1\t2020-01-01\t2020-02-01\tf3\tREVOKED\n") // revoked → exclude

	reg := &Registry{Domains: map[string]Domain{"work": {}}}
	ex := expiringCerts(reg, 21)
	if len(ex) != 1 {
		t.Fatalf("expected 1 expiring cert, got %d: %+v", len(ex), ex)
	}
	if ex[0].Entry.Identity != "soon" {
		t.Errorf("wrong entry surfaced: %+v", ex[0].Entry)
	}
}

// TestLoadRegistryFromExample: the bundled config.toml.example parses and yields
// domains + anchors — guards the shipped template against drift.
func TestLoadRegistryFromExample(t *testing.T) {
	if len(ykt.ConfigExample) == 0 {
		t.Skip("no embedded config example")
	}
	dir := t.TempDir()
	withTrustHome(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), ykt.ConfigExample, 0o644); err != nil {
		t.Fatal(err)
	}
	reg := loadRegistry()
	if len(reg.Domains) == 0 {
		t.Error("example config should define [domains.*]")
	}
	if len(reg.Anchors) == 0 {
		t.Error("example config should define [anchors.*]")
	}
	if len(reg.domainNames()) != len(reg.Domains) {
		t.Error("domainNames() count should match Domains")
	}
}
