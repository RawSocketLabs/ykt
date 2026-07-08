package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseUint32(t *testing.T) {
	if n, err := parseUint32("9749071"); err != nil || n != 9749071 {
		t.Errorf("parseUint32(9749071) = %d, %v", n, err)
	}
	for _, bad := range []string{"unset", "", "-1", "99999999999999", "abc"} {
		if _, err := parseUint32(bad); err == nil {
			t.Errorf("parseUint32(%q) should error", bad)
		}
	}
}

// TestBuildAnchorRecord: the record carries the serial and per-domain CA
// fingerprints assembled from the published pub/ material.
func TestBuildAnchorRecord(t *testing.T) {
	dir := t.TempDir()
	withTrustHome(t, dir)
	reg := &Registry{
		Anchors: map[string]Anchor{"a1": {Holder: "mike", YubikeySerial: "9749071"}},
		Domains: map[string]Domain{"work": {Anchors: []string{"a1"}, HostPattern: "*.work.internal"}},
	}
	writeFixture(t, dir, filepath.Join("pub", "work_user_ca_a1.pub"), string(mustSSHPubLine(t)))
	writeFixture(t, dir, filepath.Join("pub", "work_host_ca_a1.pub"), string(mustSSHPubLine(t)))
	// a real client-CA cert so the tls fingerprint path is exercised
	caCert, err := makeClientCACert(mustEd25519(t), "work client CA")
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCertPEM(clientCACertPath("work", "a1"), caCert); err != nil {
		t.Fatal(err)
	}

	rec := buildAnchorRecord(reg, "a1", 9749071)
	if rec.Serial != 9749071 {
		t.Errorf("serial = %d", rec.Serial)
	}
	e := rec.Domains["work"]
	if !strings.HasPrefix(e["user"], "SHA256:") || !strings.HasPrefix(e["host"], "SHA256:") {
		t.Errorf("user/host fingerprints = %q / %q", e["user"], e["host"])
	}
	if e["tls"] == "" {
		t.Error("tls fingerprint missing")
	}

	// write() emits JSON to disk
	p := filepath.Join(dir, "a1.json")
	if err := rec.write(p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "9749071") {
		t.Errorf("record JSON missing serial: %s", b)
	}
}
