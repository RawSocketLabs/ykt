package main

import (
	"os"
	"testing"
)

// TestGenesisProvisionsSlots runs the extracted genesis steps for all three CA
// roles against fakePIV, then confirms the published material and slot certs —
// the genesis ceremony's core, with no hardware.
func TestGenesisProvisionsSlots(t *testing.T) {
	dir := t.TempDir()
	withTrustHome(t, dir)
	f := newFakePIV(t)
	mk := f.mgmt

	for _, rs := range []struct{ role, slot string }{{"user", "9a"}, {"host", "9c"}, {"tls", "82"}} {
		pub, err := genesisGenerateSlot(f, mk, "a1", "work", rs.role, rs.slot)
		if err != nil {
			t.Fatalf("[%s] generate: %v", rs.role, err)
		}
		if _, err := os.Stat(caPubPEMPath("a1", "work", rs.role)); err != nil {
			t.Errorf("[%s] public-key PEM not written", rs.role)
		}
		if _, err := os.Stat(caAttestPath("a1", "work", rs.role)); err != nil {
			t.Errorf("[%s] slot attestation not written", rs.role)
		}
		if err := genesisStoreSlotCert(f, mk, "654321", "a1", "work", rs.role, rs.slot, pub); err != nil {
			t.Fatalf("[%s] store slot cert: %v", rs.role, err)
		}
	}

	// user/host publish an OpenSSH CA pub; tls publishes a CA:TRUE client cert.
	if _, err := os.Stat(caPubPath("work", "user", "a1")); err != nil {
		t.Error("user CA pub not published")
	}
	if _, err := os.Stat(caPubPath("work", "host", "a1")); err != nil {
		t.Error("host CA pub not published")
	}
	cert, err := loadCertPEM(clientCACertPath("work", "a1"))
	if err != nil || !cert.IsCA {
		t.Errorf("tls client-CA cert missing or not a CA: %v", err)
	}
	if len(f.certs) != 3 {
		t.Errorf("expected a slot cert in all 3 CA slots, got %d", len(f.certs))
	}

	// with the CA pubs in place, trust-file assembly now succeeds.
	reg := &Registry{
		Anchors: map[string]Anchor{"a1": {YubikeySerial: "12345678"}},
		Domains: map[string]Domain{"work": {Anchors: []string{"a1"}, HostPattern: "*.work.internal"}},
	}
	if err := assembleTrustFiles(reg, "work"); err != nil {
		t.Errorf("assembleTrustFiles after genesis: %v", err)
	}
}
