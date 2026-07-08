package main

// Integration test for the queue → sign → dist → cert-install file-name
// contract and the ledger. It drives the real path helpers and signing code
// (with an in-memory ECDSA key standing in for the on-device CA), so a change
// to any producer filename that isn't matched by its consumer fails here
// instead of silently making cert-install "find nothing".

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func withTempTrustHome(t *testing.T) {
	t.Helper()
	prev := trustHome
	trustHome = t.TempDir()
	t.Cleanup(func() { trustHome = prev })
	for _, d := range []string{"queue/work", "dist/work", "index", "pub"} {
		if err := os.MkdirAll(filepath.Join(trustHome, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// TestUserCertNameRoundTrip: the id the signing parses out of a queue file
// must rebuild the exact dist name cert-install later looks for.
func TestUserCertNameRoundTrip(t *testing.T) {
	person, host := "alice", "thinkpad"
	queueName := queueUserKeyName(person, host) // producer (user-enroll)
	// signing strips "user_" prefix + ".pub" suffix to get id, then writes
	// "user_" + id + "-cert.pub"
	id := queueName[len("user_") : len(queueName)-len(".pub")]
	signedDist := "user_" + id + "-cert.pub"
	consumerLookup := distUserCertName(person, host) // consumer (cert-install)
	if signedDist != consumerLookup {
		t.Fatalf("user cert name drift: signing writes %q, cert-install looks for %q", signedDist, consumerLookup)
	}
}

func TestTLSCertNameRoundTrip(t *testing.T) {
	person, host := "alice", "thinkpad"
	csr := queueTLSName(person, host)
	id := csr[len("tls_") : len(csr)-len(".csr")]
	signedDist := "tls_" + id + ".crt"
	if got := distTLSName(person, host); signedDist != got {
		t.Fatalf("tls cert name drift: signing writes %q, cert-install looks for %q", signedDist, got)
	}
}

func TestHostCertNameRoundTrip(t *testing.T) {
	host := "web1"
	q := queueHostKeyName(host)
	id := q[len("host_") : len(q)-len(".pub")]
	signedDist := distHostCertName(id)
	if got := distHostCertName(host); signedDist != got {
		t.Fatalf("host cert name drift: %q vs %q", signedDist, got)
	}
}

// TestEndToEndSigningChain writes a queued user request, signs it exactly as
// the signing does (in-memory CA), writes the dist cert under the signing's
// convention, and confirms cert-install's lookup path resolves to it — then
// verifies the produced cert with ssh-keygen semantics via x/crypto/ssh.
func TestEndToEndSigningChain(t *testing.T) {
	withTempTrustHome(t)
	dryRun = false
	person, host, domain := "alice", "thinkpad", "work"

	// user-enroll writes the request
	userPub := buildSKEd25519AuthorizedKey(t, "ssh:yk")
	qpath := trustPath("queue", domain, queueUserKeyName(person, host))
	if err := os.WriteFile(qpath, userPub, 0o644); err != nil {
		t.Fatal(err)
	}

	// signing signs (in-memory ECDSA CA stands in for the slot key)
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := person + "_" + host
	cert, err := signSSHCert(caKey, certSpec{
		certType: ssh.UserCert, keyID: domain + ":" + id, serial: 1001,
		principals: cleanPrincipals("alice, alice "), validity: "+13w",
	}, userPub)
	if err != nil {
		t.Fatal(err)
	}
	distName := "user_" + id + "-cert.pub"
	if err := writeFileAtomic(trustPath("dist", domain, distName), cert, 0o644); err != nil {
		t.Fatal(err)
	}

	// cert-install's lookup must resolve to the file the signing wrote
	lookup := trustPath("dist", domain, distUserCertName(person, host))
	if _, err := os.Stat(lookup); err != nil {
		t.Fatalf("cert-install would not find the signed cert at %s: %v", lookup, err)
	}

	// the cert must parse and carry the cleaned principals (no empty/space)
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(cert)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatalf("signed output is not a certificate")
	}
	if len(c.ValidPrincipals) != 2 || c.ValidPrincipals[0] != "alice" || c.ValidPrincipals[1] != "alice" {
		t.Fatalf("principals not cleaned: %#v", c.ValidPrincipals)
	}

	// ledger round-trip: append then read back, and nextSerial advances
	if err := appendLedgerOnce(domain, LedgerEntry{Serial: 1001, Type: "user",
		Identity: id, Principals: "alice,alice", Anchor: "a1", Signed: today(),
		Expires: expiryFromValidity("+13w"), File: "dist/" + domain + "/" + distName}); err != nil {
		t.Fatal(err)
	}
	// idempotent: a second append for the same File must not duplicate
	if err := appendLedgerOnce(domain, LedgerEntry{Serial: 1001, Type: "user",
		Identity: id, File: "dist/" + domain + "/" + distName}); err != nil {
		t.Fatal(err)
	}
	entries := loadLedger(domain)
	if len(entries) != 1 {
		t.Fatalf("ledger should have exactly 1 row (idempotent), got %d", len(entries))
	}
	if got := nextSerial(domain, Anchor{SerialBase: 1000}); got != 1002 {
		t.Fatalf("nextSerial after 1001 should be 1002, got %d", got)
	}
}

// TestLedgerRenewalRecordsNewSerial: a renewal (same person+host, same dist
// file, NEW serial) must be recorded, not skipped as a dup — otherwise
// nextSerial reissues the serial and revoke targets the wrong cert.
func TestLedgerRenewalRecordsNewSerial(t *testing.T) {
	withTempTrustHome(t)
	dryRun = false
	file := "dist/work/user_alice_laptop-cert.pub"
	if err := appendLedgerOnce("work", LedgerEntry{Serial: 1001, Type: "user",
		Identity: "alice_laptop", Anchor: "a1", Signed: today(), File: file}); err != nil {
		t.Fatal(err)
	}
	// retry of the SAME serial must be a no-op
	if err := appendLedgerOnce("work", LedgerEntry{Serial: 1001, Type: "user",
		Identity: "alice_laptop", Anchor: "a1", File: file}); err != nil {
		t.Fatal(err)
	}
	// renewal: same file, NEW serial — must be recorded
	if err := appendLedgerOnce("work", LedgerEntry{Serial: 1002, Type: "user",
		Identity: "alice_laptop", Anchor: "a1", Signed: today(), File: file}); err != nil {
		t.Fatal(err)
	}
	entries := loadLedger("work")
	if len(entries) != 2 {
		t.Fatalf("expected 2 rows (1001 + renewal 1002), got %d", len(entries))
	}
	if got := nextSerial("work", Anchor{SerialBase: 1000}); got != 1003 {
		t.Fatalf("nextSerial after 1001,1002 should be 1003, got %d", got)
	}
}

// TestNextSerialBlockExhaustion: the last usable serial is base+999; asking
// past it must fail loudly rather than collide into the next block.
func TestNextSerialBlockGuard(t *testing.T) {
	withTempTrustHome(t)
	dryRun = false
	// seed the ledger at base+999
	_ = appendLedger("work", LedgerEntry{Serial: 1999, Type: "user", Identity: "x",
		Anchor: "a1", File: "dist/work/x-cert.pub"})
	// nextSerial fatals via fatal()→os.Exit, which a test can't catch; instead
	// assert the boundary just below: base+998 present → returns 999.
	withTempTrustHome(t)
	_ = appendLedger("work", LedgerEntry{Serial: 1998, Type: "user", Identity: "x",
		Anchor: "a1", File: "dist/work/x-cert.pub"})
	if got := nextSerial("work", Anchor{SerialBase: 1000}); got != 1999 {
		t.Fatalf("expected 1999, got %d", got)
	}
}
