package main

import (
	"strings"
	"testing"
)

// TestParseLogins: extract user/from/key-id/serial/timestamp from both journald
// short-iso and classic syslog "Accepted publickey" lines.
func TestParseLogins(t *testing.T) {
	text := `2026-07-08T12:00:00+00:00 web1 sshd[123]: Accepted publickey for deploy from 10.0.0.5 port 51000 ssh2: ED25519-CERT SHA256:abc ID rsl:alice (serial 1004) CA ED25519 SHA256:def
Jul  8 12:05:00 web1 sshd[124]: Accepted publickey for root from 10.0.0.6 port 51001 ssh2: ED25519 SHA256:zzz
2026-07-08T13:00:00+00:00 web1 sshd[125]: Connection closed by 10.0.0.9`
	rows := parseLogins("web1", text)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (non-login line must be ignored)", len(rows))
	}
	r0 := rows[0]
	if r0.user != "deploy" || r0.from != "10.0.0.5" || r0.keyID != "rsl:alice" || r0.serial != "1004" {
		t.Errorf("cert login mis-parsed: %+v", r0)
	}
	if r0.when != "2026-07-08T12:00:00+00:00" {
		t.Errorf("iso timestamp = %q", r0.when)
	}
	r1 := rows[1]
	if r1.user != "root" || r1.keyID != "-" || r1.serial != "-" {
		t.Errorf("plain-key login should have no cert id: %+v", r1)
	}
	if r1.when != "Jul  8 12:05:00" {
		t.Errorf("syslog timestamp = %q", r1.when)
	}
}

// TestDropInLogLevel: the drop-in carries LogLevel when set, omits it when empty.
func TestDropInLogLevel(t *testing.T) {
	old := sshdLogLevel
	defer func() { sshdLogLevel = old }()

	sshdLogLevel = "VERBOSE"
	if !strings.Contains(buildHostDropIn([]string{"work"}, false, false), "LogLevel VERBOSE") {
		t.Error("drop-in should set LogLevel VERBOSE for login attribution")
	}
	sshdLogLevel = ""
	if strings.Contains(buildHostDropIn([]string{"work"}, false, false), "LogLevel") {
		t.Error("empty log level should omit the LogLevel directive")
	}
}

// TestHarvestScriptQuotesSince: the --since value is shell-quoted, not interpolated raw.
func TestHarvestScriptQuotesSince(t *testing.T) {
	s := harvestScript("7 days ago; rm -rf /")
	if strings.Contains(s, "days ago; rm -rf /'") == false && !strings.Contains(s, "'7 days ago; rm -rf /'") {
		t.Errorf("since value not safely quoted: %s", s)
	}
}
