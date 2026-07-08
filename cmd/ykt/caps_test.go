package main

import (
	"slices"
	"strings"
	"testing"
)

func TestAtLeast(t *testing.T) {
	for _, tc := range []struct {
		v      [3]int
		a      [3]int
		expect bool
	}{
		{[3]int{5, 7, 0}, [3]int{5, 2, 3}, true},
		{[3]int{5, 2, 3}, [3]int{5, 2, 3}, true},
		{[3]int{5, 1, 2}, [3]int{5, 2, 3}, false},
		{[3]int{5, 2, 2}, [3]int{5, 2, 3}, false},
		{[3]int{6, 0, 0}, [3]int{5, 9, 9}, true},
		{[3]int{4, 9, 9}, [3]int{5, 0, 0}, false},
	} {
		if got := atLeast(tc.v, tc.a[0], tc.a[1], tc.a[2]); got != tc.expect {
			t.Errorf("atLeast(%v, %v) = %v, want %v", tc.v, tc.a, got, tc.expect)
		}
	}
}

func TestCapsForVersion(t *testing.T) {
	m := capsForVersion([3]int{5, 7, 0})
	if m.SSHKeyType != "ed25519-sk" || !m.ResidentSSH || !m.VerifyCapable || !m.Known {
		t.Errorf("5.7.0 caps = %+v", m)
	}
	o := capsForVersion([3]int{5, 1, 2})
	if o.SSHKeyType != "ecdsa-sk" || o.ResidentSSH {
		t.Errorf("5.1.2 caps = %+v", o)
	}
	// exactly at the 5.2.3 boundary → modern
	if capsForVersion([3]int{5, 2, 3}).SSHKeyType != "ed25519-sk" {
		t.Error("5.2.3 should be modern")
	}
}

func TestCapsForNilIsDryRun(t *testing.T) {
	d := capsFor(nil)
	if d.Known {
		t.Error("dry-run caps must be Known=false")
	}
	if d.SSHKeyType != "ed25519-sk" {
		t.Error("dry-run assumes a modern key")
	}
}

func TestSSHKeygenArgs(t *testing.T) {
	m := capsForVersion([3]int{5, 7, 0})
	args := m.sshKeygenArgs("/tmp/id_yk", false)
	if !slices.Contains(args, "ed25519-sk") || !slices.Contains(args, "resident") {
		t.Errorf("modern args = %v", args)
	}
	if slices.Contains(args, "verify-required") {
		t.Error("verify-required must be opt-in")
	}
	if !slices.Contains(m.sshKeygenArgs("/tmp/id_yk", true), "verify-required") {
		t.Error("verify-required requested but absent")
	}
	old := capsForVersion([3]int{5, 1, 2})
	if slices.Contains(old.sshKeygenArgs("/tmp/id_yk", false), "resident") {
		t.Error("old firmware must not request resident keys")
	}
}

func TestCapsSummary(t *testing.T) {
	if !strings.Contains(capsForVersion([3]int{5, 7, 0}).summary(), "resident") {
		t.Error("modern summary should say resident")
	}
	if !strings.Contains(capsForVersion([3]int{5, 1, 2}).summary(), "non-resident") {
		t.Error("old summary should say non-resident")
	}
}
