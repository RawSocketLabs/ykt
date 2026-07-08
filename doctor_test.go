package main

import "testing"

// TestCheckDailyKeySlots covers the daily-key slot-namespace validation: a
// clean map passes, and every kind of collision (cross-domain, stub-slot,
// invalid slot) is counted so doctor can flag it.
func TestCheckDailyKeySlots(t *testing.T) {
	reg := func(domains map[string]Domain) *Registry { return &Registry{Domains: domains} }

	cases := []struct {
		name string
		reg  *Registry
		want int
	}{
		{"clean", reg(map[string]Domain{
			"work": {ClientSlot: "9a", SSHCertSlot: "90"},
			"home": {ClientSlot: "9d", SSHCertSlot: "91"},
		}), 0},
		{"cross-domain collision", reg(map[string]Domain{
			"work": {ClientSlot: "9a", SSHCertSlot: "90"},
			"home": {ClientSlot: "9d", SSHCertSlot: "9a"}, // clashes work client_slot
		}), 1},
		{"two stash slots equal", reg(map[string]Domain{
			"work": {ClientSlot: "9a", SSHCertSlot: "90"},
			"home": {ClientSlot: "9d", SSHCertSlot: "90"}, // duplicate ssh_cert_slot
		}), 1},
		{"collides with stub slot", reg(map[string]Domain{
			"work": {ClientSlot: "9a", SSHCertSlot: sshKeyStashSlot}, // == id_yk stub slot
		}), 1},
		{"invalid slot", reg(map[string]Domain{
			"work": {ClientSlot: "9a", SSHCertSlot: "zz"},
		}), 1},
		{"route 2 off (no ssh_cert_slot)", reg(map[string]Domain{
			"work": {ClientSlot: "9a"},
			"home": {ClientSlot: "9d"},
		}), 0},
	}
	for _, tc := range cases {
		if got := checkDailyKeySlots(tc.reg); got != tc.want {
			t.Errorf("%s: checkDailyKeySlots = %d, want %d", tc.name, got, tc.want)
		}
	}
}
