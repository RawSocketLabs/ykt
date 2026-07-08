package main

import "testing"

func validFixture() *Registry {
	return &Registry{
		Anchors: map[string]Anchor{
			"a1": {SerialBase: 1000},
			"a2": {SerialBase: 2000},
		},
		Domains: map[string]Domain{
			"work": {Anchors: []string{"a1", "a2"}, UserSlot: "82", HostSlot: "83", TLSSlot: "84"},
			"home": {Anchors: []string{"a1"}, UserSlot: "85", HostSlot: "86", TLSSlot: "87"},
		},
	}
}

func TestValidateRegistry(t *testing.T) {
	if err := validateRegistry(validFixture()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	t.Run("undefined anchor", func(t *testing.T) {
		r := validFixture()
		d := r.Domains["work"]
		d.Anchors = []string{"a1", "a9"}
		r.Domains["work"] = d
		if validateRegistry(r) == nil {
			t.Error("a domain referencing an undefined anchor must fail")
		}
	})

	t.Run("slot collision on one anchor", func(t *testing.T) {
		r := validFixture()
		d := r.Domains["work"]
		d.HostSlot = d.UserSlot // 82 twice on a1 → genesis would clobber
		r.Domains["work"] = d
		if validateRegistry(r) == nil {
			t.Error("two roles sharing a slot on one anchor must fail")
		}
	})

	t.Run("serial_base overlap", func(t *testing.T) {
		r := validFixture()
		r.Anchors["a2"] = Anchor{SerialBase: 1500} // <1000 from a1's 1000
		if validateRegistry(r) == nil {
			t.Error("overlapping serial_base blocks must fail")
		}
	})

	t.Run("empty required slot", func(t *testing.T) {
		r := validFixture()
		d := r.Domains["home"]
		d.TLSSlot = ""
		r.Domains["home"] = d
		if validateRegistry(r) == nil {
			t.Error("an empty slot must fail")
		}
	})

	t.Run("same slot on different anchors is fine", func(t *testing.T) {
		// home uses 85/86/87 on a1; a domain on a2 reusing 85 is OK (different device)
		r := validFixture()
		r.Domains["lab"] = Domain{Anchors: []string{"a2"}, UserSlot: "85", HostSlot: "88", TLSSlot: "89"}
		if err := validateRegistry(r); err != nil {
			t.Errorf("same slot on a different anchor should be allowed: %v", err)
		}
	})
}
