package main

import (
	"path/filepath"
	"slices"
	"testing"
)

// TestAnchorDomainState: a domain is "present" only with all three role artifacts;
// some-but-not-all is "partial" (interrupted genesis) so init ca won't skip it.
func TestAnchorDomainState(t *testing.T) {
	dir := t.TempDir()
	withTrustHome(t, dir)

	// fully provisioned
	writeFixture(t, dir, filepath.Join("pub", "full_user_ca_a1.pub"), "k\n")
	writeFixture(t, dir, filepath.Join("pub", "full_host_ca_a1.pub"), "k\n")
	writeFixture(t, dir, filepath.Join("pub", "full_client_ca_a1.crt"), "c\n")
	// partial: user pub only (the exact interrupted-genesis case)
	writeFixture(t, dir, filepath.Join("pub", "half_user_ca_a1.pub"), "k\n")
	// "none" domain writes nothing.

	missing, present, partial := anchorDomainState("a1", []string{"full", "half", "none"})
	if !slices.Equal(present, []string{"full"}) {
		t.Errorf("present = %v, want [full]", present)
	}
	if !slices.Equal(partial, []string{"half"}) {
		t.Errorf("partial = %v, want [half] (user pub without host/tls)", partial)
	}
	if !slices.Equal(missing, []string{"none"}) {
		t.Errorf("missing = %v, want [none]", missing)
	}
}
