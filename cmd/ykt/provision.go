package main

// Idempotent PIV provisioning. The previous inline version was not safe to
// retry: once SetPIN(DefaultPIN, newPIN) succeeded, a later failure in the
// same closure left the PIN non-default, so runTask's [r]etry re-ran
// SetPIN(DefaultPIN, ...) forever. Here the factory reset is part of the same
// retryable unit, so every attempt starts from a known default state.

import (
	"fmt"

	"github.com/go-piv/piv-go/v2/piv"
)

// resetAndProvisionPIV factory-resets the PIV applet, then sets the PIN, PUK,
// and a fresh PIN-protected management key. Safe to retry from any state
// because Reset() restores defaults first. Returns the new management key.
//
// The returned *[]byte is written into mkOut so the caller sees the key even
// though this runs inside an act() closure (which only returns error).
func resetAndProvisionPIV(yk *piv.YubiKey, pin, puk string, mkOut *[]byte) error {
	if err := yk.Reset(); err != nil {
		return fmt.Errorf("reset: %w", err)
	}
	if err := yk.SetPIN(piv.DefaultPIN, pin); err != nil {
		return fmt.Errorf("SetPIN: %w", err)
	}
	if err := yk.SetPUK(piv.DefaultPUK, puk); err != nil {
		return fmt.Errorf("SetPUK: %w", err)
	}
	newKey := randomManagementKey()
	if err := yk.SetManagementKey(piv.DefaultManagementKey, newKey); err != nil {
		return fmt.Errorf("SetManagementKey: %w", err)
	}
	if err := yk.SetMetadata(newKey, &piv.Metadata{ManagementKey: &newKey}); err != nil {
		return fmt.Errorf("store protected management key: %w", err)
	}
	*mkOut = newKey
	return nil
}
