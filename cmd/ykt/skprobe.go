package main

// FIDO2 toolchain preflight. macOS ships an ssh-keygen without FIDO middleware
// ("No FIDO SecurityKeyProvider specified"), and enrollment factory-resets the
// key BEFORE generating the sk credential — so a broken toolchain strands the
// operator with a wiped key. We probe capability up front, before any reset.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// sshKeygenPath returns the ssh-keygen ykt should invoke for FIDO2 sk keys,
// preferring a FIDO-capable build over the platform default. macOS's system
// /usr/bin/ssh-keygen ships WITHOUT FIDO middleware, so Homebrew/MacPorts
// locations are tried first and ykt calls the result by ABSOLUTE PATH — the user
// never has to reorder their PATH. Elsewhere (and if no known-good build is
// found) it falls back to a PATH lookup, then the bare name.
func sshKeygenPath() string {
	if runtime.GOOS == "darwin" {
		for _, p := range []string{
			"/opt/homebrew/bin/ssh-keygen", // Apple-silicon Homebrew
			"/usr/local/bin/ssh-keygen",    // Intel Homebrew
			"/opt/local/bin/ssh-keygen",    // MacPorts
		} {
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				return p
			}
		}
	}
	if p, err := exec.LookPath("ssh-keygen"); err == nil {
		return p
	}
	return "ssh-keygen"
}

type skStatus int

const (
	skKeygenOK skStatus = iota
	skKeygenMissing
	skKeygenNoFIDO
	skKeygenUnknown
)

// skKeygenStatus reports whether the ssh-keygen ykt will invoke can generate
// FIDO2 sk keys — WITHOUT touching a device (safe for doctor). On macOS the only
// reliable no-device signal is the binary itself: a Homebrew/MacPorts build is
// FIDO-capable, Apple's /usr/bin build is not, and sshKeygenPath already prefers
// the capable ones — so a resolution to the system path means none is installed.
// Elsewhere `ssh -Q key` is honest (no provider split), so it settles it.
func skKeygenStatus() skStatus {
	path := sshKeygenPath()
	if path == "ssh-keygen" {
		if _, err := exec.LookPath("ssh-keygen"); err != nil {
			return skKeygenMissing
		}
	}
	if runtime.GOOS == "darwin" {
		if path == "/usr/bin/ssh-keygen" || path == "ssh-keygen" {
			return skKeygenNoFIDO
		}
		return skKeygenOK
	}
	out, err := exec.Command("ssh", "-Q", "key").Output()
	if err != nil {
		return skKeygenUnknown
	}
	if strings.Contains(string(out), "sk-ssh-ed25519@openssh.com") ||
		strings.Contains(string(out), "sk-ecdsa-sha2-nistp256@openssh.com") {
		return skKeygenOK
	}
	return skKeygenNoFIDO
}

// skOutputIncapable reports whether ssh-keygen output shows a toolchain that
// cannot generate FIDO2 security-key credentials at all (as opposed to a
// device/PIN/touch condition). These messages are emitted fast, before any
// device interaction.
func skOutputIncapable(out string) bool {
	low := strings.ToLower(out)
	for _, bad := range []string{
		"securitykeyprovider", // Apple's ssh-keygen with no middleware
		"invalid format",      // follows the provider error / Win32-OpenSSH without sk
		"unknown key type",    // ssh-keygen too old to know *-sk
		"unknown option",      // ancient ssh-keygen without -O sk options
		"unsupported",
	} {
		if strings.Contains(low, bad) {
			return true
		}
	}
	return false
}

// skKeygenProbe verifies the local ssh-keygen can drive a FIDO2 key BEFORE
// enrollment does anything destructive. An incapable toolchain fails fast with a
// recognizable error (skOutputIncapable) — that's what we catch. A capable one
// blocks waiting for a touch; we let a short deadline elapse, kill it, and report
// capable. The probe key is non-resident (no on-key slot consumed) in a temp dir
// we delete. Returns nil when capable (or when we can't tell — never a false
// block).
func skKeygenProbe(argv0, skType string) error {
	resolved, err := exec.LookPath(argv0)
	if err != nil {
		return fmt.Errorf("%s is not on PATH — install OpenSSH (macOS: brew install openssh)", argv0)
	}
	tmp, err := os.MkdirTemp("", "ykt-skprobe")
	if err != nil {
		return nil // can't probe → don't block the flow
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolved,
		"-t", skType, "-N", "", "-O", "application=ssh:ykt-probe", "-f", filepath.Join(tmp, "probe"))
	out, _ := cmd.CombinedOutput()

	if skOutputIncapable(string(out)) {
		return fmt.Errorf("the ssh-keygen at %s cannot generate FIDO2 security-key credentials:\n  %s",
			resolved, strings.TrimSpace(string(out)))
	}
	// Timed out on a touch prompt, or a transient device error → capable; let the
	// real generation surface anything else.
	return nil
}
