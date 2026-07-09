package main

// YubiKey capability model. Different firmware generations expose different
// FIDO2/PIV features; rather than scatter version checks, we derive one
// capability set per key and let enrollment pick the strongest options each
// key actually supports. This is what lets a 5.1.2 test key and a 5.7 daily
// key both be used to their fullest from the same tool.

type ykCaps struct {
	Version       [3]int
	Known         bool   // false in dry-run (no hardware to query)
	SSHKeyType    string // "ed25519-sk" (5.2.3+) or "ecdsa-sk" (older)
	ResidentSSH   bool   // discoverable FIDO2 credentials (credProtect) — 5.2.3+
	VerifyCapable bool   // -O verify-required (PIN-per-use) — any FIDO2 key
}

func atLeast(v [3]int, maj, min, pat int) bool {
	if v[0] != maj {
		return v[0] > maj
	}
	if v[1] != min {
		return v[1] > min
	}
	return v[2] >= pat
}

// capsForVersion derives capabilities from a firmware triple.
func capsForVersion(v [3]int) ykCaps {
	c := ykCaps{Version: v, Known: true, VerifyCapable: true}
	if atLeast(v, 5, 2, 3) {
		c.SSHKeyType = "ed25519-sk"
		c.ResidentSSH = true
	} else {
		// Pre-5.2.3: no Ed25519 over FIDO2 and no credProtect for resident
		// keys — fall back to an ECDSA P-256 non-resident sk key. Same
		// security properties (hardware-bound, touch-gated); only the
		// convenience of on-key recovery is lost.
		c.SSHKeyType = "ecdsa-sk"
		c.ResidentSSH = false
	}
	return c
}

func capsFor(yk pivKey) ykCaps {
	if yk == nil { // dry-run: assume a modern key but mark it unknown
		c := capsForVersion([3]int{5, 7, 0})
		c.Known = false
		return c
	}
	v := yk.Version()
	return capsForVersion([3]int{v.Major, v.Minor, v.Patch})
}

// sshKeygenArgs builds the ssh-keygen invocation for a daily SSH key on this
// key, using resident + Ed25519 where supported. verifyRequired adds
// PIN-per-use (independent of touch) when the operator opts in.
func (c ykCaps) sshKeygenArgs(keyFile string, verifyRequired bool) []string {
	// Absolute path to a FIDO-capable ssh-keygen (Homebrew-first on macOS) so we
	// never depend on the user's PATH ordering.
	argv := []string{sshKeygenPath(), "-t", c.SSHKeyType, "-O", "application=" + fidoApplication, "-N", ""}
	if c.ResidentSSH {
		argv = append(argv, "-O", "resident")
	}
	if verifyRequired && c.VerifyCapable {
		argv = append(argv, "-O", "verify-required")
	}
	argv = append(argv, "-f", keyFile)
	return argv
}

// summary is a one-line human description for doctor / enrollment output.
func (c ykCaps) summary() string {
	res := "non-resident"
	if c.ResidentSSH {
		res = "resident"
	}
	// PIV keys are ECDSA P-256 regardless of firmware (uniform across anchors,
	// including older ones); we don't claim Ed25519 PIV since we never issue it.
	return c.SSHKeyType + " (" + res + "), P-256 PIV client cert"
}
