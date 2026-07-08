package main

// cert install: the last mile after signing, run on the enrollee's
// machine with their YubiKey inserted. The SSH cert is just a file copied
// next to the key handle (the private key never left the YubiKey); the TLS
// cert is imported into PIV 9a natively so browsers see key+cert together.

import (
	"fmt"
	"os"
	"path/filepath"
)

func cmdCertInstall(args []string) {
	if len(args) < 2 {
		fatal("usage: ykt cert install <name> <domain...>")
	}
	reg := loadRegistry()
	person := args[0]
	domains := args[1:]
	for _, d := range domains {
		reg.domain(d)
	}
	requireCleanDailyKeySlots(reg) // refuse to write PIV slots on a colliding config
	hostname := shortHost(hostnameOrDie())
	sshDir := filepath.Join(homeDir(), ".ssh")

	head("Install signed output for %q on this machine", person)

	// ---- locate everything first -------------------------------------------
	type sshInstall struct{ src, dst, domain string }
	type tlsInstall struct{ src, slot, domain string }
	var sshWork []sshInstall
	var tlsWork []tlsInstall
	for _, dn := range domains {
		src := trustPath("dist", dn, distUserCertName(person, hostname))
		if _, err := os.Stat(src); err != nil {
			warn("[%s] no signed SSH cert for this machine at %s — skipping (not signed yet, or different hostname?)", dn, src)
		} else {
			// id_<domain>-cert.pub; needs an explicit CertificateFile (no auto-pair)
			dst := filepath.Join(sshDir, installedSSHCertName(dn))
			sshWork = append(sshWork, sshInstall{src, dst, dn})
		}
		tsrc := trustPath("dist", dn, distTLSName(person, hostname))
		if _, err := os.Stat(tsrc); err == nil {
			tlsWork = append(tlsWork, tlsInstall{tsrc, reg.domain(dn).ClientSlot, dn})
		} else {
			warn("[%s] no signed TLS cert at %s — skipping", dn, tsrc)
		}
	}
	if len(sshWork) == 0 && len(tlsWork) == 0 {
		fatal("nothing to install — run 'cert sign' first (and pull the repo)")
	}

	// Which SSH certs can also ride on the card (route 2 — the domain reserves an
	// ssh_cert_slot). Requires the daily key inserted, same as an mTLS import.
	keyStub := filepath.Join(sshDir, dailyKeyName)
	var sshStash []sshInstall
	for _, w := range sshWork {
		if reg.domain(w.domain).SSHCertSlot != "" {
			sshStash = append(sshStash, w)
		}
	}
	stashStub := len(sshStash) > 0 && fileExists(keyStub)
	needCard := len(tlsWork) > 0 || len(sshStash) > 0

	// ---- plan ----------------------------------------------------------------
	var planLines []string
	for _, w := range sshWork {
		planLines = append(planLines, fmt.Sprintf("[%s] copy SSH cert → %s (plain file; key stays in hardware)", w.domain, w.dst))
	}
	if stashStub {
		planLines = append(planLines, fmt.Sprintf("stash the %s key stub into PIV slot %s (so a new machine needs only the key)", dailyKeyName, sshKeyStashSlot))
	}
	for _, w := range sshStash {
		planLines = append(planLines, fmt.Sprintf("[%s] stash SSH cert into PIV slot %s (carry-only-the-key)", w.domain, reg.domain(w.domain).SSHCertSlot))
	}
	for _, w := range tlsWork {
		planLines = append(planLines, fmt.Sprintf("[%s] import mTLS cert into PIV slot %s (native, needs PIN)", w.domain, w.slot))
	}
	confirmPlan(planLines)

	// ---- execute ---------------------------------------------------------------
	for _, w := range sshWork {
		w := w
		act(fmt.Sprintf("[%s] install SSH certificate", w.domain), "", func() error {
			return copyFile(w.src, w.dst, 0o644)
		})
	}
	if needCard {
		yk, _ := pickYubiKey("")
		if yk != nil {
			defer yk.Close()
		}
		var pin string
		var mk []byte
		if !dryRun {
			pin = promptSecret("  PIV PIN of this key: ")
			verifyPINOnce(yk, pin)
			mk = mgmtKey(yk, pin)
		}
		if stashStub {
			act(fmt.Sprintf("stash %s key stub into slot %s", dailyKeyName, sshKeyStashSlot), "", func() error {
				stub, err := os.ReadFile(keyStub)
				if err != nil {
					return err
				}
				return stashOnCard(yk, mk, sshKeyStashSlot, dailyKeyName, stub)
			})
		}
		for _, w := range sshStash {
			w := w
			slot := reg.domain(w.domain).SSHCertSlot
			act(fmt.Sprintf("[%s] stash SSH cert into slot %s", w.domain, slot), "", func() error {
				// Read the authoritative dist source, not w.dst — the ~/.ssh copy
				// is a separate skippable step and may be absent or stale.
				certBytes, err := os.ReadFile(w.src)
				if err != nil {
					return err
				}
				return stashOnCard(yk, mk, slot, "ssh-cert "+w.domain, certBytes)
			})
		}
		for _, w := range tlsWork {
			w := w
			act(fmt.Sprintf("[%s] import mTLS cert into slot %s", w.domain, w.slot), "", func() error {
				cert, err := loadCertPEM(w.src)
				if err != nil {
					return err
				}
				return setSlotCertificate(yk, mk, w.slot, cert)
			})
		}
	}

	head("Installed")
	// The daily key (id_yk) has no domain of its own, so every domain's cert
	// needs an explicit CertificateFile — there is no auto-pairing special case.
	if len(sshWork) > 0 {
		say("Each domain's cert needs a Match block in ~/.ssh/config:")
		for _, w := range sshWork {
			say("  Match host %s", reg.domain(w.domain).HostPattern)
			say("    IdentityFile ~/.ssh/%s", dailyKeyName)
			say("    CertificateFile ~/.ssh/%s", installedSSHCertName(w.domain))
			say("    IdentitiesOnly yes")
		}
		say("")
		say("Tip: 'ykt setup ssh init' generates these ~/.ssh/<domain>/ folders for you, so")
		say("short names just work — no hand-written Match blocks.")
		if len(sshStash) > 0 {
			say("")
			if stashStub {
				say("Carry-only-the-key: the cert + key stub now ride on this YubiKey. On a")
				say("fresh machine, insert the key and run 'ykt setup key' — no files to bring.")
			} else {
				warn("SSH cert(s) stashed, but ~/.ssh/%s was absent so the KEY STUB was NOT stashed.", dailyKeyName)
				warn("'ykt setup key' will fail without it. Run 'ykt init user' first (it creates the")
				warn("stub), then re-run 'ykt cert install' to stash the stub too.")
			}
		}
	}
	if len(tlsWork) > 0 {
		say("Browsers see each domain's cert via the smartcard stack (opensc) and")
		say("offer the matching one per site (server advertises its client CA).")
	}
}

func shortHost(h string) string {
	for i := range h {
		if h[i] == '.' {
			return h[:i]
		}
	}
	return h
}
