package main

// hydrate: set up a fresh machine carrying ONLY the YubiKey. cert-install
// stashes the id_yk key stub and each domain's SSH certificate into spare PIV
// slots (as X.509 carriers). This command reads them back off the inserted key
// and re-materializes the files + wires ~/.ssh/config — no files to bring.
//
// Reading a PIV certificate object needs neither PIN nor touch, so hydrate only
// needs the key present. (Using the key afterward still requires the FIDO2
// touch/PIN, as always.)

import (
	"fmt"
	"path/filepath"
)

func cmdSetupKey(args []string) {
	reg := loadRegistry()

	// Target domains: those named, else every domain that reserves a cert slot.
	var domains []string
	if len(args) > 0 {
		for _, dn := range args {
			d := reg.domain(dn)
			if d.SSHCertSlot == "" {
				fatal("domain %q has no ssh_cert_slot — its cert isn't stashed on the key (add one and re-run 'ykt cert install')", dn)
			}
			domains = append(domains, dn)
		}
	} else {
		for _, dn := range reg.domainNames() {
			if reg.domain(dn).SSHCertSlot != "" {
				domains = append(domains, dn)
			}
		}
		if len(domains) == 0 {
			fatal("no domains reserve an ssh_cert_slot — nothing was stashed to hydrate from")
		}
	}

	requireCleanDailyKeySlots(reg) // refuse to read/write PIV slots on a colliding config
	sshDir := filepath.Join(homeDir(), ".ssh")
	keyStub := filepath.Join(sshDir, dailyKeyName)

	head("Hydrate this machine from the inserted YubiKey")
	explain("Reads the key stub + SSH certs stashed on the card and writes them to",
		"~/.ssh, then wires ~/.ssh/config. Nothing here needs a PIN — only the key.")

	// ---- plan ----------------------------------------------------------------
	planLines := []string{
		fmt.Sprintf("read the %s key stub from slot %s → write %s", dailyKeyName, sshKeyStashSlot, keyStub),
	}
	for _, dn := range domains {
		planLines = append(planLines,
			fmt.Sprintf("[%s] read SSH cert from slot %s → write ~/.ssh/%s", dn, reg.domain(dn).SSHCertSlot, installedSSHCertName(dn)))
	}
	planLines = append(planLines, "wire ~/.ssh/config (per-domain Include folders) for: "+fmt.Sprint(domains))
	confirmPlan(planLines)

	// ---- execute -------------------------------------------------------------
	yk, _ := pickYubiKey("")
	if yk != nil {
		defer yk.Close()
	}
	ensureSSHDirs(domains)

	act(fmt.Sprintf("recover %s key stub from slot %s", dailyKeyName, sshKeyStashSlot),
		"The stub is a hardware-bound reference; useless without this physical key.",
		func() error {
			cert, err := slotCertificate(yk, sshKeyStashSlot)
			if err != nil {
				return fmt.Errorf("no key stub stashed in slot %s (run 'ykt cert install' with the key inserted first): %w", sshKeyStashSlot, err)
			}
			stub, err := payloadFromCarrier(cert)
			if err != nil {
				return err
			}
			return writeFileAtomic(keyStub, stub, 0o600)
		})

	for _, dn := range domains {
		dn := dn
		slot := reg.domain(dn).SSHCertSlot
		dst := filepath.Join(sshDir, installedSSHCertName(dn))
		act(fmt.Sprintf("[%s] recover SSH cert from slot %s", dn, slot), "", func() error {
			cert, err := slotCertificate(yk, slot)
			if err != nil {
				return fmt.Errorf("no SSH cert stashed in slot %s: %w", slot, err)
			}
			payload, err := payloadFromCarrier(cert)
			if err != nil {
				return err
			}
			return writeFileAtomic(dst, payload, 0o644)
		})
	}

	// ---- wire config ---------------------------------------------------------
	for _, dn := range domains {
		dn := dn
		d := reg.domain(dn)
		act(fmt.Sprintf("[%s] write ~/.ssh/%s/00-defaults.conf", dn, dn), "", func() error {
			return writeFileAtomic(filepath.Join(domainConfDir(dn), "00-defaults.conf"),
				[]byte(domainDefaults(d, dn)), 0o600)
		})
	}
	act("update ~/.ssh/config Include block", "", func() error { return upsertManagedIncludes(domains) })

	head("Hydrated — this machine is ready")
	say("Connect with your certificate, e.g.:  ssh <user>@<host>.%s", reg.domain(domains[0]).BaseZone())
	say("(The YubiKey must be inserted; login prompts for one touch.)")
	note("Add per-host short names any time:  ykt setup ssh add <domain> <host> --address <ip>")
}
