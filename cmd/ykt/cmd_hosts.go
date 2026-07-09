package main

// Machine-facing commands: inventory management, host key collection,
// and host installation (print mode = the commands to run on each machine;
// apply mode = native SSH, validated, one host at a time).

import (
	"fmt"
	"os"
	"strings"
)

// ---------------------------------------------------------------- inventory

func inventoryList() {
	reg := loadRegistry()
	inv := loadInventory()
	head("machine inventory")
	if len(inv.Machines) == 0 {
		say("  (empty — add with: ykt data inventory add <name> --domain <d> [--address a] [--principals p1,p2] [--roles r1,r2])")
		return
	}
	for _, name := range sortedKeys(inv.Machines) {
		m := inv.Machines[name]
		d := reg.domain(m.Domain)
		say("  %-14s domain=%-5s ssh=%s principals=%s roles=%s",
			name, m.Domain, m.sshDest(name, d),
			strings.Join(m.principals(name, d), ","), strings.Join(m.Roles, ","))
	}
}

// inventoryAdd creates or updates a machine; only keys present in set change.
func inventoryAdd(name string, set map[string]string) {
	reg := loadRegistry()
	inv := loadInventory()
	m := inv.Machines[name] // zero value if new → add doubles as update
	if v, ok := set["domain"]; ok {
		m.Domain = v
	}
	if m.Domain == "" {
		fatal("--domain is required")
	}
	reg.domain(m.Domain) // validate
	if v, ok := set["trust"]; ok {
		var trust []string
		for _, dn := range strings.Split(v, ",") {
			dn = strings.TrimSpace(dn)
			if dn == "" || dn == m.Domain {
				continue
			}
			reg.domain(dn) // validate the additional trust domain exists
			trust = append(trust, dn)
		}
		m.Trust = trust
	}
	if v, ok := set["address"]; ok {
		m.Address = v
	}
	if v, ok := set["principals"]; ok {
		m.Principals = strings.Split(v, ",")
	}
	if v, ok := set["roles"]; ok {
		m.Roles = strings.Split(v, ",")
	}
	if v, ok := set["notes"]; ok {
		m.Notes = v
	}
	inv.Machines[name] = m
	inv.save()
	if !dryRun {
		good("saved %s (inventory.toml)", name)
	}
}

func inventoryRemove(name string) {
	inv := loadInventory()
	if _, ok := inv.Machines[name]; !ok {
		fatal("no machine named %q", name)
	}
	delete(inv.Machines, name)
	inv.save()
	if !dryRun {
		good("removed %s", name)
	}
}

// resolveMachines returns inventory machines for a domain, or all of the
// domain's machines when names is empty.
func resolveMachines(reg *Registry, inv *Inventory, domain string, names []string) []string {
	if len(names) == 0 {
		names = inv.inDomain(domain)
		if len(names) == 0 {
			fatal("no machines in inventory for domain %q — add some first:\n  ykt data inventory add <name> --domain %s", domain, domain)
		}
		return names
	}
	for _, n := range names {
		m, ok := inv.Machines[n]
		if !ok {
			fatal("machine %q not in inventory (ykt data inventory add %s --domain %s ...)", n, n, domain)
		}
		if m.Domain != domain {
			fatal("machine %q belongs to domain %q, not %q", n, m.Domain, domain)
		}
	}
	return names
}

// ---------------------------------------------------------------- collect

func cmdRemoteCollect(args []string) {
	if len(args) < 1 {
		fatal("usage: ykt remote collect <domain> [machine...]")
	}
	reg, inv := loadRegistry(), loadInventory()
	domain := args[0]
	d := reg.domain(domain)
	machines := resolveMachines(reg, inv, domain, args[1:])

	head("P3a · Collect host keys for %q", domain)
	if err := ensureDir(trustPath("queue", domain)); err != nil {
		fatal("%v", err)
	}
	for _, name := range machines {
		m := inv.Machines[name]
		dest := m.sshDest(name, d)
		var pub []byte
		act(fmt.Sprintf("fetch /etc/ssh/ssh_host_ed25519_key.pub from %s", dest),
			"First contact confirms + pins the host key (this key is about to become CA-authoritative).",
			func() error {
				c, err := sshConnectTOFU(dest)
				if err != nil {
					return err
				}
				defer c.Close()
				pub, err = remoteReadFile(c, "/etc/ssh/ssh_host_ed25519_key.pub")
				if err != nil {
					return err
				}
				return writeFileAtomic(trustPath("queue", domain, queueHostKeyName(name)), pub, 0o644)
			})
	}
	say("")
	say("Queued. Sign with: ykt cert sign <anchor>")
}

// ---------------------------------------------------------------- install

func cmdRemoteInstall(args []string, apply, all bool) {
	validateSshdLogLevel()
	reg, inv := loadRegistry(), loadInventory()

	// --all: install/refresh EVERY host. After `cert revoke`, run it so every
	// host gets the current KRL and its full CA trust — otherwise a revoked cert
	// keeps working until each host is re-installed by hand.
	var machines []string
	if all {
		if len(args) > 0 {
			fatal("--all installs every host; don't also name a domain or machine")
		}
		machines = sortedKeys(inv.Machines)
		if len(machines) == 0 {
			fatal("no machines in inventory — add some first (ykt data inventory add ...)")
		}
	} else {
		if len(args) == 0 {
			fatal("name a domain (or use --all): ykt remote install <domain> [machine...]")
		}
		machines = resolveMachines(reg, inv, args[0], args[1:])
	}

	if !apply {
		printHostInstall(reg, inv, machines)
		return
	}
	applyHostInstall(reg, inv, machines)
	if all {
		good("installed on %d host(s) — each carries its full trust set + current KRL", len(machines))
	}
}

// hostInstall is everything one host needs, computed from its FULL trust set
// (primary domain + Trust) so an install never de-trusts a multi-domain host.
type hostInstall struct {
	dest     string
	trust    []string
	caPub    []byte
	krl      []byte
	cert     []byte
	haveCert bool
}

func gatherHostInstall(reg *Registry, inv *Inventory, name string) hostInstall {
	m := inv.Machines[name]
	pd := reg.domain(m.Domain) // primary domain: ssh destination + host cert
	trust := m.trustedDomains()
	caPub, err := gatherHostCA(trust)
	if err != nil {
		fatal("[%s] %v", name, err)
	}
	cert, certErr := os.ReadFile(trustPath("dist", m.Domain, distHostCertName(name)))
	return hostInstall{
		dest:     m.sshDest(name, pd),
		trust:    trust,
		caPub:    caPub,
		krl:      hostKRLBytes(trust),
		cert:     cert,
		haveCert: certErr == nil,
	}
}

// printHostInstall emits copy-pasteable per-machine commands (for consoles / new
// boxes not yet reachable over SSH). Each host gets its FULL trust set + KRL.
func printHostInstall(reg *Registry, inv *Inventory, machines []string) {
	head("Per-machine install commands (nothing executed)")
	for _, name := range machines {
		h := gatherHostInstall(reg, inv, name)
		dropIn := buildHostDropIn(h.trust, h.haveCert, h.krl != nil)
		fmt.Printf("\n%s\n", colorize(cBold, "──── "+name+" ("+h.dest+") · trusts "+strings.Join(h.trust, " ")+" ────"))

		// Steps are numbered by what's actually present (no gaps): the KRL and
		// host-cert steps only exist when there's a KRL / a signed host cert.
		step := 0
		next := func() int { step++; return step }

		fmt.Printf("# %d. trusted user CA(s)\nsudo tee %s > /dev/null <<'EOF'\n%sEOF\n", next(), hostTrustCAFile, h.caPub)
		if h.krl != nil {
			fmt.Printf("\n# %d. revocation list (KRL — empty until you revoke; shipped so revoking later is one file, no reload): scp the binary KRL to %s\n", next(), hostTrustKRLFile)
		} else {
			fmt.Printf("\n# (KRL could not be built — revocation would NOT be enforced on this host)\n")
		}
		if h.haveCert {
			fmt.Printf("\n# %d. this machine's host certificate\nsudo tee %s > /dev/null <<'EOF'\n%sEOF\n", next(), hostCertFile, h.cert)
		} else {
			fmt.Printf("\n# (no signed host cert yet — this host stays TOFU; see the note below to upgrade)\n")
		}
		fmt.Printf("\n# %d. sshd drop-in\nsudo tee %s > /dev/null <<'EOF'\n%sEOF\n", next(), hostTrustDropIn, dropIn)
		fmt.Printf("\n# %d. validate BEFORE reload — do not skip\n%s\n", next(), sshdReloadCommand)
		fmt.Printf("\n# %d. from ANOTHER terminal: ssh %s  (expect: no password, one touch)\n", next(), h.dest)
		if !h.haveCert {
			fmt.Printf("\n# To upgrade %s from TOFU to full host-cert verification later:\n"+
				"#   ykt remote collect %s  →  ykt cert sign <anchor>  →  re-run this install\n", name, name)
		}
	}
}

func applyHostInstall(reg *Registry, inv *Inventory, machines []string) {
	head("Install on hosts (native SSH, one at a time, validated)")
	explain("Each host receives its FULL user-CA trust set and KRL; the host cert",
		"lands only where one is signed. sshd -t runs BEFORE reload in one step,",
		"and a rejected drop-in is rolled back. Keep this session open.")
	for _, name := range machines {
		h := gatherHostInstall(reg, inv, name)
		if !h.haveCert {
			note("[%s] no signed host cert yet — installing user-CA trust + KRL only (host stays TOFU)", name)
		}
		dropIn := buildHostDropIn(h.trust, h.haveCert, h.krl != nil)
		head("[%s] install via %s (trusts %s)", name, h.dest, strings.Join(h.trust, " "))
		act("push trust files, validate sshd config, reload", "", func() error {
			c, err := sshConnect(h.dest)
			if err != nil {
				return err
			}
			defer c.Close()
			if err := remoteWriteFile(c, hostTrustCAFile, h.caPub, "0644"); err != nil {
				return fmt.Errorf("user CA file: %w", err)
			}
			if h.krl != nil {
				if err := remoteWriteFile(c, hostTrustKRLFile, h.krl, "0644"); err != nil {
					return fmt.Errorf("KRL: %w", err)
				}
			}
			if h.haveCert {
				if err := remoteWriteFile(c, hostCertFile, h.cert, "0644"); err != nil {
					return fmt.Errorf("host cert: %w", err)
				}
			}
			if err := remoteWriteFile(c, hostTrustDropIn, []byte(dropIn), "0644"); err != nil {
				return fmt.Errorf("drop-in: %w", err)
			}
			// validate-then-reload as one guarded command: reload never runs if
			// sshd -t fails, and a rejected drop-in is rolled back so a later
			// reboot/reload can't activate a config that fails sshd -t.
			if out, err := remoteRun(c, sshdReloadCommand); err != nil {
				_, _ = remoteRun(c, "sudo rm -f "+shellQuote(hostTrustDropIn))
				return fmt.Errorf("validate/reload FAILED (drop-in rolled back, not applied): %s", strings.TrimSpace(out))
			}
			return nil
		})
		if dryRun {
			continue
		}
		warn("Before the next host: verify from ANOTHER terminal: ssh %s", h.dest)
		warn("(expect: no host-key prompt, no password, one YubiKey touch)")
		if !confirm("Verified — continue?") {
			fatal("stopped; fix %s before proceeding", name)
		}
	}
	good("remote install finished")
}
