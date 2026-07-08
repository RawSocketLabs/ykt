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
	reg, inv := loadRegistry(), loadInventory()

	// --all: refresh every host in every domain. This is the revocation sweep —
	// after `cert revoke`, run it so every host gets the current KRL, otherwise a
	// revoked cert keeps working on hosts until the domain is re-installed.
	if all {
		if len(args) > 0 {
			fatal("--all sweeps every domain; don't also name a domain or machine")
		}
		swept := 0
		for _, domain := range reg.domainNames() {
			machines := inv.inDomain(domain)
			if len(machines) == 0 {
				continue
			}
			installDomain(reg, inv, domain, machines, apply)
			swept++
		}
		if swept == 0 {
			fatal("no machines in inventory for any domain — nothing to sweep")
		}
		if apply {
			good("swept %d domain(s) — every host now carries the current CA trust + KRL", swept)
		}
		return
	}

	if len(args) == 0 {
		fatal("name a domain (or use --all): ykt remote install <domain> [machine...]")
	}
	domain := args[0]
	machines := resolveMachines(reg, inv, domain, args[1:])
	installDomain(reg, inv, domain, machines, apply)
}

// installDomain installs/refreshes trust material on one domain's machines.
func installDomain(reg *Registry, inv *Inventory, domain string, machines []string, apply bool) {
	d := reg.domain(domain)
	caPub, err := gatherHostCA([]string{domain})
	if err != nil {
		fatal("%v", err)
	}
	krlBytes := singleKRL([]string{domain})

	if !apply {
		printHostInstall(domain, d, inv, machines, caPub, krlBytes)
		return
	}
	applyHostInstall(domain, d, inv, machines, caPub, krlBytes)
}

// printHostInstall emits a copy-pasteable block per machine — the "just give
// me the commands for each machine" mode, useful for consoles and new boxes
// that can't be reached over SSH yet. The user-CA trust and KRL are installed
// on EVERY host; the host certificate only where one has been signed.
func printHostInstall(domain string, d Domain, inv *Inventory, machines []string, caPub, krlBytes []byte) {
	head("Per-machine install commands for domain %q (nothing executed)", domain)
	for _, name := range machines {
		cert, certErr := os.ReadFile(trustPath("dist", domain, distHostCertName(name)))
		dropIn := buildHostDropIn([]string{domain}, certErr == nil, krlBytes != nil)
		fmt.Printf("\n%s\n", colorize(cBold, "──── "+name+" ("+inv.Machines[name].sshDest(name, d)+") ────"))
		fmt.Printf("# 1. trusted user CA\nsudo tee %s > /dev/null <<'EOF'\n%sEOF\n", hostTrustCAFile, caPub)
		if krlBytes != nil {
			fmt.Printf("\n# 2. revocation list: copy pub/%s.krl to %s (binary — scp it)\n", domain, hostTrustKRLFile)
		}
		if certErr == nil {
			fmt.Printf("\n# 3. this machine's host certificate\nsudo tee %s > /dev/null <<'EOF'\n%sEOF\n", hostCertFile, cert)
		} else {
			fmt.Printf("\n# (no signed host cert yet — remote collect + cert sign to add one; TOFU until then)\n")
		}
		fmt.Printf("\n# 4. sshd drop-in\nsudo tee %s > /dev/null <<'EOF'\n%sEOF\n", hostTrustDropIn, dropIn)
		fmt.Printf("\n# 5. validate BEFORE reload — do not skip\n%s\n", sshdReloadCommand)
		fmt.Printf("\n# 6. from ANOTHER terminal: ssh %s  (expect: no password, one touch)\n",
			inv.Machines[name].sshDest(name, d))
	}
}

func applyHostInstall(domain string, d Domain, inv *Inventory, machines []string, caPub, krlBytes []byte) {
	head("P3c · Install on %q hosts (native SSH, one at a time, validated)", domain)
	explain("Every host receives the user-CA trust and KRL; the host certificate",
		"lands only where one is signed. sshd -t runs BEFORE reload in one step,",
		"so a validation failure never reloads a broken config. Keep this session open.")
	for _, name := range machines {
		m := inv.Machines[name]
		dest := m.sshDest(name, d)
		cert, certErr := os.ReadFile(trustPath("dist", domain, distHostCertName(name)))
		haveCert := certErr == nil
		if !haveCert {
			note("[%s] no signed host cert yet — installing user-CA trust + KRL only (host stays TOFU)", name)
		}
		dropIn := buildHostDropIn([]string{domain}, haveCert, krlBytes != nil)
		head("[%s] install via %s", name, dest)
		act("push trust files, validate sshd config, reload", "", func() error {
			c, err := sshConnect(dest)
			if err != nil {
				return err
			}
			defer c.Close()
			if err := remoteWriteFile(c, hostTrustCAFile, caPub, "0644"); err != nil {
				return fmt.Errorf("user CA file: %w", err)
			}
			if krlBytes != nil {
				if err := remoteWriteFile(c, hostTrustKRLFile, krlBytes, "0644"); err != nil {
					return fmt.Errorf("KRL: %w", err)
				}
			}
			if haveCert {
				if err := remoteWriteFile(c, hostCertFile, cert, "0644"); err != nil {
					return fmt.Errorf("host cert: %w", err)
				}
			}
			if err := remoteWriteFile(c, hostTrustDropIn, []byte(dropIn), "0644"); err != nil {
				return fmt.Errorf("drop-in: %w", err)
			}
			// validate-then-reload as one guarded command: reload never runs
			// if sshd -t fails.
			if out, err := remoteRun(c, sshdReloadCommand); err != nil {
				return fmt.Errorf("validate/reload FAILED (config not applied): %s", strings.TrimSpace(out))
			}
			return nil
		})
		if dryRun {
			continue
		}
		warn("Before the next host: verify from ANOTHER terminal: ssh %s", dest)
		warn("(expect: no host-key prompt, no password, one YubiKey touch)")
		if !confirm("Verified — continue?") {
			fatal("stopped; fix %s before proceeding", name)
		}
	}
	good("remote install finished")
}
