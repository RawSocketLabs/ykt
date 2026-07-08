package main

// ssh-config: manage ~/.ssh/config as a structured tree. Everything ykt writes
// lives under ONE namespaced folder — ~/.ssh/ykt/<domain>/*.conf (one folder per
// configured domain) — so it can never collide with folders you already keep in
// ~/.ssh. The top-level config gets a marker-delimited Include block you can put
// at the TOP (ykt entries win) or BOTTOM (your existing config wins). Each host
// entry sets an explicit HostName + CertificateFile, so `ssh <host>` works by
// short name and presents the right domain cert — no TOFU, no auto-pair guessing.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	sshBeginMarker    = "# >>> ykt managed includes (do not edit this block) >>>"
	sshEndMarker      = "# <<< ykt managed includes <<<"
	sshManagedSubdir  = "ykt" // the single ~/.ssh folder ykt owns
	sshManagedComment = "managed by ykt"
)

// Include-block placement in ~/.ssh/config.
const (
	includeTop      = "top"    // ykt entries take precedence over existing config
	includeBottom   = "bottom" // existing config takes precedence; ykt fills gaps
	includePreserve = ""       // keep the block wherever it already sits (add/sync)
)

func sshHomeDir() string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		fatal("cannot determine home directory: %v", err)
	}
	return filepath.Join(h, ".ssh")
}

func sshManagedDir() string              { return filepath.Join(sshHomeDir(), sshManagedSubdir) }
func domainConfDir(domain string) string { return filepath.Join(sshManagedDir(), domain) }

// ensureSSHDirs creates ~/.ssh and each domain folder with tight perms.
func ensureSSHDirs(domains []string) {
	if dryRun {
		return
	}
	if err := os.MkdirAll(sshHomeDir(), 0o700); err != nil {
		fatal("%v", err)
	}
	for _, dn := range domains {
		if err := os.MkdirAll(domainConfDir(dn), 0o700); err != nil {
			fatal("%v", err)
		}
	}
}

// domainDefaults is the catch-all block for hosts matching the domain's
// pattern that have no explicit per-host file.
func domainDefaults(d Domain, domain string) string {
	return fmt.Sprintf(`# %s domain defaults — managed by ykt
Match host %s
    IdentityFile ~/.ssh/%s
    CertificateFile ~/.ssh/%s
    IdentitiesOnly yes
`, domain, d.HostPattern, dailyKeyName, installedSSHCertName(domain))
}

// managedIncludeBlock builds the Include block for the top-level config. Paths
// are relative to ~/.ssh and namespaced under ykt/, so they can't shadow a
// user's own includes.
func managedIncludeBlock(domains []string) string {
	var b strings.Builder
	b.WriteString(sshBeginMarker + "\n")
	for _, dn := range domains {
		fmt.Fprintf(&b, "Include %s/%s/*.conf\n", sshManagedSubdir, dn)
	}
	b.WriteString(sshEndMarker + "\n")
	return b.String()
}

// upsertManagedIncludes inserts/replaces the managed block in ~/.ssh/config,
// preserving all unmanaged content. position controls placement:
//   - includeTop:    block first, so ykt entries win for overlapping hosts
//   - includeBottom: block last, so your existing config wins
//   - includePreserve: keep the block wherever it currently is (add/sync)
//
// SSH takes the first value it sees for each option, so placement is precedence.
func upsertManagedIncludes(domains []string, position string) error {
	path := filepath.Join(sshHomeDir(), "config")
	block := managedIncludeBlock(domains)
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	content := string(existing)

	if i := strings.Index(content, sshBeginMarker); i >= 0 {
		j := strings.Index(content, sshEndMarker)
		if j < 0 {
			return fmt.Errorf("~/.ssh/config has a begin marker but no end marker — fix by hand")
		}
		j += len(sshEndMarker)
		if j < len(content) && content[j] == '\n' {
			j++
		}
		if position == includePreserve {
			// replace in place — don't move a block the user positioned
			return writeFileAtomic(path, []byte(content[:i]+block+content[j:]), 0o600)
		}
		content = content[:i] + content[j:] // strip so we can reposition
	} else if position == includePreserve {
		position = includeTop // brand-new block: default to top
	}

	body := strings.Trim(content, "\n")
	blk := strings.TrimRight(block, "\n")
	var out string
	switch {
	case body == "":
		out = blk + "\n"
	case position == includeBottom:
		out = body + "\n\n" + blk + "\n"
	default:
		out = blk + "\n\n" + body + "\n"
	}
	return writeFileAtomic(path, []byte(out), 0o600)
}

// migrateOldLayout moves pre-namespace ~/.ssh/<domain>/ folders that ykt created
// into ~/.ssh/ykt/<domain>/. Only folders ykt clearly owns (their
// 00-defaults.conf carries our marker) are touched; a user's same-named folder
// is left untouched — which is the whole point of the ykt/ namespace.
func migrateOldLayout(domains []string) {
	if dryRun {
		return
	}
	for _, dn := range domains {
		oldDir := filepath.Join(sshHomeDir(), dn)
		newDir := domainConfDir(dn)
		if oldDir == newDir {
			continue
		}
		entries, err := os.ReadDir(oldDir)
		if err != nil {
			continue
		}
		// The dir is ours only if at least ONE .conf carries our marker — so a
		// user's same-named folder is never touched. If it's ours, migrate every
		// .conf (not just 00-defaults), so a deleted defaults file can't orphan
		// per-host entries.
		owned := false
		var confs []string
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			confs = append(confs, e.Name())
			if b, rerr := os.ReadFile(filepath.Join(oldDir, e.Name())); rerr == nil && strings.Contains(string(b), sshManagedComment) {
				owned = true
			}
		}
		if !owned || os.MkdirAll(newDir, 0o700) != nil {
			continue
		}
		moved := 0
		for _, name := range confs {
			if os.Rename(filepath.Join(oldDir, name), filepath.Join(newDir, name)) == nil {
				moved++
			}
		}
		if rem, _ := os.ReadDir(oldDir); len(rem) == 0 {
			_ = os.Remove(oldDir)
		}
		if moved > 0 {
			note("migrated %d file(s) from ~/.ssh/%s/ to ~/.ssh/%s/%s/", moved, dn, sshManagedSubdir, dn)
		}
	}
}

func cmdSSHConfigInit(position string) {
	reg := loadRegistry()
	domains := reg.domainNames()
	place := position
	if place == includePreserve {
		place = includeTop + " (default)"
	}
	head("Set up ~/.ssh/ykt structured config for domains: %s", strings.Join(domains, " "))
	confirmPlan(append([]string{
		"create ~/.ssh/ykt/<domain>/ folders (0700): " + strings.Join(domains, " "),
		fmt.Sprintf("place the managed Include block at the %s of ~/.ssh/config", place)},
		prefixEach(domains, "write ~/.ssh/ykt/", "/00-defaults.conf")...))
	migrateOldLayout(domains)
	ensureSSHDirs(domains)
	for _, dn := range domains {
		dn := dn
		d := reg.domain(dn)
		act(fmt.Sprintf("[%s] write domain defaults", dn), "", func() error {
			return writeFileAtomic(filepath.Join(domainConfDir(dn), "00-defaults.conf"),
				[]byte(domainDefaults(d, dn)), 0o600)
		})
	}
	act(fmt.Sprintf("place ~/.ssh/config Include block (%s)", place), "", func() error {
		return upsertManagedIncludes(domains, position)
	})
	head("Done")
	if position == includeBottom {
		say("Include is at the BOTTOM — your existing ~/.ssh/config entries take precedence.")
	} else {
		say("Include is at the TOP — ykt entries take precedence over existing config.")
	}
	say("Add hosts:  ykt setup ssh add <domain> <host> [--address <ip>] [--user <u>]")
	say("Or sync from inventory:  ykt setup ssh sync")
}

func prefixEach(items []string, pre, suf string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = pre + s + suf
	}
	return out
}

// hostConfEntry renders one host's config file content.
//
// The friendly FQDN (<host>.<zone>) is always the identity used for host-key /
// certificate verification. If `address` pins a specific IP (or a different
// name) to connect to, we set HostName to that address AND HostKeyAlias to the
// FQDN — so ssh dials the pinned IP but still verifies the host cert against
// the FQDN (matching the @cert-authority *.<zone> pattern). That's how you
// "say the hostname but resolve to a specific IP" in one entry.
func hostConfEntry(reg *Registry, domain, host, address, user string, port int) string {
	d := reg.domain(domain)
	fqdn := host + "." + d.BaseZone()
	hostname := fqdn
	hostKeyAlias := ""
	if address != "" && address != fqdn {
		hostname = address  // connect here (IP or alternate name)
		hostKeyAlias = fqdn // verify / known_hosts as the FQDN
	}
	if user == "" {
		user = d.DefaultPrincipal
	}
	// Both the short name and the FQDN resolve to this entry.
	aliases := []string{host}
	if fqdn != host {
		aliases = append(aliases, fqdn)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s/%s — managed by ykt (edit via 'ykt setup ssh')\n", domain, host)
	fmt.Fprintf(&b, "Host %s\n", strings.Join(aliases, " "))
	fmt.Fprintf(&b, "    HostName %s\n", hostname)
	if hostKeyAlias != "" {
		fmt.Fprintf(&b, "    HostKeyAlias %s\n", hostKeyAlias)
	}
	fmt.Fprintf(&b, "    User %s\n", user)
	if port != 0 && port != 22 {
		fmt.Fprintf(&b, "    Port %d\n", port)
	}
	fmt.Fprintf(&b, "    IdentityFile ~/.ssh/%s\n", dailyKeyName)
	fmt.Fprintf(&b, "    CertificateFile ~/.ssh/%s\n", installedSSHCertName(domain))
	fmt.Fprintf(&b, "    IdentitiesOnly yes\n")
	return b.String()
}

func writeHostConf(reg *Registry, domain, host, hostname, user string, port int) error {
	ensureSSHDirs([]string{domain})
	path := filepath.Join(domainConfDir(domain), host+".conf")
	return writeFileAtomic(path, []byte(hostConfEntry(reg, domain, host, hostname, user, port)), 0o600)
}

func cmdSSHConfigAdd(domain, host, address, user string, port int) {
	reg := loadRegistry()
	reg.domain(domain)
	head("Add ssh config: %s/%s", domain, host)
	// make sure the Include block + folders exist (migrating any old layout,
	// and preserving wherever the user placed the Include block)
	if _, err := os.Stat(domainConfDir(domain)); err != nil {
		act("initialize ~/.ssh/ykt structure (Include block + folders)", "", func() error {
			migrateOldLayout(reg.domainNames())
			ensureSSHDirs(reg.domainNames())
			for _, dn := range reg.domainNames() {
				d := reg.domain(dn)
				if werr := writeFileAtomic(filepath.Join(domainConfDir(dn), "00-defaults.conf"),
					[]byte(domainDefaults(d, dn)), 0o600); werr != nil {
					return werr
				}
			}
			return upsertManagedIncludes(reg.domainNames(), includePreserve)
		})
	}
	act(fmt.Sprintf("write ~/.ssh/%s/%s/%s.conf", sshManagedSubdir, domain, host), "", func() error {
		return writeHostConf(reg, domain, host, address, user, port)
	})
	d := reg.domain(domain)
	fqdn := host + "." + d.BaseZone()
	head("Added — connect with:  ssh %s", host)
	if address != "" && address != fqdn {
		say("  connects to %s, verified as %s (HostKeyAlias), cert ~/.ssh/%s", address, fqdn, installedSSHCertName(domain))
	} else {
		say("  HostName %s, cert ~/.ssh/%s", fqdn, installedSSHCertName(domain))
	}
}

// cmdSSHConfigSync regenerates a host file for every machine in inventory.
func cmdSSHConfigSync() {
	reg := loadRegistry()
	inv := loadInventory()
	if len(inv.Machines) == 0 {
		fatal("inventory is empty — add machines first (ykt data inventory add ...)")
	}
	head("Sync ~/.ssh/ykt host files from inventory (%d machines)", len(inv.Machines))
	migrateOldLayout(reg.domainNames())
	var plan []string
	for _, name := range sortedKeys(inv.Machines) {
		m := inv.Machines[name]
		plan = append(plan, fmt.Sprintf("~/.ssh/%s/%s/%s.conf → %s", sshManagedSubdir, m.Domain, name, m.sshDest(name, reg.domain(m.Domain))))
	}
	confirmPlan(plan)
	for _, name := range sortedKeys(inv.Machines) {
		name := name
		m := inv.Machines[name]
		d := reg.domain(m.Domain)
		host := m.Address
		if host == "" {
			host = name + "." + d.BaseZone()
		}
		act(fmt.Sprintf("[%s] write ~/.ssh/%s/%s/%s.conf", m.Domain, sshManagedSubdir, m.Domain, name), "", func() error {
			return writeHostConf(reg, m.Domain, name, host, m.SSHUser, 0)
		})
	}
	good("ssh config synced from inventory")
}

func cmdSSHConfigRemove(domain, host string) {
	reg := loadRegistry()
	reg.domain(domain)
	path := filepath.Join(domainConfDir(domain), host+".conf")
	if _, err := os.Stat(path); err != nil {
		fatal("no managed config at %s", path)
	}
	act("remove "+path, "", func() error { return removeIfPresent(path) })
	good("removed ssh config for %s/%s", domain, host)
}

func cmdSSHConfigList() {
	reg := loadRegistry()
	head("Managed ssh config")
	for _, dn := range reg.domainNames() {
		entries, err := os.ReadDir(domainConfDir(dn))
		if err != nil {
			continue
		}
		var hosts []string
		for _, e := range entries {
			n := e.Name()
			if strings.HasSuffix(n, ".conf") && n != "00-defaults.conf" {
				hosts = append(hosts, strings.TrimSuffix(n, ".conf"))
			}
		}
		sort.Strings(hosts)
		if len(hosts) > 0 {
			say("  %-6s %s", dn, strings.Join(hosts, " "))
		} else {
			say("  %-6s (defaults only)", dn)
		}
	}
}
