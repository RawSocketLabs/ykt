package main

// ssh-config: manage ~/.ssh/config as a structured tree. The top-level config
// gets a managed Include block pulling in per-domain folders
// (~/.ssh/<domain>/*.conf, one folder per configured domain); each holds a domain-defaults
// file plus one file per host. Because each host entry sets an explicit
// HostName + CertificateFile, `ssh <host>` works by short name and presents the
// right domain cert — no TOFU, no auto-pair guessing.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	sshBeginMarker = "# >>> ykt managed includes (do not edit this block) >>>"
	sshEndMarker   = "# <<< ykt managed includes <<<"
)

func sshHomeDir() string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		fatal("cannot determine home directory: %v", err)
	}
	return filepath.Join(h, ".ssh")
}

func domainConfDir(domain string) string { return filepath.Join(sshHomeDir(), domain) }

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

// managedIncludeBlock builds the Include block for the top-level config.
func managedIncludeBlock(domains []string) string {
	var b strings.Builder
	b.WriteString(sshBeginMarker + "\n")
	for _, dn := range domains {
		fmt.Fprintf(&b, "Include %s/*.conf\n", dn)
	}
	b.WriteString(sshEndMarker + "\n")
	return b.String()
}

// upsertManagedIncludes inserts/replaces the managed block at the TOP of
// ~/.ssh/config, preserving all existing (unmanaged) content below it.
func upsertManagedIncludes(domains []string) error {
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
		content = content[:i] + block + content[j:]
	} else {
		content = block + "\n" + content
	}
	return writeFileAtomic(path, []byte(content), 0o600)
}

func cmdSSHConfigInit() {
	reg := loadRegistry()
	domains := reg.domainNames()
	head("Set up ~/.ssh structured config for domains: %s", strings.Join(domains, " "))
	confirmPlan(append([]string{
		"ensure ~/.ssh/config includes " + strings.Join(prefixEach(domains, "", "/*.conf"), ", "),
		"create ~/.ssh/<domain>/ folders (0700)"},
		prefixEach(domains, "write ~/.ssh/", "/00-defaults.conf")...))
	ensureSSHDirs(domains)
	for _, dn := range domains {
		dn := dn
		d := reg.domain(dn)
		act(fmt.Sprintf("[%s] write domain defaults", dn), "", func() error {
			return writeFileAtomic(filepath.Join(domainConfDir(dn), "00-defaults.conf"),
				[]byte(domainDefaults(d, dn)), 0o600)
		})
	}
	act("update ~/.ssh/config Include block", "", func() error { return upsertManagedIncludes(domains) })
	head("Done")
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
	// make sure the Include block + folders exist
	if _, err := os.Stat(filepath.Join(sshHomeDir(), domain)); err != nil {
		act("initialize ~/.ssh structure (Include block + folders)", "", func() error {
			ensureSSHDirs(reg.domainNames())
			for _, dn := range reg.domainNames() {
				d := reg.domain(dn)
				if werr := writeFileAtomic(filepath.Join(domainConfDir(dn), "00-defaults.conf"),
					[]byte(domainDefaults(d, dn)), 0o600); werr != nil {
					return werr
				}
			}
			return upsertManagedIncludes(reg.domainNames())
		})
	}
	act(fmt.Sprintf("write ~/.ssh/%s/%s.conf", domain, host), "", func() error {
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
	head("Sync ~/.ssh host files from inventory (%d machines)", len(inv.Machines))
	var plan []string
	for _, name := range sortedKeys(inv.Machines) {
		m := inv.Machines[name]
		plan = append(plan, fmt.Sprintf("~/.ssh/%s/%s.conf → %s", m.Domain, name, m.sshDest(name, reg.domain(m.Domain))))
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
		act(fmt.Sprintf("[%s] write ~/.ssh/%s/%s.conf", m.Domain, m.Domain, name), "", func() error {
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
