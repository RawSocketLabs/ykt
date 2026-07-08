package main

// config.toml (trust domains, anchors) and inventory.toml (machines) — the
// two data files everything else is driven by. Both are public material,
// both are committed to git. config.toml is hand-edited; inventory.toml is
// managed by `ykt data inventory` (hand-editing is fine too).

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

var trustHome string

// initTrustHome locates the trust directory (marked by config.toml). It
// returns false if none is found rather than fataling, so commands that can
// run without a repo (e.g. doctor on a fresh machine) still work.
func initTrustHome() bool {
	if h := os.Getenv("YKT_HOME"); h != "" {
		trustHome = h
		return true
	}
	// binary lives in trust/go/ or trust/bin/; config.toml marks the root
	exe, err := os.Executable()
	if err == nil {
		for _, dir := range []string{filepath.Dir(exe), filepath.Dir(filepath.Dir(exe))} {
			if _, err := os.Stat(filepath.Join(dir, "config.toml")); err == nil {
				trustHome = dir
				return true
			}
		}
	}
	if wd, err := os.Getwd(); err == nil {
		for d := wd; d != "/"; d = filepath.Dir(d) {
			if _, err := os.Stat(filepath.Join(d, "config.toml")); err == nil {
				trustHome = d
				return true
			}
		}
	}
	// last resort: a pointer recorded by `ykt setup home` (global invocation)
	if dir := readHomePointer(); dir != "" {
		trustHome = dir
		return true
	}
	return false
}

// requireTrustHome is initTrustHome for commands that genuinely need a repo.
func requireTrustHome() {
	if !initTrustHome() {
		fatal("cannot locate config.toml — run from inside your ykt store, set $YKT_HOME, or record it once with `ykt setup home <path>`")
	}
}

func trustPath(parts ...string) string {
	return filepath.Join(append([]string{trustHome}, parts...)...)
}

// ---------------------------------------------------------------- registry

type Anchor struct {
	Holder        string `toml:"holder"`
	Location      string `toml:"location"`
	YubikeySerial string `toml:"yubikey_serial"`
	SerialBase    uint64 `toml:"serial_base"`
}

type Domain struct {
	Scope            string   `toml:"scope"`
	Anchors          []string `toml:"anchors"`
	UserSlot         string   `toml:"user_slot"`
	HostSlot         string   `toml:"host_slot"`
	TLSSlot          string   `toml:"tls_slot"`      // ANCHOR keys: this domain's client-CA slot
	ClientSlot       string   `toml:"client_slot"`   // DAILY keys: this domain's mTLS key+cert slot
	SSHCertSlot      string   `toml:"ssh_cert_slot"` // DAILY keys: carrier slot for this domain's SSH cert (route 2; optional)
	HostPattern      string   `toml:"host_pattern"`
	DefaultPrincipal string   `toml:"default_principal"`
	UserValidity     string   `toml:"user_validity"`
	HostValidity     string   `toml:"host_validity"`
	TLSValidityDays  int      `toml:"tls_validity_days"`
}

func (d Domain) AnchorList() []string { return d.Anchors }
func (d Domain) HeldBy(anchor string) bool {
	for _, a := range d.Anchors {
		if a == anchor {
			return true
		}
	}
	return false
}

// BaseZone turns "*.example.internal" into "example.internal".
func (d Domain) BaseZone() string { return strings.TrimPrefix(d.HostPattern, "*.") }

type Registry struct {
	Anchors map[string]Anchor `toml:"anchors"`
	Domains map[string]Domain `toml:"domains"`
}

func loadRegistry() *Registry {
	var r Registry
	if _, err := toml.DecodeFile(trustPath("config.toml"), &r); err != nil {
		fatal("parsing config.toml: %v", err)
	}
	if len(r.Domains) == 0 {
		fatal("config.toml defines no [domains.*]")
	}
	return &r
}

func (r *Registry) domain(name string) Domain {
	d, ok := r.Domains[name]
	if !ok {
		fatal("unknown domain %q (known: %s)", name, strings.Join(r.domainNames(), " "))
	}
	return d
}

func (r *Registry) anchor(name string) Anchor {
	a, ok := r.Anchors[name]
	if !ok {
		fatal("unknown anchor %q (known: %s)", name, strings.Join(r.anchorNames(), " "))
	}
	return a
}

func (r *Registry) domainNames() []string { return sortedKeys(r.Domains) }
func (r *Registry) anchorNames() []string { return sortedKeys(r.Anchors) }

func (r *Registry) domainsOn(anchor string) []string {
	var out []string
	for _, name := range r.domainNames() {
		if r.Domains[name].HeldBy(anchor) {
			out = append(out, name)
		}
	}
	return out
}

// setAnchorSerial rewrites just the yubikey_serial line inside the
// [anchors.<name>] table, preserving comments and formatting.
func (r *Registry) setAnchorSerial(anchor, serial string) error {
	path := trustPath("config.toml")
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	inSection := false
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") {
			inSection = t == "[anchors."+anchor+"]"
			continue
		}
		if inSection && strings.HasPrefix(t, "yubikey_serial") {
			lines[i] = fmt.Sprintf("yubikey_serial = %q", serial)
			return writeFileAtomic(path, []byte(strings.Join(lines, "\n")), 0o644)
		}
	}
	return fmt.Errorf("yubikey_serial line in [anchors.%s] not found", anchor)
}

// ---------------------------------------------------------------- inventory

type Machine struct {
	Domain     string   `toml:"domain"`
	Address    string   `toml:"address,omitempty"`    // ssh destination (host or user@host)
	SSHUser    string   `toml:"ssh_user,omitempty"`   // optional; default from ssh config
	Principals []string `toml:"principals,omitempty"` // host-cert principals; default derived
	Roles      []string `toml:"roles,omitempty"`      // ssh-host, caddy-edge, ...
	Notes      string   `toml:"notes,omitempty"`
}

type Inventory struct {
	Machines map[string]Machine `toml:"machines"`
}

func loadInventory() *Inventory {
	inv := &Inventory{Machines: map[string]Machine{}}
	raw, err := os.ReadFile(trustPath("inventory.toml"))
	if os.IsNotExist(err) {
		return inv
	}
	if err != nil {
		fatal("reading inventory: %v", err)
	}
	if err := toml.Unmarshal(raw, inv); err != nil {
		fatal("parsing inventory.toml: %v", err)
	}
	if inv.Machines == nil {
		inv.Machines = map[string]Machine{}
	}
	return inv
}

func (inv *Inventory) save() {
	if dryRun {
		note("dry-run: inventory.toml not written")
		return
	}
	var buf bytes.Buffer
	buf.WriteString("# ykt machine inventory — public material, committed to git.\n")
	buf.WriteString("# Managed by 'ykt data inventory ...' (hand-editing is fine too).\n\n")
	if err := toml.NewEncoder(&buf).Encode(inv); err != nil {
		fatal("encoding inventory: %v", err)
	}
	if err := writeFileAtomic(trustPath("inventory.toml"), buf.Bytes(), 0o644); err != nil {
		fatal("writing inventory: %v", err)
	}
}

func (inv *Inventory) inDomain(domain string) []string {
	var out []string
	for name, m := range inv.Machines {
		if m.Domain == domain {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// principals returns the host-cert principals for a machine, deriving
// "<name>.<zone>,<name>" when not set explicitly.
func (m Machine) principals(name string, d Domain) []string {
	if len(m.Principals) > 0 {
		return m.Principals
	}
	return []string{name + "." + d.BaseZone(), name}
}

func (m Machine) sshDest(name string, d Domain) string {
	addr := m.Address
	if addr == "" {
		addr = name + "." + d.BaseZone()
	}
	if m.SSHUser != "" && !strings.Contains(addr, "@") {
		addr = m.SSHUser + "@" + addr
	}
	return addr
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
