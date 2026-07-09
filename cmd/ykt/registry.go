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
	"slices"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

var trustHome string

// isTrustStore reports whether dir is a ykt trust store. It requires config.toml
// to decode and declare at least one [domains.*], so the CWD walk / pointer
// never latches onto an unrelated project's config.toml (a common filename).
func isTrustStore(dir string) bool {
	p := filepath.Join(dir, "config.toml")
	if fi, err := os.Stat(p); err != nil || fi.IsDir() {
		return false
	}
	var r Registry
	if _, err := toml.DecodeFile(p, &r); err != nil {
		return false
	}
	return len(r.Domains) > 0
}

// storeFromEnvOrCWD is the "where am I" answer: $YKT_HOME, else the nearest
// config.toml walking up from the working directory. Excludes the binary
// location and the recorded pointer — so it reflects the store you're standing
// in, which is what `setup home` (no arg) records.
func storeFromEnvOrCWD() string {
	if h := os.Getenv("YKT_HOME"); h != "" {
		return h
	}
	if wd, err := os.Getwd(); err == nil {
		for d := wd; ; {
			if isTrustStore(d) {
				return d
			}
			parent := filepath.Dir(d)
			if parent == d { // reached the filesystem root (POSIX or Windows)
				break
			}
			d = parent
		}
	}
	return ""
}

// initTrustHome locates the trust directory (marked by config.toml). It
// returns false if none is found rather than fataling, so commands that can
// run without a repo (e.g. doctor on a fresh machine) still work. Precedence:
// the store you're standing in ($YKT_HOME / nearest config.toml) wins over a
// store next to the binary, which wins over a recorded pointer.
func initTrustHome() bool {
	if dir := storeFromEnvOrCWD(); dir != "" {
		trustHome = dir
		return true
	}
	// a store next to the binary (dev builds placed inside a store)
	if exe, err := os.Executable(); err == nil {
		for _, dir := range []string{filepath.Dir(exe), filepath.Dir(filepath.Dir(exe))} {
			if isTrustStore(dir) {
				trustHome = dir
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

// schemaVersion is the config.toml / on-disk store data-model version this tool
// speaks. Bump it when config.toml's schema or the store layout changes in a way
// that needs migration, and add handling for older versions at that time. A
// store written by a NEWER ykt (higher schema_version) is refused rather than
// silently misread.
const schemaVersion = 1

type Registry struct {
	SchemaVersion int               `toml:"schema_version"` // 0/absent = legacy v1
	Anchors       map[string]Anchor `toml:"anchors"`
	Domains       map[string]Domain `toml:"domains"`
}

func loadRegistry() *Registry {
	var r Registry
	if _, err := toml.DecodeFile(trustPath("config.toml"), &r); err != nil {
		fatal("parsing config.toml: %v", err)
	}
	if err := checkSchemaVersion(r.SchemaVersion); err != nil {
		fatal("%v", err)
	}
	if len(r.Domains) == 0 {
		fatal("config.toml defines no [domains.*]")
	}
	if err := validateRegistry(&r); err != nil {
		fatal("invalid config.toml: %v", err)
	}
	return &r
}

// checkSchemaVersion refuses a store written by a NEWER ykt (its schema may carry
// fields/semantics this build can't honor). Absent (0) means a legacy store from
// before the field existed — treated as v1.
func checkSchemaVersion(v int) error {
	if v > schemaVersion {
		return fmt.Errorf("this store needs a newer ykt: config schema_version %d, this build supports %d — update: go install github.com/RawSocketLabs/ykt/cmd/ykt@latest", v, schemaVersion)
	}
	return nil
}

// validateRegistry catches config.toml mistakes that would otherwise surface
// only in production: undefined anchor references, anchor PIV-slot collisions
// (genesis silently overwrites a CA key on-device), and overlapping serial_base
// blocks (duplicate cert serials across operators). Called from loadRegistry so
// every command fails fast, before any factory reset or signing.
func validateRegistry(r *Registry) error {
	// (a) every domain names ≥1 anchor, and every named anchor is defined.
	for _, dn := range sortedKeys(r.Domains) {
		d := r.Domains[dn]
		if len(d.Anchors) == 0 {
			return fmt.Errorf("domain %q lists no anchors", dn)
		}
		for _, an := range d.Anchors {
			if _, ok := r.Anchors[an]; !ok {
				return fmt.Errorf("domain %q references undefined anchor %q (add an [anchors.%s] table)", dn, an, an)
			}
		}
	}

	// (b) per anchor, the CA slots it hosts (each domain-on-it × user/host/tls)
	//     are present, valid, and distinct. A collision means genesis would
	//     overwrite one CA key on-device.
	for _, an := range sortedKeys(r.Anchors) {
		used := map[string]string{} // slot -> "domain/role"
		for _, dn := range sortedKeys(r.Domains) {
			d := r.Domains[dn]
			if !slices.Contains(d.Anchors, an) {
				continue
			}
			for _, rs := range domainRoleSlots(d) {
				if rs.slot == "" {
					return fmt.Errorf("domain %q has an empty %s_slot", dn, rs.role)
				}
				if _, err := slotByName(rs.slot); err != nil {
					return fmt.Errorf("domain %q %s_slot: %w", dn, rs.role, err)
				}
				owner := dn + "/" + rs.role
				if prev, dup := used[rs.slot]; dup {
					return fmt.Errorf("anchor %q slot %s is claimed by both %s and %s — genesis would overwrite a CA key", an, rs.slot, prev, owner)
				}
				used[rs.slot] = owner
			}
		}
	}

	// (c) serial_base blocks (base+1 .. base+999) must not overlap across anchors.
	type ab struct {
		name string
		base uint64
	}
	bases := make([]ab, 0, len(r.Anchors))
	for _, an := range sortedKeys(r.Anchors) {
		bases = append(bases, ab{an, r.Anchors[an].SerialBase})
	}
	sort.Slice(bases, func(i, j int) bool { return bases[i].base < bases[j].base })
	for i := 1; i < len(bases); i++ {
		if bases[i].base-bases[i-1].base < 1000 {
			return fmt.Errorf("anchors %q (serial_base %d) and %q (serial_base %d) overlap — space serial_base ≥1000 apart so cert serials stay unique",
				bases[i-1].name, bases[i-1].base, bases[i].name, bases[i].base)
		}
	}
	return nil
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
	Domain     string   `toml:"domain"`               // primary domain (zone/FQDN + host cert)
	Trust      []string `toml:"trust,omitempty"`      // ADDITIONAL user-CA domains this host accepts
	Address    string   `toml:"address,omitempty"`    // ssh destination (host or user@host)
	SSHUser    string   `toml:"ssh_user,omitempty"`   // optional; default from ssh config
	Principals []string `toml:"principals,omitempty"` // host-cert principals; default derived
	Roles      []string `toml:"roles,omitempty"`      // ssh-host, caddy-edge, ...
	Notes      string   `toml:"notes,omitempty"`
}

// trustedDomains is the full set of domains whose user CAs this host accepts:
// the primary Domain plus any additional Trust domains, deduped, primary first.
func (m Machine) trustedDomains() []string {
	out := []string{m.Domain}
	for _, d := range m.Trust {
		if d != "" && !slices.Contains(out, d) {
			out = append(out, d)
		}
	}
	return out
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
