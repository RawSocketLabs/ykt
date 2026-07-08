package main

// ykt — YubiKey-anchored offline CA for SSH + mTLS.
// CLI structure via cobra; see trust/README.md.

import (
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// version is injected at build time via -ldflags "-X main.version=..."
// (see Makefile / goreleaser); defaults to "dev" for `go run`/`go build`.
var version = "dev"

func main() {
	root := &cobra.Command{
		Use:           "ykt",
		Short:         "YubiKey-anchored offline CA for SSH and mTLS (native Go)",
		Long:          "Offline YubiKey-anchored certificate authority for SSH and mTLS\nacross your configured trust domains (see config.toml).",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// Most commands need config.toml; a few must run without a locatable
			// store (doctor on a fresh machine, `setup home` recording where the
			// store IS, `docs`, and cobra's help/completion). That policy lives
			// on each command via the "store":"optional" annotation — not a name
			// allowlist a future same-named subcommand could silently trip.
			if storeOptional(cmd) {
				initTrustHome()
			} else {
				requireTrustHome()
			}
			if dryRun {
				note("dry-run mode: no hardware or files will be touched")
			}
		},
	}
	root.PersistentFlags().BoolVarP(&dryRun, "dry-run", "n", false,
		"walk any command without touching hardware or files")

	// Show commands in lifecycle order under a few headings rather than one flat
	// alphabetical list. Sorting off ⇒ display order = add order.
	cobra.EnableCommandSorting = false
	root.AddGroup(
		&cobra.Group{ID: "start", Title: "Get oriented:"},
		&cobra.Group{ID: "build", Title: "Build the trust:"},
		&cobra.Group{ID: "deploy", Title: "Deploy & use:"},
		&cobra.Group{ID: "extra", Title: "More:"},
	)
	root.SetHelpCommandGroupID("extra")
	root.SetCompletionCommandGroupID("extra")

	// Assign each top-level command to a heading. Added in lifecycle order:
	// orient → build → deploy, and within each, the order you'd run them.
	grouped := func(id string, c *cobra.Command) *cobra.Command { c.GroupID = id; return c }
	root.AddCommand(
		grouped("start", &cobra.Command{Use: "flow", Short: "Guided workflow: assess state, wait for the right key, run the next step",
			Args: cobra.NoArgs, Run: func(c *cobra.Command, a []string) { cmdFlow() }}),
		grouped("start", newDoctorCmd()),
		grouped("start", &cobra.Command{Use: "status", Short: "Registry, inventory, queue, and ledger summary",
			Args: cobra.NoArgs, Run: func(c *cobra.Command, a []string) { cmdStatus() }}),
		grouped("start", newDocsCmd()),
		grouped("build", newInitCmd()),    // ca / user / host — provision keys & hosts into trust
		grouped("build", newCertCmd()),    // sign / install / revoke / expiring
		grouped("deploy", newRepoCmd()),   // init / sync / push — your trust store as a git repo
		grouped("deploy", newDataCmd()),   // inventory / record — machines & records
		grouped("deploy", newRemoteCmd()), // collect / install — operator → remote hosts
		grouped("deploy", newSetupCmd()),  // ssh / key / vps / caddy — set up consumers
	)

	if err := root.Execute(); err != nil {
		fatal("%v", err)
	}
}

// storeOptional reports whether cmd may run without a locatable trust store:
// cobra's built-in help/completion machinery (including the hidden __complete
// commands that fire on TAB), plus any command marked "store":"optional".
func storeOptional(cmd *cobra.Command) bool {
	if cmd.Annotations["store"] == "optional" {
		return true
	}
	// Walk the ancestry: `completion` has leaf subcommands (bash/zsh/…), and the
	// hidden __complete commands fire on TAB — all need no store.
	for c := cmd; c != nil; c = c.Parent() {
		switch c.Name() {
		case "help", "completion", cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd:
			return true
		}
	}
	return false
}

// storeOptionalAnn marks a command as runnable without a trust store.
var storeOptionalAnn = map[string]string{"store": "optional"}

// newInitCmd groups the flows that bring a key or host into trust.
func newInitCmd() *cobra.Command {
	init := &cobra.Command{Use: "init", Short: "Provision keys & hosts into trust (anchor CA, user key, host)"}

	init.AddCommand(&cobra.Command{Use: "ca <anchor>", Short: "Genesis for an anchor YubiKey (factory-resets PIV)",
		Args: cobra.ExactArgs(1), Run: func(c *cobra.Command, a []string) { cmdInitCA(a) }})

	var keep, verifyRequired bool
	user := &cobra.Command{
		Use:   "user <name> <domain...>",
		Short: "Provision this machine's daily YubiKey (FIDO+PIV reset by default)",
		Args:  cobra.MinimumNArgs(2),
		Run:   func(c *cobra.Command, a []string) { cmdInitUser(a, keep, verifyRequired) },
	}
	user.Flags().BoolVar(&keep, "keep", false, "skip the factory resets; reuse existing keys and PIN")
	user.Flags().BoolVar(&verifyRequired, "verify-required", false, "require FIDO2 PIN on every SSH use (in addition to touch), where supported")

	var multi bool
	var breakGlass string
	host := &cobra.Command{
		Use:   "host <domain...>",
		Short: "Run ON a host (sudo): trust a domain's user CA, validate, optionally disable password auth",
		Args:  cobra.MinimumNArgs(1),
		Run:   func(c *cobra.Command, a []string) { cmdInitHost(a, multi, breakGlass) },
	}
	host.Flags().BoolVar(&multi, "multi", false, "allow trusting more than one domain on this host (shared login principal)")
	host.Flags().StringVar(&breakGlass, "break-glass", "", "install this offline emergency pubkey as a break-glass authorized_keys entry")

	init.AddCommand(user, host)
	return init
}

// newCertCmd groups the certificate lifecycle at the CA.
func newCertCmd() *cobra.Command {
	cert := &cobra.Command{Use: "cert", Short: "Certificate lifecycle: sign, install, revoke, expiring"}
	cert.AddCommand(
		&cobra.Command{Use: "sign <anchor>", Short: "Sign everything queued for this anchor's domains",
			Args: cobra.ExactArgs(1), Run: func(c *cobra.Command, a []string) { cmdSign(a) }},
		&cobra.Command{Use: "install <name> <domain...>", Short: "After signing: place SSH certs, import TLS certs into PIV slots",
			Args: cobra.MinimumNArgs(2), Run: func(c *cobra.Command, a []string) { cmdCertInstall(a) }},
		&cobra.Command{Use: "revoke <domain> <serial...>", Short: "Revoke ledger serials into the domain KRL",
			Args: cobra.MinimumNArgs(2), Run: func(c *cobra.Command, a []string) { cmdCertRevoke(a) }},
		&cobra.Command{Use: "expiring [days]", Short: "List certificates expiring within N days (default 21)",
			Args: cobra.MaximumNArgs(1), Run: func(c *cobra.Command, a []string) { cmdCertExpiring(a) }},
	)
	return cert
}

// newRemoteCmd groups the operator-side remote host actions.
func newRemoteCmd() *cobra.Command {
	remote := &cobra.Command{Use: "remote", Short: "Operator-side remote host management (collect keys, install trust)"}
	remote.AddCommand(
		&cobra.Command{Use: "collect <domain> [machine...]", Short: "Fetch host keys into the queue (inventory-driven)",
			Args: cobra.MinimumNArgs(1), Run: func(c *cobra.Command, a []string) { cmdRemoteCollect(a) }},
		newRemoteInstallCmd(),
	)
	return remote
}

func newRemoteInstallCmd() *cobra.Command {
	var apply bool
	c := &cobra.Command{
		Use:   "install <domain> [machine...]",
		Short: "Install trust material on hosts (prints commands; --apply pushes via SSH)",
		Args:  cobra.MinimumNArgs(1),
		Run:   func(c *cobra.Command, a []string) { cmdRemoteInstall(a, apply) },
	}
	c.Flags().BoolVar(&apply, "apply", false, "push via native SSH (validated, one host at a time) instead of printing")
	return c
}

// newSetupCmd groups the consumers of the trust — client + edge config.
func newSetupCmd() *cobra.Command {
	setup := &cobra.Command{Use: "setup", Short: "Set up consumers of the trust (ssh config, this machine's key, VPS, Caddy)"}
	setup.AddCommand(
		newSetupSSHCmd(),
		&cobra.Command{Use: "key [domain...]", Short: "Set up THIS machine from the inserted key alone (carry no files)",
			Run: func(c *cobra.Command, a []string) { cmdSetupKey(a) }},
		&cobra.Command{Use: "home [path]", Short: "Record this trust store so `ykt` finds it from any directory",
			Annotations: storeOptionalAnn,
			Args:        cobra.MaximumNArgs(1), Run: func(c *cobra.Command, a []string) { cmdSetupHome(a) }},
		newVPSCmd(),
		newCaddyCmd(),
	)
	return setup
}

// newRepoCmd groups management of the trust store as a git repo — the way to
// keep and share the public CA material without forking the tool's source.
func newRepoCmd() *cobra.Command {
	repo := &cobra.Command{Use: "repo", Short: "Manage the trust store as a git repo (init / sync / push / status)"}

	var remote string
	initc := &cobra.Command{
		Use:         "init [path]",
		Short:       "Turn a directory into a data-only trust-store git repo",
		Annotations: storeOptionalAnn,
		Args:        cobra.MaximumNArgs(1),
		Run:         func(c *cobra.Command, a []string) { cmdRepoInit(a, remote) },
	}
	initc.Flags().StringVar(&remote, "remote", "", "set the origin remote URL (e.g. git@github.com:you/trust.git)")

	var msg string
	push := &cobra.Command{
		Use:   "push",
		Short: "Commit local changes and push the store",
		Args:  cobra.NoArgs,
		Run:   func(c *cobra.Command, a []string) { cmdRepoPush(msg) },
	}
	push.Flags().StringVarP(&msg, "message", "m", "", `commit message (default: "chore: update trust material")`)

	repo.AddCommand(
		initc,
		&cobra.Command{Use: "sync", Short: "Fetch and fast-forward the store (git pull)",
			Args: cobra.NoArgs, Run: func(c *cobra.Command, a []string) { cmdRepoSync() }},
		push,
		&cobra.Command{Use: "status", Short: "Show the store's git status",
			Args: cobra.NoArgs, Run: func(c *cobra.Command, a []string) { cmdRepoStatus() }},
	)
	return repo
}

// newDataCmd groups the trust-bookkeeping files.
func newDataCmd() *cobra.Command {
	data := &cobra.Command{Use: "data", Short: "Trust bookkeeping: machine inventory and anchor records"}
	data.AddCommand(
		newInventoryCmd(),
		&cobra.Command{Use: "record <anchor>", Short: "Regenerate <anchor>.json from published trust material",
			Args: cobra.ExactArgs(1), Run: func(c *cobra.Command, a []string) { cmdDataRecord(a) }},
	)
	return data
}

func newDocsCmd() *cobra.Command {
	var port int
	var noBrowser bool
	c := &cobra.Command{
		Use:         "docs",
		Short:       "Open the bundled documentation in a browser (offline, embedded)",
		Annotations: storeOptionalAnn,
		Args:        cobra.NoArgs,
		Run:         func(c *cobra.Command, a []string) { cmdDocs(port, noBrowser) },
	}
	c.Flags().IntVar(&port, "port", 0, "port to serve on (default: a free port chosen automatically)")
	c.Flags().BoolVar(&noBrowser, "no-browser", false, "just serve; don't try to open a browser")
	return c
}

func newDoctorCmd() *cobra.Command {
	var fix bool
	c := &cobra.Command{
		Use:         "doctor",
		Short:       "Check PC/SC, YubiKeys, tools, and trust files; --fix installs what's missing",
		Annotations: storeOptionalAnn,
		Args:        cobra.NoArgs,
		Run:         func(c *cobra.Command, a []string) { cmdDoctor(fix) },
	}
	c.Flags().BoolVar(&fix, "fix", false, "plan + run package-manager commands for missing dependencies")
	return c
}

func newSetupSSHCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "ssh",
		Short: "Manage ~/.ssh/config as per-domain Include folders with per-host entries",
	}
	root.AddCommand(
		&cobra.Command{Use: "init", Short: "Create the Include block + domain folders + defaults",
			Args: cobra.NoArgs, Run: func(c *cobra.Command, a []string) { cmdSSHConfigInit() }},
		&cobra.Command{Use: "sync", Short: "Regenerate host entries from inventory.toml",
			Args: cobra.NoArgs, Run: func(c *cobra.Command, a []string) { cmdSSHConfigSync() }},
		&cobra.Command{Use: "list", Short: "List managed host entries",
			Args: cobra.NoArgs, Run: func(c *cobra.Command, a []string) { cmdSSHConfigList() }},
		&cobra.Command{Use: "remove <domain> <host>", Short: "Remove a managed host entry",
			Args: cobra.ExactArgs(2), Run: func(c *cobra.Command, a []string) { cmdSSHConfigRemove(a[0], a[1]) }},
		newSSHConfigAddCmd(),
	)
	return root
}

func newSSHConfigAddCmd() *cobra.Command {
	var address, user string
	var port int
	c := &cobra.Command{
		Use:   "add <domain> <host>",
		Short: "Add a host entry (alias = short name, HostName = FQDN or --address)",
		Args:  cobra.ExactArgs(2),
		Run:   func(c *cobra.Command, a []string) { cmdSSHConfigAdd(a[0], a[1], address, user, port) },
	}
	c.Flags().StringVar(&address, "address", "", "pin the connection to this IP/host (keeps the FQDN as HostKeyAlias for cert verification)")
	c.Flags().StringVar(&user, "user", "", "login user (default: domain principal)")
	c.Flags().IntVar(&port, "port", 0, "ssh port (default 22)")
	return c
}

func newVPSCmd() *cobra.Command {
	vps := &cobra.Command{
		Use:   "vps",
		Short: "Throwaway test-box helpers: cloud-init / install-script / trust (public material only)",
	}
	var ciUser, scUser string
	ci := &cobra.Command{
		Use:   "cloud-init <domain>",
		Short: "Emit cloud-init user-data that trusts your user CA (push at VPS creation)",
		Args:  cobra.ExactArgs(1),
		Run:   func(c *cobra.Command, a []string) { cmdVPSCloudInit(a[0], ciUser) },
	}
	ci.Flags().StringVar(&ciUser, "user", "root", "login user your cert principal must match")
	sc := &cobra.Command{
		Use:   "install-script <domain>",
		Short: "Emit a paste-on-the-box shell snippet that trusts your user CA",
		Args:  cobra.ExactArgs(1),
		Run:   func(c *cobra.Command, a []string) { cmdVPSInstallScript(a[0], scUser) },
	}
	sc.Flags().StringVar(&scUser, "user", "root", "login user your cert principal must match")
	trust := &cobra.Command{
		Use:   "trust <ip-or-host>",
		Short: "Pin a box's host key to known_hosts (TOFU-confirm) so connecting won't prompt",
		Args:  cobra.ExactArgs(1),
		Run:   func(c *cobra.Command, a []string) { cmdVPSTrust(a[0]) },
	}
	vps.AddCommand(ci, sc, trust)
	return vps
}

func newCaddyCmd() *cobra.Command {
	var sni string
	c := &cobra.Command{
		Use:   "caddy <domain...>",
		Short: "Generate Caddy mTLS client-auth config (JSON fragment + Caddyfile reference)",
		Args:  cobra.MinimumNArgs(1),
		Run:   func(c *cobra.Command, a []string) { cmdCaddy(a, sni) },
	}
	c.Flags().StringVar(&sni, "sni", "", "comma-separated SNI hosts to gate (default: *.<domain zone>)")
	return c
}

func newInventoryCmd() *cobra.Command {
	inv := &cobra.Command{
		Use:   "inventory",
		Short: "Manage the machine inventory (inventory.toml)",
		Args:  cobra.NoArgs,
		Run:   func(c *cobra.Command, a []string) { inventoryList() },
	}
	inv.AddCommand(&cobra.Command{Use: "list", Short: "List machines",
		Args: cobra.NoArgs, Run: func(c *cobra.Command, a []string) { inventoryList() }})

	add := &cobra.Command{
		Use:   "add <name>",
		Short: "Add or update a machine",
		Args:  cobra.ExactArgs(1),
		Run: func(c *cobra.Command, a []string) {
			set := map[string]string{}
			for _, k := range []string{"domain", "address", "principals", "roles", "notes"} {
				if c.Flags().Changed(k) {
					v, _ := c.Flags().GetString(k)
					set[k] = v
				}
			}
			inventoryAdd(a[0], set)
		},
	}
	add.Flags().String("domain", "", "trust domain (required for new machines)")
	add.Flags().String("address", "", "ssh destination (host or user@host)")
	add.Flags().String("principals", "", "comma-separated host-cert principals")
	add.Flags().String("roles", "", "comma-separated roles (ssh-host, caddy-edge, ...)")
	add.Flags().String("notes", "", "free-form notes")
	inv.AddCommand(add)

	inv.AddCommand(&cobra.Command{Use: "remove <name>", Short: "Remove a machine",
		Args: cobra.ExactArgs(1), Run: func(c *cobra.Command, a []string) { inventoryRemove(a[0]) }})
	return inv
}

// ---------------------------------------------------------------- status

func cmdStatus() {
	reg := loadRegistry()
	inv := loadInventory()
	head("registry")
	for _, dn := range reg.domainNames() {
		d := reg.Domains[dn]
		say("  %-6s anchors[%s]  slots u/%s h/%s t/%s c/%s  pattern %s",
			dn, strings.Join(d.Anchors, " "), d.UserSlot, d.HostSlot, d.TLSSlot, d.ClientSlot, d.HostPattern)
	}
	for _, an := range reg.anchorNames() {
		a := reg.Anchors[an]
		say("  anchor %-3s holder=%s location=%s yubikey=%s", an, a.Holder, a.Location, a.YubikeySerial)
	}
	head("inventory (%d machines)", len(inv.Machines))
	for _, name := range sortedKeys(inv.Machines) {
		m := inv.Machines[name]
		say("  %-14s %-6s %s", name, m.Domain, m.sshDest(name, reg.domain(m.Domain)))
	}
	head("queue (pending signing requests)")
	pending := 0
	for _, dn := range reg.domainNames() {
		entries, err := os.ReadDir(trustPath("queue", dn))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			say("  %s/%s", dn, e.Name())
			pending++
		}
	}
	say("  (%d pending)", pending)
	head("issued certificates")
	for _, dn := range reg.domainNames() {
		entries := loadLedger(dn)
		if len(entries) > 0 {
			revoked := 0
			for _, e := range entries {
				if e.Revoked {
					revoked++
				}
			}
			say("  %-6s %d issued, %d revoked", dn, len(entries), revoked)
		}
	}
}

// ---------------------------------------------------------------- expiring

func cmdCertExpiring(args []string) {
	days := 21
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil {
			days = n
		}
	}
	cutoff := time.Now().AddDate(0, 0, days).Format("2006-01-02")
	reg := loadRegistry()
	head("certificates expiring on or before %s", cutoff)
	found := false
	for _, dn := range reg.domainNames() {
		for _, e := range loadLedger(dn) {
			if e.Revoked || e.Expires == "" || e.Expires == "?" {
				continue
			}
			if e.Expires <= cutoff {
				say("  %-6s %-5s %-24s expires %s (%s)", dn, e.Type, e.Identity, e.Expires, e.File)
				found = true
			}
		}
	}
	if !found {
		good("nothing expiring within %d days", days)
	}
}

// ---------------------------------------------------------------- revoke

func cmdCertRevoke(args []string) {
	reg := loadRegistry()
	domainName := args[0]
	reg.domain(domainName)

	var serials []uint64
	for _, s := range args[1:] {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			fatal("bad serial %q — revoke works from ledger serials (see index/%s.tsv)", s, domainName)
		}
		serials = append(serials, n)
	}

	head("Revoke %s serial(s) %v into the domain KRL", domainName, serials)

	// 1. Validate every serial exists in the ledger BEFORE mutating anything.
	//    (dry-run makes markRevoked a no-op read; we only inspect notFound.)
	ledgerEntries := loadLedger(domainName)
	known := map[uint64]bool{}
	for _, e := range ledgerEntries {
		if e.Serial != 0 {
			known[e.Serial] = true
		}
	}
	var missing []uint64
	for _, s := range serials {
		if !known[s] {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		fatal("serial(s) %v not found in the %s ledger — nothing was changed", missing, domainName)
	}

	// 2. Build the KRL groups from the ledger PLUS the serials being revoked
	//    now, so the KRL is written before the ledger and a missing CA pub is
	//    a hard error (never a silently smaller KRL).
	revokedByAnchor := map[string]map[uint64]bool{}
	addRevocation := func(anchor string, serial uint64) {
		if revokedByAnchor[anchor] == nil {
			revokedByAnchor[anchor] = map[uint64]bool{}
		}
		revokedByAnchor[anchor][serial] = true
	}
	newlyRevoked := map[uint64]string{} // serial -> anchor
	for _, s := range serials {
		newlyRevoked[s] = ""
	}
	for _, e := range ledgerEntries {
		if e.Serial == 0 {
			continue
		}
		if e.Revoked {
			addRevocation(e.Anchor, e.Serial)
		}
		if _, want := newlyRevoked[e.Serial]; want {
			addRevocation(e.Anchor, e.Serial)
		}
	}

	var groups []krlCAGroup
	for anchor, set := range revokedByAnchor {
		var sers []uint64
		for s := range set {
			sers = append(sers, s)
		}
		gotCA := false
		for _, role := range []string{"user", "host"} {
			caPub, err := os.ReadFile(caPubPath(domainName, role, anchor))
			if err != nil {
				continue
			}
			groups = append(groups, krlCAGroup{caPub: caPub, serials: sers})
			gotCA = true
		}
		if !gotCA {
			fatal("cannot build KRL: no CA public key for anchor %q in pub/ — %s revocations would be silently dropped. Pull the full repo and retry.", anchor, domainName)
		}
	}

	version := uint64(nowUnix())
	act(fmt.Sprintf("write %s (version %d)", krlPath(domainName), version),
		"Native PROTOCOL.krl writer; revokes by certificate serial per CA.",
		func() error {
			return writeKRL(krlPath(domainName), groups, version,
				fmt.Sprintf("ykt %s revocations %s", domainName, today()))
		})

	// 3. Only after the KRL is written, mark the ledger (idempotent + batched).
	act("record the revocation(s) in the ledger", "", func() error {
		_, notFound, err := markRevoked(domainName, serials)
		if err != nil {
			return err
		}
		if len(notFound) > 0 {
			return fmt.Errorf("serials %v vanished from ledger between validate and mark", notFound)
		}
		return nil
	})

	warn("Revocation is only real once every host has the new KRL:")
	say("  ykt remote install %s --apply     (pushes the KRL everywhere)", domainName)
	say("  (or re-run 'sudo ykt init host %s' on each host)", domainName)
}

func expiryDays(days int) string {
	return time.Now().AddDate(0, 0, days).Format("2006-01-02")
}

func mustRandRead(b []byte) {
	if _, err := rand.Read(b); err != nil {
		fatal("entropy failure: %v", err)
	}
}
