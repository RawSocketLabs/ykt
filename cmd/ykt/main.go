package main

// ykt — YubiKey-anchored offline CA for SSH + mTLS.
// CLI structure via cobra; see trust/README.md.

import (
	"crypto/rand"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// version is injected at build time via -ldflags "-X main.version=..." (release
// binaries and the Makefile). Left as "dev" for plain `go build`/`go run`.
var version = "dev"

// effectiveVersion prefers the ldflags value; for `go install ...@vX.Y.Z`
// (no ldflags) it falls back to the module version the toolchain records.
func effectiveVersion() string {
	if version != "" && version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

func main() {
	root := &cobra.Command{
		Use:           "ykt",
		Short:         "YubiKey-anchored offline CA for SSH and mTLS (native Go)",
		Long:          "Offline YubiKey-anchored certificate authority for SSH and mTLS\nacross your configured trust domains (see config.toml).",
		Version:       effectiveVersion(),
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
		grouped("start", newVerifyCmd()),
		grouped("start", newDocsCmd()),
		grouped("extra", newAuditCmd()),
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
	host.Flags().StringVar(&sshdLogLevel, "log-level", "VERBOSE", `sshd LogLevel in the drop-in (VERBOSE logs which cert logged in; "" to omit)`)

	init.AddCommand(user, host)
	return init
}

// newCertCmd groups the certificate lifecycle at the CA.
func newCertCmd() *cobra.Command {
	cert := &cobra.Command{Use: "cert", Short: "Certificate lifecycle: sign, install, renew, revoke, expiring"}

	var renewVerify bool
	renew := &cobra.Command{
		Use:   "renew <person> <domain...>",
		Short: "Re-request certs for your existing daily key (no reset); then `cert sign`",
		Args:  cobra.MinimumNArgs(2),
		Run:   func(c *cobra.Command, a []string) { cmdCertRenew(a, renewVerify) },
	}
	renew.Flags().BoolVar(&renewVerify, "verify-required", false, "require FIDO2 PIN on every SSH use, where supported")

	cert.AddCommand(
		&cobra.Command{Use: "sign <anchor>", Short: "Sign everything queued for this anchor's domains",
			Args: cobra.ExactArgs(1), Run: func(c *cobra.Command, a []string) { cmdSign(a) }},
		&cobra.Command{Use: "install <name> <domain...>", Short: "After signing: place SSH certs, import TLS certs into PIV slots",
			Args: cobra.MinimumNArgs(2), Run: func(c *cobra.Command, a []string) { cmdCertInstall(a) }},
		renew,
		&cobra.Command{Use: "revoke <domain> <serial...>", Short: "Revoke ledger serials into the domain KRL",
			Args: cobra.MinimumNArgs(2), Run: func(c *cobra.Command, a []string) { cmdCertRevoke(a) }},
		&cobra.Command{Use: "expiring [days]", Short: "List certificates expiring within N days (default 21)",
			Args: cobra.MaximumNArgs(1), Run: func(c *cobra.Command, a []string) { cmdCertExpiring(a) }},
	)
	return cert
}

// cmdCertRenew re-queues signing requests for the existing daily key without a
// factory reset — the renewal path for a cert nearing expiry.
func cmdCertRenew(args []string, verifyRequired bool) {
	note("renew = re-queue signing requests for your EXISTING daily key (no FIDO/PIV reset).")
	cmdInitUser(args, true, verifyRequired) // keep = true
}

// newRemoteCmd groups the operator-side remote host actions.
func newRemoteCmd() *cobra.Command {
	remote := &cobra.Command{Use: "remote", Short: "Operator-side remote host management (collect keys, install trust)"}
	var since, out string
	logins := &cobra.Command{
		Use:   "logins [domain] [host...]",
		Short: "Harvest SSH certificate logins (who logged in where/when) from hosts",
		Args:  cobra.ArbitraryArgs,
		Run:   func(c *cobra.Command, a []string) { cmdRemoteLogins(a, since, out) },
	}
	logins.Flags().StringVar(&since, "since", "7 days ago", "how far back to read (journalctl --since syntax)")
	logins.Flags().StringVar(&out, "out", "", "also write the rows as TSV to this file")

	remote.AddCommand(
		&cobra.Command{Use: "collect <domain> [machine...]", Short: "Fetch host keys into the queue (inventory-driven)",
			Args: cobra.MinimumNArgs(1), Run: func(c *cobra.Command, a []string) { cmdRemoteCollect(a) }},
		newRemoteInstallCmd(),
		logins,
	)
	return remote
}

func newRemoteInstallCmd() *cobra.Command {
	var apply, all bool
	c := &cobra.Command{
		Use:   "install [domain] [machine...]",
		Short: "Install/refresh trust on hosts (prints commands; --apply pushes via SSH; --all sweeps every domain)",
		Args:  cobra.ArbitraryArgs,
		Run:   func(c *cobra.Command, a []string) { cmdRemoteInstall(a, apply, all) },
	}
	c.Flags().BoolVar(&apply, "apply", false, "push via native SSH (validated, one host at a time) instead of printing")
	c.Flags().BoolVar(&all, "all", false, "refresh every host in every domain — run after `cert revoke` so KRLs propagate")
	c.Flags().StringVar(&sshdLogLevel, "log-level", "VERBOSE", `sshd LogLevel in the drop-in (VERBOSE logs which cert logged in; "" to omit)`)
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
		newBootstrapCmd(),
		newCaddyCmd(),
	)
	return setup
}

// newAuditCmd exposes the machine-local action log (view / export / path).
func newAuditCmd() *cobra.Command {
	audit := &cobra.Command{
		Use:         "audit [N|all]",
		Short:       "Show this machine's local ykt action log (default: last 40 lines)",
		Annotations: storeOptionalAnn,
		Args:        cobra.MaximumNArgs(1),
		Run:         func(c *cobra.Command, a []string) { cmdAudit(a) },
	}
	audit.AddCommand(
		&cobra.Command{Use: "export <path>", Short: "Copy the audit log to a file",
			Annotations: storeOptionalAnn, Args: cobra.ExactArgs(1),
			Run: func(c *cobra.Command, a []string) { cmdAuditExport(a[0]) }},
		&cobra.Command{Use: "path", Short: "Print the audit log path",
			Annotations: storeOptionalAnn, Args: cobra.NoArgs,
			Run: func(c *cobra.Command, a []string) { cmdAuditPath() }},
	)
	return audit
}

// newVerifyCmd groups offline verification of the trust material.
func newVerifyCmd() *cobra.Command {
	verify := &cobra.Command{Use: "verify", Short: "Verify trust material (attestations) offline"}
	verify.AddCommand(
		&cobra.Command{Use: "attestation [anchor...]", Short: "Prove CA keys are on-device via PIV attestation (no hardware needed)",
			Args: cobra.ArbitraryArgs, Run: func(c *cobra.Command, a []string) { cmdVerifyAttestation(a) }},
	)
	return verify
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

	clone := &cobra.Command{
		Use:         "clone <url> [dir]",
		Short:       "Clone a trust store and record it (git clone + setup home)",
		Annotations: storeOptionalAnn,
		Args:        cobra.RangeArgs(1, 2),
		Run: func(c *cobra.Command, a []string) {
			dir := ""
			if len(a) == 2 {
				dir = a[1]
			}
			cmdRepoClone(a[0], dir)
		},
	}

	var rebase bool
	sync := &cobra.Command{
		Use:   "sync",
		Short: "Pull the latest store (fast-forward; --rebase if you have local commits)",
		Args:  cobra.NoArgs,
		Run:   func(c *cobra.Command, a []string) { cmdRepoSync(rebase) },
	}
	sync.Flags().BoolVar(&rebase, "rebase", false, "rebase local commits on top of the remote instead of fast-forward")

	var msg string
	push := &cobra.Command{
		Use:   "push",
		Short: "Commit local changes and push the store (rebases onto the remote first)",
		Args:  cobra.NoArgs,
		Run:   func(c *cobra.Command, a []string) { cmdRepoPush(msg) },
	}
	push.Flags().StringVarP(&msg, "message", "m", "", `commit message (default: "chore: update trust material")`)

	repo.AddCommand(
		initc,
		clone,
		sync,
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
	var includeAt string
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Create the Include block + ~/.ssh/ykt domain folders + defaults",
		Args:  cobra.NoArgs,
		Run: func(c *cobra.Command, a []string) {
			switch includeAt {
			case "", "top":
				cmdSSHConfigInit("top")
			case "bottom":
				cmdSSHConfigInit("bottom")
			default:
				fatal("--include must be 'top' or 'bottom'")
			}
		},
	}
	initCmd.Flags().StringVar(&includeAt, "include", "top",
		"where to place the managed Include block in ~/.ssh/config: 'top' (ykt wins) or 'bottom' (your config wins)")

	root.AddCommand(
		initCmd,
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

func newBootstrapCmd() *cobra.Command {
	bootstrap := &cobra.Command{
		Use:     "bootstrap",
		Aliases: []string{"vps"}, // old name kept working
		Short:   "Make a fresh box trust your CA: cloud-init / install-script / trust (public material only)",
	}
	var ciUser, scUser string
	ci := &cobra.Command{
		Use:   "cloud-init <domain>",
		Short: "Emit cloud-init user-data that trusts your user CA (push at box creation)",
		Args:  cobra.ExactArgs(1),
		Run:   func(c *cobra.Command, a []string) { cmdBootstrapCloudInit(a[0], ciUser) },
	}
	ci.Flags().StringVar(&ciUser, "user", "root", "login user your cert principal must match")
	sc := &cobra.Command{
		Use:   "install-script <domain>",
		Short: "Emit a paste-on-the-box shell snippet that trusts your user CA",
		Args:  cobra.ExactArgs(1),
		Run:   func(c *cobra.Command, a []string) { cmdBootstrapInstallScript(a[0], scUser) },
	}
	sc.Flags().StringVar(&scUser, "user", "root", "login user your cert principal must match")
	trust := &cobra.Command{
		Use:   "trust <ip-or-host>",
		Short: "Pin a box's host key to known_hosts (TOFU-confirm) so connecting won't prompt",
		Args:  cobra.ExactArgs(1),
		Run:   func(c *cobra.Command, a []string) { cmdBootstrapTrust(a[0]) },
	}
	bootstrap.AddCommand(ci, sc, trust)
	return bootstrap
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
			for _, k := range []string{"domain", "trust", "address", "principals", "roles", "notes"} {
				if c.Flags().Changed(k) {
					v, _ := c.Flags().GetString(k)
					set[k] = v
				}
			}
			inventoryAdd(a[0], set)
		},
	}
	add.Flags().String("domain", "", "primary trust domain (required for new machines)")
	add.Flags().String("trust", "", "ADDITIONAL user-CA domains this host accepts (comma-separated)")
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
	if ex := expiringCerts(reg, 21); len(ex) > 0 {
		head("attention")
		warn("%d certificate(s) expire within 21 days — `ykt cert expiring` for details, `ykt cert renew` to re-request", len(ex))
	}
}

// ---------------------------------------------------------------- expiring

// expiringCert pairs a ledger entry with its domain for reporting.
type expiringCert struct {
	Domain string
	Entry  LedgerEntry
}

// expiringCerts returns the non-revoked certs expiring within `days` days,
// across every domain. Shared by `cert expiring` and the `status` summary.
func expiringCerts(reg *Registry, days int) []expiringCert {
	cutoff := time.Now().AddDate(0, 0, days).Format("2006-01-02")
	var out []expiringCert
	for _, dn := range reg.domainNames() {
		for _, e := range loadLedger(dn) {
			if e.Revoked || e.Expires == "" || e.Expires == "?" {
				continue
			}
			if e.Expires <= cutoff {
				out = append(out, expiringCert{dn, e})
			}
		}
	}
	return out
}

func cmdCertExpiring(args []string) {
	days := 21
	if len(args) > 0 {
		if n, err := strconv.Atoi(args[0]); err == nil {
			days = n
		}
	}
	reg := loadRegistry()
	head("certificates expiring within %d days", days)
	ex := expiringCerts(reg, days)
	for _, x := range ex {
		say("  %-6s %-5s %-24s expires %s (%s)", x.Domain, x.Entry.Type, x.Entry.Identity, x.Entry.Expires, x.Entry.File)
	}
	if len(ex) == 0 {
		good("nothing expiring within %d days", days)
	} else {
		note("renew with `ykt cert renew <person> <domain...>` (no key reset), then `ykt cert sign`.")
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

	// Classify: the SSH KRL only revokes SSH (user/host) certs. mTLS (tls) certs
	// are X.509 — the KRL can't enforce them, so we record but don't pretend.
	serialType := map[uint64]string{}
	for _, e := range ledgerEntries {
		if e.Serial != 0 {
			serialType[e.Serial] = e.Type
		}
	}
	var tlsSerials []uint64
	for _, s := range serials {
		if serialType[s] == "tls" {
			tlsSerials = append(tlsSerials, s)
		}
	}
	sshCount := len(serials) - len(tlsSerials)

	// Confirm before mutating — the only destructive command that used to skip this.
	var plan []string
	if sshCount > 0 {
		plan = append(plan, fmt.Sprintf("revoke %d SSH serial(s) into %s (enforced once hosts get the KRL)", sshCount, krlPath(domainName)))
	}
	if len(tlsSerials) > 0 {
		plan = append(plan, fmt.Sprintf("record %d mTLS serial(s) %v as REVOKED in the ledger (NOT enforced by ykt yet)", len(tlsSerials), tlsSerials))
	}
	plan = append(plan, "mark the serial(s) REVOKED in the ledger")
	confirmPlan(plan)

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
		if e.Serial == 0 || e.Type == "tls" {
			continue // the SSH KRL never lists X.509 (mTLS) serials
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

	if sshCount > 0 {
		warn("SSH revocation is only real once every host has the new KRL:")
		say("  ykt remote install %s --apply     (or --all after revoking across domains)", domainName)
		say("  (or re-run 'sudo ykt init host %s' on each host)", domainName)
	}
	if len(tlsSerials) > 0 {
		warn("mTLS revocation is RECORDED in the ledger but NOT ENFORCED by ykt yet:")
		say("  a revoked mTLS cert keeps working until it expires (TLSValidityDays).")
		say("  To enforce now, re-issue the domain's client CA, or keep TLS lifetimes short.")
		say("  (An X.509 CRL for mTLS is a planned follow-up.)")
	}
}

func expiryDays(days int) string {
	return time.Now().AddDate(0, 0, days).Format("2006-01-02")
}

func mustRandRead(b []byte) {
	if _, err := rand.Read(b); err != nil {
		fatal("entropy failure: %v", err)
	}
}
