package main

// host-setup: run ON a host (with sudo) to make it trust a domain's user CA.
// Installs the canonical trust files (shared with host-install), validates
// sshd before reloading in a single guarded step, walks the operator through a
// live login check, and only then offers to disable password authentication.
//
// One domain per host by default; --multi opts into a shared-principal host
// (see warnIfMultiDomain).

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

func cmdInitHost(domains []string, multi bool, breakGlassFile string) {
	if os.Geteuid() != 0 && !dryRun {
		fatal("init host writes /etc/ssh — run it with sudo")
	}
	reg := loadRegistry()
	for _, d := range domains {
		reg.domain(d)
	}
	warnIfMultiDomain(domains, multi)
	if breakGlassFile != "" {
		if b, err := os.ReadFile(breakGlassFile); err != nil {
			fatal("reading break-glass key %s: %v", breakGlassFile, err)
		} else if verr := validSSHPublicKey(b); verr != nil {
			fatal("%s is not a valid SSH public key: %v", breakGlassFile, verr)
		}
	}
	hostname := shortHost(hostnameOrDie())

	head("Host setup: trust domain(s) %s on this machine", strings.Join(domains, " "))

	// ---- preflight ---------------------------------------------------------
	caData, err := gatherHostCA(domains)
	if err != nil {
		fatal("%v", err)
	}
	if raw, err := os.ReadFile("/etc/ssh/sshd_config"); err == nil &&
		!strings.Contains(string(raw), "sshd_config.d") {
		warn("/etc/ssh/sshd_config has no Include for sshd_config.d — the drop-in will be")
		warn("ignored. Add 'Include /etc/ssh/sshd_config.d/*.conf' before continuing.")
	}
	krlBytes := singleKRL(domains)
	if krlBytes == nil && len(domains) > 1 {
		for _, dn := range domains {
			if _, err := os.Stat(krlPath(dn)); err == nil {
				warn("[%s] has a KRL, but a multi-domain host uses a single RevokedKeys file", dn)
				warn("      — push revocations to this host manually until it is single-domain")
			}
		}
	}

	// host certificate: install if a signed one exists, else queue the request.
	hostCertSrc := ""
	var queueDomains []string
	for _, dn := range domains {
		src := trustPath("dist", dn, distHostCertName(hostname))
		if _, err := os.Stat(src); err == nil && hostCertSrc == "" {
			hostCertSrc = src
		} else if err != nil {
			queueDomains = append(queueDomains, dn)
		}
	}
	dropIn := buildHostDropIn(domains, hostCertSrc != "", krlBytes != nil)

	// ---- plan ---------------------------------------------------------------
	planLines := []string{
		fmt.Sprintf("write %s (user CAs of: %s)", hostTrustCAFile, strings.Join(domains, " ")),
		fmt.Sprintf("write %s (sshd drop-in)", hostTrustDropIn),
	}
	if krlBytes != nil {
		planLines = append(planLines, fmt.Sprintf("write %s (revocation list)", hostTrustKRLFile))
	}
	if hostCertSrc != "" {
		planLines = append(planLines, "install this host's signed certificate → "+hostCertFile)
	}
	if breakGlassFile != "" {
		planLines = append(planLines, "install break-glass emergency key → "+breakGlassAuthKeysPath())
	}
	for _, dn := range queueDomains {
		planLines = append(planLines, fmt.Sprintf("[%s] queue this host's key for a host certificate at the next 'cert sign'", dn))
	}
	planLines = append(planLines,
		"validate + reload sshd in ONE step (reload only if sshd -t passes)",
		"guided check: you verify certificate login from another terminal",
		"then — and only if verified — offer to disable password authentication")
	confirmPlan(planLines)

	// ---- execute -------------------------------------------------------------
	if breakGlassFile != "" {
		installBreakGlass(breakGlassFile)
	}
	act("write "+hostTrustCAFile, "", func() error {
		return writeFileAtomic(hostTrustCAFile, caData, 0o644)
	})
	if krlBytes != nil {
		act("write "+hostTrustKRLFile, "", func() error {
			return writeFileAtomic(hostTrustKRLFile, krlBytes, 0o644)
		})
	}
	if hostCertSrc != "" {
		src := hostCertSrc
		act("install the signed host certificate", "", func() error {
			return copyFile(src, hostCertFile, 0o644)
		})
	}
	act("write "+hostTrustDropIn, "", func() error {
		return writeFileAtomic(hostTrustDropIn, []byte(dropIn), 0o644)
	})
	for _, dn := range queueDomains {
		dn := dn
		act(fmt.Sprintf("[%s] queue this host's public key for signing", dn),
			"A host certificate removes first-connection prompts for clients; sign at the next 'cert sign'.",
			func() error {
				pub, err := os.ReadFile(hostCertKeyFile + ".pub")
				if err != nil {
					return err
				}
				dst := trustPath("queue", dn, queueHostKeyName(hostname))
				if err := writeFileAtomic(dst, pub, 0o644); err != nil {
					return err
				}
				return chownToSudoUser(dst, trustPath("queue", dn), trustPath("queue"))
			})
	}

	act("validate and reload sshd", "Reload runs ONLY if sshd -t passes.", validateReloadLocalSSHD)

	// ---- guided validation ---------------------------------------------------
	head("Validate — DO NOT close this terminal")
	say("From ANOTHER terminal (or another machine), log in with your certificate:")
	for _, dn := range domains {
		say("  ssh -o IdentitiesOnly=yes -i ~/.ssh/"+dailyKeyName+" -o CertificateFile=~/.ssh/%s <user>@%s",
			installedSSHCertName(dn), hostname)
	}
	say("Expect: no password prompt, one YubiKey touch.")
	if dryRun {
		note("dry-run: skipping validation + password-auth question")
		return
	}
	if !confirm("Did certificate login work?") {
		warn("Leaving password authentication ON. Fix the issue and re-run 'init host';")
		warn("nothing destructive has happened.")
		return
	}
	good("certificate login verified")

	// ---- optional: turn off password auth ------------------------------------
	if !confirm("Disable password authentication for sshd now?") {
		say("Keeping passwords enabled. Re-run 'init host' any time to disable them.")
		return
	}
	// Refuse to remove the last non-certificate way in without a break-glass
	// path: an installed break-glass authorized_keys entry, OR an explicit
	// acknowledgement that out-of-band console access exists.
	if !breakGlassPresent() {
		warn("No break-glass authorized_keys entry found. Disabling passwords now")
		warn("means the ONLY way in is a valid certificate — if the CA/YubiKey is")
		warn("lost or a cert expires with none to replace it, you are locked out.")
		warn("Fix: re-run with --break-glass <offline-key.pub>, or confirm you have")
		warn("out-of-band access (provider console / IPMI / physical).")
		if !confirm("I have out-of-band console access — disable passwords anyway?") {
			say("Left passwords ON. Add a break-glass key and re-run.")
			return
		}
	}
	act("write "+hostTrustNoPass, "", func() error {
		return writeFileAtomic(hostTrustNoPass,
			[]byte("# managed by ykt init host\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n"), 0o644)
	})
	act("validate and reload sshd", "Reload runs ONLY if sshd -t passes.", validateReloadLocalSSHD)
	warn("Password auth is OFF. Keep out-of-band access (console/IPMI/provider")
	warn("console) and the break-glass key current. To undo:")
	say("  sudo rm %s && sudo systemctl reload sshd", hostTrustNoPass)
}

// breakGlassMarker tags the break-glass line in a user's authorized_keys so it
// is idempotent to install and detectable. The key is appended to a specific
// account's authorized_keys (not a global AuthorizedKeysFile), so it: (a) never
// overrides sshd's default AuthorizedKeysFile or drops authorized_keys2, (b) is
// scoped to that one recovery account rather than every account, and (c)
// survives `remote install` (which only touches /etc/ssh/*).
const breakGlassMarker = "ykt-break-glass"

// breakGlassAccount picks the recovery account: the invoking sudo user (so you
// recover as yourself, which works even when PermitRootLogin is off), falling
// back to root. Returns login name, home dir, and uid/gid for chown.
func breakGlassAccount() (name, home string, uid, gid int) {
	lookup := func(n string) (string, string, int, int, bool) {
		u, err := user.Lookup(n)
		if err != nil {
			return "", "", 0, 0, false
		}
		ui, _ := strconv.Atoi(u.Uid)
		gi, _ := strconv.Atoi(u.Gid)
		return u.Username, u.HomeDir, ui, gi, true
	}
	if s := os.Getenv("SUDO_USER"); s != "" && s != "root" {
		if n, h, ui, gi, ok := lookup(s); ok {
			return n, h, ui, gi
		}
	}
	if n, h, ui, gi, ok := lookup("root"); ok {
		return n, h, ui, gi
	}
	return "root", "/root", 0, 0
}

func breakGlassAuthKeysPath() string {
	_, home, _, _ := breakGlassAccount()
	return filepath.Join(home, ".ssh", "authorized_keys")
}

// installBreakGlass appends the offline emergency public key to the recovery
// account's authorized_keys, marked and de-duplicated.
func installBreakGlass(pubFile string) {
	pub, err := os.ReadFile(pubFile)
	if err != nil {
		fatal("reading break-glass key %s: %v", pubFile, err)
	}
	if perr := validSSHPublicKey(pub); perr != nil {
		fatal("%s is not a valid SSH public key: %v", pubFile, perr)
	}
	name, home, uid, gid := breakGlassAccount()
	akPath := filepath.Join(home, ".ssh", "authorized_keys")
	// Build the marked line: "<type> <base64> ykt-break-glass".
	fields := strings.Fields(string(pub))
	if len(fields) < 2 {
		fatal("%s is not a valid SSH public key", pubFile)
	}
	line := fields[0] + " " + fields[1] + " " + breakGlassMarker

	act(fmt.Sprintf("install break-glass key into %s (%s)", akPath, name),
		"Offline emergency key — the way in if the CA is ever unavailable.",
		func() error {
			if dryRun {
				return nil
			}
			sshDir := filepath.Dir(akPath)
			_, dirExisted := os.Stat(sshDir)
			if err := os.MkdirAll(sshDir, 0o700); err != nil {
				return err
			}
			// If WE created ~/.ssh (didn't exist), hand it to the account so the
			// operator isn't locked out of their own SSH dir. Don't touch a
			// pre-existing dir's ownership.
			if dirExisted != nil {
				if err := os.Chown(sshDir, uid, gid); err != nil {
					return err
				}
			}
			existing, _ := os.ReadFile(akPath)
			if strings.Contains(string(existing), breakGlassMarker) {
				// replace the existing marked line rather than duplicate
				var kept []string
				for _, l := range strings.Split(string(existing), "\n") {
					if !strings.Contains(l, breakGlassMarker) {
						kept = append(kept, l)
					}
				}
				existing = []byte(strings.TrimRight(strings.Join(kept, "\n"), "\n"))
			}
			out := strings.TrimRight(string(existing), "\n")
			if out != "" {
				out += "\n"
			}
			out += line + "\n"
			if err := writeFileAtomic(akPath, []byte(out), 0o600); err != nil {
				return err
			}
			return os.Chown(akPath, uid, gid)
		})
	note("break-glass key installed for account %q — verify you can log in with it BEFORE relying on it.", name)
}

func breakGlassPresent() bool {
	b, err := os.ReadFile(breakGlassAuthKeysPath())
	return err == nil && strings.Contains(string(b), breakGlassMarker)
}

// resolveSbin finds a system binary that may live in /usr/sbin or /sbin —
// directories frequently absent from PATH under sudo. Falls back to the bare
// name (letting exec use PATH) if not found in the known locations.
func resolveSbin(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		p := filepath.Join(dir, name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return name
}

// validateReloadLocalSSHD runs `sshd -t` and reloads ONLY if it passes, as one
// step — so a skipped/failed validation can never leave a reloaded-but-broken
// daemon.
func validateReloadLocalSSHD() error {
	if dryRun {
		return nil
	}
	sshd := resolveSbin("sshd")
	if out, err := exec.Command(sshd, "-t").CombinedOutput(); err != nil {
		return fmt.Errorf("`%s -t` FAILED — not reloading: %s", sshd, strings.TrimSpace(string(out)))
	}
	return reloadSSHD()
}

func reloadSSHD() error {
	systemctl := resolveSbin("systemctl")
	if _, err := exec.Command(systemctl, "reload", "sshd").CombinedOutput(); err == nil {
		return nil
	}
	if out, err := exec.Command(systemctl, "reload", "ssh").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl reload sshd/ssh: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// chownToSudoUser hands files written as root back to the invoking user so the
// repo stays committable without sudo.
func chownToSudoUser(paths ...string) error {
	uid, uerr := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, gerr := strconv.Atoi(os.Getenv("SUDO_GID"))
	if uerr != nil || gerr != nil {
		//nolint:nilerr // best-effort: not run under sudo means nothing to hand back
		return nil
	}
	for _, p := range paths {
		_ = os.Chown(p, uid, gid)
	}
	return nil
}
