package main

// doctor: preflight the host for ykt. Checks the PC/SC stack, connected
// YubiKeys, external tools (ssh-keygen with sk support, ykman), and trust
// files. With --fix it builds a plan of package-manager commands for whatever
// is missing, confirms once, and runs them attached to this terminal.

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
)

type depFix struct {
	problem string
	argvs   [][]string // commands that install/enable the dependency
}

func cmdDoctor(fix bool) {
	head("ykt doctor (%s)", runtime.GOOS)
	var fixes []depFix
	unknown := false // a check that could not be completed (not fixable, but not OK)

	// ---- PC/SC + YubiKeys ----------------------------------------------------
	keys, err := listYubiKeys()
	switch {
	case err == nil:
		good("PC/SC stack reachable")
		if len(keys) == 0 {
			warn("no YubiKeys connected")
		}
		for serial, card := range keys {
			if yk, err := piv.Open(card); err == nil {
				v := yk.Version()
				r, _ := yk.Retries()
				caps := capsFor(yk)
				yk.Close()
				good("YubiKey serial %d: firmware %d.%d.%d · PIN retries %d", serial, v.Major, v.Minor, v.Patch, r)
				say("    daily-key features: %s", caps.summary())
				say("    PIV applet reachable — mTLS + cert-stash slots usable")
			} else {
				warn("YubiKey serial %d present but busy: %v", serial, err)
			}
		}
	case runtime.GOOS == "linux":
		warn("PC/SC unreachable: %v", err)
		fixes = append(fixes, depFix{
			problem: "pcscd (smart-card daemon) missing or not running",
			argvs:   pcscdFix(),
		})
	default:
		// macOS/Windows ship PC/SC in the OS — an error here is a driver or
		// service problem, not a missing package: flag it, but not as a fix.
		warn("PC/SC unreachable: %v", err)
		if runtime.GOOS == "windows" {
			warn("check the Smart Card service:  sc start SCardSvr")
		}
		unknown = true
	}

	// ---- external tools --------------------------------------------------------
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		warn("ssh-keygen missing — needed for FIDO2 sk key generation")
		fixes = append(fixes, depFix{problem: "OpenSSH client missing", argvs: opensshFix()})
	} else if out, err := exec.Command("ssh", "-Q", "key").Output(); err != nil {
		warn("could not probe ssh key types (`ssh -Q key`: %v) — cannot confirm sk support", err)
		unknown = true
	} else if !strings.Contains(string(out), "sk-ssh-ed25519@openssh.com") {
		warn("ssh lacks security-key (sk) support — hardware-backed ssh keys will fail")
		if runtime.GOOS == "darwin" {
			warn("Apple's bundled OpenSSH disables FIDO support")
			fixes = append(fixes, depFix{problem: "OpenSSH without sk support",
				argvs: [][]string{{"brew", "install", "openssh"}}})
		} else {
			fixes = append(fixes, depFix{problem: "OpenSSH too old for sk keys", argvs: opensshFix()})
		}
	} else {
		good("ssh-keygen present with security-key support")
	}

	if _, err := exec.LookPath("ykman"); err != nil {
		warn("ykman missing — needed for FIDO2 factory reset during init user")
		fixes = append(fixes, depFix{problem: "ykman (YubiKey Manager CLI) missing", argvs: ykmanFix()})
	} else {
		good("ykman present")
		checkYKInterfaces(&fixes)
	}

	// ---- trust material (only when run inside a repo) ---------------------------
	if trustHome == "" {
		note("no config.toml found — dependency checks only (run inside the trust/ repo for trust-file checks)")
	} else if _, err := os.Stat(trustPath("config.toml")); err == nil {
		good("config %s", trustPath("config.toml"))
		reg := loadRegistry()
		for _, dn := range reg.domainNames() {
			if _, err := os.Stat(trustedUserCAPath(dn)); err == nil {
				good("[%s] trust files present", dn)
			} else {
				note("[%s] no trust files yet (init ca pending)", dn)
			}
		}
		if checkDailyKeySlots(reg) > 0 {
			unknown = true
		}
	}
	switch {
	case runtime.GOOS == "windows":
		note("ssh-agent on Windows uses a named pipe — not checked here")
	case os.Getenv("SSH_AUTH_SOCK") == "":
		warn("SSH_AUTH_SOCK not set — remote collect / remote install --apply need an ssh-agent")
	default:
		good("ssh-agent socket present")
	}

	// ---- --fix -----------------------------------------------------------------
	if len(fixes) == 0 {
		if unknown {
			warn("no installable gaps, but a check above could not be completed — see warnings")
			os.Exit(1)
		}
		good("no missing dependencies")
		return
	}
	if !fix {
		warn("%d dependency problem(s) found — re-run with --fix to install, or run:", len(fixes))
		for _, f := range fixes {
			for _, argv := range f.argvs {
				say("  %s", shellJoin(argv))
			}
		}
		os.Exit(1)
	}
	var planLines []string
	for _, f := range fixes {
		for _, argv := range f.argvs {
			planLines = append(planLines, f.problem+" → "+shellJoin(argv))
		}
	}
	confirmPlan(planLines)
	for _, f := range fixes {
		for _, argv := range f.argvs {
			actCommand("fix: "+f.problem, argv, "Package-manager prompts (sudo password etc.) happen right here.")
		}
	}
	say("\nRe-run 'ykt doctor' to verify.")
}

// checkYKInterfaces finds connected YubiKeys whose PIV (CCID) or FIDO USB
// interface is disabled — the state a FIDO-only factory config or a fresh key
// can be in — and queues a fix to re-enable it. ykt needs CCID for PIV (anchor
// CA + mTLS slots) and FIDO for the daily sk key. Enabling requires a replug to
// take effect. Uses ykman because a disabled CCID interface is invisible to
// PC/SC, so ykt's own enumeration can't see the key at all.
func checkYKInterfaces(fixes *[]depFix) {
	out, err := exec.Command("ykman", "list", "--serials").Output()
	if err != nil {
		return // older ykman or none reachable; presence check already ran
	}
	for _, serial := range strings.Fields(string(out)) {
		info, err := exec.Command("ykman", "--device", serial, "info").Output()
		if err != nil {
			continue
		}
		ifaces, ok := usbInterfacesLine(string(info))
		if !ok {
			// Don't guess against the whole info blob — its applications table
			// contains "FIDO"/"CCID" too and would mask a genuinely disabled
			// interface (or misfire). Skip rather than misreport.
			note("YubiKey %s: couldn't read USB interface state from ykman — skipping interface check", serial)
			continue
		}
		enabled := true
		// name = human label, app = ykman's lowercase choice value.
		enable := func(name, app, why string) {
			enabled = false
			warn("YubiKey %s: %s USB interface disabled — %s (replug after enabling)", serial, name, why)
			*fixes = append(*fixes, depFix{
				problem: fmt.Sprintf("YubiKey %s: enable %s interface (replug after)", serial, name),
				argvs:   [][]string{{"ykman", "--device", serial, "config", "usb", "--enable", app, "--force"}},
			})
		}
		if !strings.Contains(ifaces, "CCID") {
			enable("PIV", "piv", "needed for anchor CA + mTLS slots")
		}
		if !strings.Contains(ifaces, "FIDO") {
			enable("FIDO2", "fido2", "needed for the daily sk key")
		}
		if enabled {
			good("YubiKey %s: PIV (CCID) + FIDO interfaces enabled", serial)
		}
	}
}

// usbInterfacesLine returns the "Enabled USB interfaces: ..." line from
// `ykman info` output. ok is false if no such line exists (label moved / new
// ykman format) — callers must NOT fall back to matching the whole blob, whose
// applications table also contains the CCID/FIDO tokens.
func usbInterfacesLine(info string) (line string, ok bool) {
	for _, l := range strings.Split(info, "\n") {
		if strings.Contains(l, "USB interface") {
			return l, true
		}
	}
	return "", false
}

// requireCleanDailyKeySlots is the hard gate for commands that actually WRITE
// daily-key PIV slots (cert install, setup key, init user). A slot collision or
// invalid slot would silently clobber an mTLS cert / the key stub, so refuse to
// proceed rather than warn-and-continue (which is all doctor/flow/init-ca do).
func requireCleanDailyKeySlots(reg *Registry) {
	if checkDailyKeySlots(reg) > 0 {
		fatal("resolve the daily-key slot problem(s) above in config.toml before continuing — proceeding would overwrite a PIV slot")
	}
}

// checkDailyKeySlots validates the PIV slots that all share the daily key's one
// namespace: each domain's client_slot (mTLS key+cert) and ssh_cert_slot
// (route-2 carrier), plus the reserved id_yk stub slot. A collision would make
// 'cert install' silently clobber one object with another (e.g. a stash slot
// overwriting an mTLS cert). Returns the number of problems found.
func checkDailyKeySlots(reg *Registry) int {
	type use struct{ slot, purpose string }
	var uses []use
	problems := 0
	stashConfigured := false
	for _, dn := range reg.domainNames() {
		d := reg.domain(dn)
		if d.ClientSlot != "" {
			if _, err := slotByName(d.ClientSlot); err != nil {
				warn("[%s] client_slot %q is not a usable PIV slot: %v", dn, d.ClientSlot, err)
				problems++
			} else {
				uses = append(uses, use{strings.ToLower(d.ClientSlot), dn + " mTLS (client_slot)"})
			}
		}
		if d.SSHCertSlot != "" {
			stashConfigured = true
			if _, err := slotByName(d.SSHCertSlot); err != nil {
				warn("[%s] ssh_cert_slot %q is not a usable PIV slot: %v", dn, d.SSHCertSlot, err)
				problems++
				continue
			}
			uses = append(uses, use{strings.ToLower(d.SSHCertSlot), dn + " SSH cert (ssh_cert_slot)"})
		}
	}
	if stashConfigured {
		uses = append(uses, use{strings.ToLower(sshKeyStashSlot), "id_yk key stub"})
	}
	seen := map[string]string{}
	for _, u := range uses {
		if prev, ok := seen[u.slot]; ok {
			warn("daily-key PIV slot %s is claimed by BOTH %s and %s — 'cert install' would clobber one", u.slot, prev, u.purpose)
			problems++
			continue
		}
		seen[u.slot] = u.purpose
	}
	switch {
	case !stashConfigured:
		note("no ssh_cert_slot set — 'carry only the key' (ykt setup key) is off; clients need the cert files")
	case problems == 0:
		good("daily-key slot map conflict-free — cert stash + 'setup key' viable (%d slots)", len(seen))
	}
	return problems
}

// linuxPkgInstall returns the install command for the first package manager
// found, with per-manager package names: {dnf, apt-get, pacman, zypper}.
func linuxPkgInstall(names map[string]string) [][]string {
	type mgr struct {
		bin  string
		args []string
	}
	for _, m := range []mgr{
		{"dnf", []string{"install", "-y"}},
		{"apt-get", []string{"install", "-y"}},
		{"pacman", []string{"-S", "--noconfirm"}},
		{"zypper", []string{"install", "-y"}},
	} {
		if _, err := exec.LookPath(m.bin); err == nil {
			pkg, ok := names[m.bin]
			if !ok || pkg == "" {
				continue
			}
			return [][]string{append(append([]string{"sudo", m.bin}, m.args...), pkg)}
		}
	}
	return [][]string{{"echo", "no supported package manager found — install manually"}}
}

func pcscdFix() [][]string {
	if runtime.GOOS != "linux" {
		return nil
	}
	cmds := linuxPkgInstall(map[string]string{
		"dnf": "pcsc-lite", "apt-get": "pcscd", "pacman": "pcsclite", "zypper": "pcsc-lite",
	})
	// only offer the systemd enable when we actually found a package manager
	// and this is a systemd host (the socket unit exists).
	if len(cmds) == 1 && cmds[0][0] == "sudo" {
		if _, err := os.Stat("/run/systemd/system"); err == nil {
			cmds = append(cmds, []string{"sudo", "systemctl", "enable", "--now", "pcscd.socket"})
		}
	}
	return cmds
}

func ykmanFix() [][]string {
	switch runtime.GOOS {
	case "linux":
		return linuxPkgInstall(map[string]string{
			"dnf": "yubikey-manager", "apt-get": "yubikey-manager", "pacman": "yubikey-manager", "zypper": "yubikey-manager",
		})
	case "darwin":
		return [][]string{{"brew", "install", "ykman"}}
	case "windows":
		return [][]string{{"winget", "install", "--id", "Yubico.YubiKeyManagerCLI", "-e"}}
	}
	return nil
}

func opensshFix() [][]string {
	switch runtime.GOOS {
	case "linux":
		return linuxPkgInstall(map[string]string{
			"dnf": "openssh-clients", "apt-get": "openssh-client", "pacman": "openssh", "zypper": "openssh-clients",
		})
	case "darwin":
		return [][]string{{"brew", "install", "openssh"}}
	case "windows":
		return [][]string{{"winget", "install", "--id", "Microsoft.OpenSSH.Preview", "-e"}}
	}
	return nil
}
