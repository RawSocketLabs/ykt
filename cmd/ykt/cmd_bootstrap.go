package main

// bootstrap: helpers to make a fresh box trust your CA without SSHing in first. Emits a cloud-init file (push at creation)
// or a one-liner install script (paste on a running box) that makes the box
// trust your user CA so your YubiKey-backed cert logs you in immediately — no
// per-box key distribution, no ssh-in-first. Only PUBLIC material is emitted,
// and identifying comments are stripped so nothing names you or your fleet.

import (
	"fmt"
	"os"
	"strings"
)

// stripCAComment returns just "<type> <base64>" from a CA pub line, dropping
// the trailing comment (e.g. "test-user-ca-a1") so the box learns no names.
func stripCAComment(caPub []byte) string {
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(caPub)), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 {
			out = append(out, f[0]+" "+f[1])
		}
	}
	return strings.Join(out, "\n")
}

// bootstrapMaterial returns the anonymized user-CA line(s) for a domain.
func bootstrapMaterial(domain string) string {
	caPub, err := os.ReadFile(trustedUserCAPath(domain))
	if err != nil {
		fatal("[%s] no trusted user CA — run init ca (and pull the repo) first: %v", domain, err)
	}
	ca := stripCAComment(caPub)
	if ca == "" {
		fatal("[%s] user CA file is empty", domain)
	}
	return ca
}

func bootstrapDropIn() string {
	// no domain/tool comment — nothing identifying lands on a throwaway box.
	return "TrustedUserCAKeys " + hostTrustCAFile + "\n"
}

func cmdBootstrapCloudInit(domain, user string) {
	reg := loadRegistry()
	reg.domain(domain)
	ca := bootstrapMaterial(domain)
	// cloud-init user-data: install the CA, drop-in, harden a touch, reload.
	fmt.Printf(`#cloud-config
# ykt test-box trust (public material only; connect with your cert).
write_files:
  - path: %s
    permissions: '0644'
    content: |
      %s
  - path: %s
    permissions: '0644'
    content: |
      %s
runcmd:
  - [ sh, -c, "sshd -t && (systemctl reload sshd || systemctl reload ssh)" ]
`, hostTrustCAFile, strings.ReplaceAll(ca, "\n", "\n      "),
		hostTrustDropIn, strings.TrimRight(bootstrapDropIn(), "\n"))

	bootstrapConnectHint(reg, domain, user)
}

func cmdBootstrapInstallScript(domain, user string) {
	reg := loadRegistry()
	reg.domain(domain)
	ca := bootstrapMaterial(domain)
	head("Paste this on the running box (as root/sudo) — public material only")
	fmt.Printf(`sudo tee %s > /dev/null <<'EOF'
%s
EOF
sudo tee %s > /dev/null <<'EOF'
%sEOF
sudo sh -c 'sshd -t && (systemctl reload sshd || systemctl reload ssh)'
`, hostTrustCAFile, ca, hostTrustDropIn, bootstrapDropIn())

	bootstrapConnectHint(reg, domain, user)
}

func bootstrapConnectHint(reg *Registry, domain, user string) {
	d := reg.domain(domain)
	principal := d.DefaultPrincipal
	fmt.Println()
	head("Then connect (first connect TOFU-pins the box's host key)")
	say("  ssh -o IdentitiesOnly=yes -i ~/.ssh/%s \\", dailyKeyName)
	say("      -o CertificateFile=~/.ssh/%s \\", installedSSHCertName(domain))
	say("      %s@<box-ip>", user)
	note("your cert authorizes login as principal %q — make sure the box has that", principal)
	note("user (root by default here), or pass --user <name> to match an existing one.")
	note("To pre-trust the box's host key (skip the TOFU prompt): ykt setup bootstrap trust <box-ip>")
	note("For a reusable short alias: ykt setup ssh add %s <name> --address <box-ip> --user %s", domain, user)
}

// cmdBootstrapTrust pins a test box's host key to known_hosts by connecting once and
// confirming the fingerprint — so later connections don't prompt. Reuses the
// same TOFU path as host-collect.
func cmdBootstrapTrust(dest string) {
	head("Pin host key for %s", dest)
	explain("Connects once, shows the host key fingerprint, and pins it to",
		"~/.ssh/known_hosts on your confirmation. No names are sent to the box.")
	if dryRun {
		note("dry-run: would connect and pin")
		return
	}
	c, err := sshConnectTOFU(dest)
	if err != nil {
		fatal("connecting to %s: %v", dest, err)
	}
	c.Close()
	good("host key for %s is pinned — future connections won't prompt", dest)
}
