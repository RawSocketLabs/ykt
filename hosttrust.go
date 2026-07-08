package main

// Canonical on-host trust layout, shared by both provisioning paths
// (host-install remote push, host-setup local). Because both paths write the
// SAME files, they can never shadow each other via sshd's first-match-wins
// include ordering — the previous 20-<domain>-ca.conf vs 20-ykt.conf split
// was a silent-lockout bug.

import (
	"fmt"
	"os"
	"strings"
)

const (
	hostTrustCAFile   = "/etc/ssh/ykt_user_ca.pub"
	hostTrustKRLFile  = "/etc/ssh/ykt.krl"
	hostTrustDropIn   = "/etc/ssh/sshd_config.d/20-ykt.conf"
	hostTrustNoPass   = "/etc/ssh/sshd_config.d/30-ykt-nopassword.conf"
	hostCertFile      = "/etc/ssh/ssh_host_ed25519_key-cert.pub"
	hostCertKeyFile   = "/etc/ssh/ssh_host_ed25519_key"
	sshdReloadCommand = "sudo sshd -t && (sudo systemctl reload sshd || sudo systemctl reload ssh)"
)

// buildHostDropIn returns the canonical sshd drop-in. It deliberately omits an
// explicit HostKey directive: naming any HostKey disables the default
// RSA/ECDSA/ED25519 host keys, so the host would serve only ed25519 and break
// clients pinning another type. HostCertificate binds to the already-loaded
// ed25519 host key without needing the HostKey line.
func buildHostDropIn(domains []string, haveHostCert, haveKRL bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# managed by ykt — trusts domain(s): %s\n", strings.Join(domains, " "))
	fmt.Fprintf(&b, "TrustedUserCAKeys %s\n", hostTrustCAFile)
	if haveHostCert {
		fmt.Fprintf(&b, "HostCertificate %s\n", hostCertFile)
	}
	if haveKRL {
		fmt.Fprintf(&b, "RevokedKeys %s\n", hostTrustKRLFile)
	}
	// Note: break-glass is installed into a recovery account's authorized_keys,
	// NOT via a global AuthorizedKeysFile here — so this drop-in is identical
	// whether or not break-glass is in use, and `remote install` can never strip
	// the emergency key.
	return b.String()
}

// gatherHostCA concatenates the trusted-user-CA file(s) for the given domains.
func gatherHostCA(domains []string) ([]byte, error) {
	var data []byte
	for _, dn := range domains {
		b, err := os.ReadFile(trustedUserCAPath(dn))
		if err != nil {
			return nil, fmt.Errorf("[%s] missing trust file — run init ca (and pull the repo) first: %w", dn, err)
		}
		data = append(data, b...)
	}
	return data, nil
}

// singleKRL returns the KRL bytes for a single-domain host, or nil. Multi-
// domain hosts get no KRL (one RevokedKeys file can't cleanly represent
// several domains' KRLs); callers warn in that case.
func singleKRL(domains []string) []byte {
	if len(domains) != 1 {
		return nil
	}
	b, err := os.ReadFile(krlPath(domains[0]))
	if err != nil {
		return nil
	}
	return b
}

// warnIfMultiDomain enforces the one-domain-per-host default: multiple domains
// require an explicit opt-in and share the login principal, so a weaker
// domain's cert can authenticate on a stronger domain's host.
func warnIfMultiDomain(domains []string, multi bool) {
	if len(domains) <= 1 {
		return
	}
	if !multi {
		fatal("refusing to trust multiple domains on one host without --multi:\n"+
			"  domains %v share the login principal, so any of these domains' user\n"+
			"  certs could log in here. Re-run with --multi if that is intended.", domains)
	}
	warn("MULTI-DOMAIN host: %v share the login principal — a cert from ANY of these", domains)
	warn("domains can authenticate here. Keep this to hosts that genuinely belong to")
	warn("all listed domains.")
}
