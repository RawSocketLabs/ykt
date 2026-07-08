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

// sshdLogLevel is the LogLevel written into the drop-in. VERBOSE makes sshd log
// the certificate key ID (domain:person) + serial on every login, so
// `ykt remote logins` can attribute who logged in. Bound to the --log-level flag
// on `init host` / `remote install`; empty omits the directive (sshd default).
var sshdLogLevel = "VERBOSE"

var validSshdLogLevels = map[string]bool{
	"QUIET": true, "FATAL": true, "ERROR": true, "INFO": true, "VERBOSE": true,
	"DEBUG": true, "DEBUG1": true, "DEBUG2": true, "DEBUG3": true,
}

// validateSshdLogLevel normalizes and checks --log-level before it's written
// into a drop-in — a typo would otherwise produce a config that fails sshd -t.
// "" is allowed and omits the directive.
func validateSshdLogLevel() {
	if sshdLogLevel == "" {
		return
	}
	up := strings.ToUpper(sshdLogLevel)
	if !validSshdLogLevels[up] {
		fatal("--log-level %q is not a valid sshd LogLevel (QUIET/FATAL/ERROR/INFO/VERBOSE/DEBUG/DEBUG1-3, or \"\" to omit)", sshdLogLevel)
	}
	sshdLogLevel = up
}

// buildHostDropIn returns the canonical sshd drop-in. It deliberately omits an
// explicit HostKey directive: naming any HostKey disables the default
// RSA/ECDSA/ED25519 host keys, so the host would serve only ed25519 and break
// clients pinning another type. HostCertificate binds to the already-loaded
// ed25519 host key without needing the HostKey line.
func buildHostDropIn(domains []string, haveHostCert, haveKRL bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# managed by ykt — trusts domain(s): %s\n", strings.Join(domains, " "))
	fmt.Fprintf(&b, "TrustedUserCAKeys %s\n", hostTrustCAFile)
	if sshdLogLevel != "" {
		// logs "Accepted publickey ... ID <domain:person> (serial N) CA ..."
		fmt.Fprintf(&b, "LogLevel %s\n", sshdLogLevel)
	}
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

// domainKRLGroups builds KRL groups (each anchor CA pub → its revoked SSH
// serials) from a domain's ledger. SSH-only; tls serials aren't in the KRL.
func domainKRLGroups(domain string) []krlCAGroup {
	revoked := map[string][]uint64{} // anchor -> serials
	for _, e := range loadLedger(domain) {
		if e.Revoked && e.Serial != 0 && e.Type != "tls" {
			revoked[e.Anchor] = append(revoked[e.Anchor], e.Serial)
		}
	}
	var groups []krlCAGroup
	for anchor, sers := range revoked {
		for _, role := range []string{"user", "host"} {
			caPub, err := os.ReadFile(caPubPath(domain, role, anchor))
			if err != nil {
				continue
			}
			groups = append(groups, krlCAGroup{caPub: caPub, serials: sers})
		}
	}
	return groups
}

// hostKRLBytes returns the KRL to push to a host trusting the given domains: the
// published per-domain KRL file for a single domain, or a freshly merged KRL
// (built from every trusted domain's ledger) for a multi-domain host — so
// revocations reach multi-domain hosts too. nil if nothing is revoked.
func hostKRLBytes(domains []string) []byte {
	if len(domains) == 1 {
		return singleKRL(domains)
	}
	var groups []krlCAGroup
	for _, dn := range domains {
		groups = append(groups, domainKRLGroups(dn)...)
	}
	if len(groups) == 0 {
		return nil
	}
	b, err := buildKRL(groups, uint64(nowUnix()), "ykt merged KRL "+today())
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
