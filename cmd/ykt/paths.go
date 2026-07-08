package main

// Centralized filename contracts. Every producer and consumer of a queue /
// dist / pub / index path goes through these helpers so the format cannot
// drift between the site that writes a file and the site that reads it.

import (
	"fmt"
	"os"
)

const (
	// dailyKeyName is the single FIDO2-backed SSH key that serves every domain
	// (the certificate, not the key, is what distinguishes domains). Generic so
	// a fork isn't tied to any one domain name.
	dailyKeyName = "id_yk"
	// fidoApplication is the FIDO2 application string baked into the daily key.
	fidoApplication = "ssh:yk"
	// sshKeyStashSlot is the daily-key PIV slot that carries the id_yk key stub
	// (route 2). One slot, shared across domains — the stub is the same for all.
	sshKeyStashSlot = "95"
)

// hostnameOrDie returns this machine's hostname, failing loudly rather than
// silently using "" (which would corrupt cert-file identity).
func hostnameOrDie() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		fatal("cannot determine hostname: %v", err)
	}
	return h
}

// homeDir returns the user's home directory, failing loudly rather than
// silently targeting "/" (which an unset HOME would do via os.Getenv).
func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		fatal("cannot determine home directory (is $HOME set?): %v", err)
	}
	return h
}

// ---- pub/ (published CA material) ------------------------------------------

func caPubPath(domain, role, anchor string) string {
	return trustPath("pub", fmt.Sprintf("%s_%s_ca_%s.pub", domain, role, anchor))
}
func caPubPEMPath(anchor, domain, role string) string {
	return trustPath("pub", fmt.Sprintf("%s_%s_%s_pub.pem", anchor, domain, role))
}
func caAttestPath(anchor, domain, role string) string {
	return trustPath("pub", fmt.Sprintf("%s_%s_%s_attest.pem", anchor, domain, role))
}
func clientCACertPath(domain, anchor string) string {
	return trustPath("pub", fmt.Sprintf("%s_client_ca_%s.crt", domain, anchor))
}
func trustedUserCAPath(domain string) string {
	return trustPath("pub", domain+"_trusted_user_ca.pub")
}
func certAuthorityKnownHostsPath(domain string) string {
	return trustPath("pub", domain+"_cert_authority.known_hosts")
}
func krlPath(domain string) string { return trustPath("pub", domain+".krl") }

// ---- queue/ (pending signing requests) -------------------------------------

func queueUserKeyName(person, host string) string {
	return fmt.Sprintf("user_%s_%s.pub", person, host)
}
func queueHostKeyName(host string) string { return "host_" + host + ".pub" }
func queueTLSName(person, host string) string {
	return fmt.Sprintf("tls_%s_%s.csr", person, host)
}

// ---- dist/ (signed certificates) -------------------------------------------

func distUserCertName(person, host string) string {
	return fmt.Sprintf("user_%s_%s-cert.pub", person, host)
}
func distHostCertName(host string) string { return "host_" + host + "-cert.pub" }
func distTLSName(person, host string) string {
	return fmt.Sprintf("tls_%s_%s.crt", person, host)
}

// installedSSHCertName is where a domain's user cert lands in ~/.ssh.
// each domain's cert; needs an explicit CertificateFile (no auto-pair with the daily key).
func installedSSHCertName(domain string) string { return "id_" + domain + "-cert.pub" }
