package main

// Native SSH certificate operations via x/crypto/ssh — signing, validity
// parsing, trust-file assembly. No ssh-keygen involved.

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// parseValidity turns "+13w" / "+54w" / "+90d" into a time span.
func parseValidity(v string) (time.Duration, error) {
	s := strings.TrimPrefix(v, "+")
	if len(s) < 2 {
		return 0, fmt.Errorf("bad validity %q", v)
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("bad validity %q (want a positive count + h/d/w, e.g. +13w)", v)
	}
	switch s[len(s)-1] {
	case 'w':
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	}
	return 0, fmt.Errorf("bad validity unit in %q (use h/d/w)", v)
}

// defaultUserExtensions mirrors what ssh-keygen grants user certs by default.
func defaultUserExtensions() map[string]string {
	return map[string]string{
		"permit-X11-forwarding":   "",
		"permit-agent-forwarding": "",
		"permit-port-forwarding":  "",
		"permit-pty":              "",
		"permit-user-rc":          "",
	}
}

type certSpec struct {
	certType   uint32 // ssh.UserCert or ssh.HostCert
	keyID      string
	principals []string
	serial     uint64
	validity   string
}

// signSSHCert signs pubBytes (an authorized_keys-format public key) with the
// CA signer and returns the certificate in authorized_keys format.
func signSSHCert(caSigner crypto.Signer, spec certSpec, pubBytes []byte) ([]byte, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	span, err := parseValidity(spec.validity)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          spec.serial,
		CertType:        spec.certType,
		KeyId:           spec.keyID,
		ValidPrincipals: spec.principals,
		ValidAfter:      uint64(now.Add(-5 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(span).Unix()),
	}
	if spec.certType == ssh.UserCert {
		cert.Permissions = ssh.Permissions{Extensions: defaultUserExtensions()}
	}
	sshCASigner, err := ssh.NewSignerFromSigner(caSigner)
	if err != nil {
		return nil, fmt.Errorf("wrapping CA signer: %w", err)
	}
	if err := cert.SignCert(rand.Reader, sshCASigner); err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	out := ssh.MarshalAuthorizedKey(cert)
	// append key id as the comment, like ssh-keygen does
	out = append(out[:len(out)-1], []byte(" "+spec.keyID+"\n")...)
	return out, nil
}

// sshPubFromCryptoPub converts a slot public key into authorized_keys format.
func sshPubFromCryptoPub(pub crypto.PublicKey, comment string) ([]byte, error) {
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, err
	}
	line := ssh.MarshalAuthorizedKey(sshPub)
	return append(line[:len(line)-1], []byte(" "+comment+"\n")...), nil
}

// validSSHPublicKey reports whether b parses as an authorized_keys line.
func validSSHPublicKey(b []byte) error {
	_, _, _, _, err := ssh.ParseAuthorizedKey(b)
	return err
}

func sshFingerprint(pubBytes []byte) string {
	pub, comment, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		return "(unparseable key)"
	}
	h := sha256.Sum256(pub.Marshal())
	fp := "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(h[:]), "=")
	return fmt.Sprintf("%s %s (%s)", fp, comment, pub.Type())
}

// assembleTrustFiles rebuilds <domain>_trusted_user_ca.pub and
// <domain>_cert_authority.known_hosts from every anchor's exported CA keys.
//
// The @cert-authority host pattern covers both the FQDN wildcard "*.<zone>"
// and the apex "<zone>" (the wildcard matches exactly one label, so the apex
// would otherwise be missed). Connecting by bare short name or IP will NOT
// match these patterns even though host certs list those principals — a
// header comment tells users to connect by FQDN or add their own pattern.
func assembleTrustFiles(reg *Registry, domain string) error {
	d := reg.domain(domain)
	pattern := fmt.Sprintf("*.%s,%s", d.BaseZone(), d.BaseZone())
	var userLines []string
	hostLines := []string{
		"# ykt " + domain + " host CA trust. Connect by FQDN (e.g. host." + d.BaseZone() + ");",
		"# bare short names or IPs won't match these patterns — add your own",
		"# @cert-authority line for those, or use the FQDN.",
	}
	// Iterate the domain's CONFIGURED anchors. For each anchor that is
	// provisioned (has a serial bound), its CA pub MUST be present — otherwise
	// a stale/partial checkout would silently shrink the trust file and lock
	// out that anchor's certs fleet-wide. Anchors not yet provisioned (serial
	// "unset") are legitimately absent and skipped.
	for _, anchor := range d.AnchorList() {
		provisioned := reg.Anchors[anchor].YubikeySerial != "" && reg.Anchors[anchor].YubikeySerial != "unset"
		u, uerr := os.ReadFile(caPubPath(domain, "user", anchor))
		if uerr != nil {
			if provisioned {
				return fmt.Errorf("anchor %q is provisioned but its %s user CA (%s) is missing — pull the full repo before assembling trust files (refusing to silently drop it)", anchor, domain, caPubPath(domain, "user", anchor))
			}
			continue // anchor not yet provisioned — legitimately absent
		}
		userLines = append(userLines, strings.TrimRight(string(u), "\n"))
		// Same guard as the user CA: a provisioned anchor missing its host CA must
		// not silently drop that anchor's @cert-authority line (which would stop
		// clients trusting its host certs). Absent + unprovisioned is legitimate.
		h, herr := os.ReadFile(caPubPath(domain, "host", anchor))
		if herr != nil {
			if provisioned {
				return fmt.Errorf("anchor %q is provisioned but its %s host CA (%s) is missing — pull the full repo before assembling trust files (refusing to silently drop host trust)", anchor, domain, caPubPath(domain, "host", anchor))
			}
			continue // not provisioned — legitimately absent
		}
		if fields := strings.Fields(string(h)); len(fields) >= 2 {
			hostLines = append(hostLines,
				fmt.Sprintf("@cert-authority %s %s %s", pattern, fields[0], fields[1]))
		}
	}
	if len(userLines) == 0 {
		return fmt.Errorf("no user CA keys found for %s — run init ca first", domain)
	}
	if err := writeFileAtomic(trustedUserCAPath(domain),
		[]byte(strings.Join(userLines, "\n")+"\n"), 0o644); err != nil {
		return err
	}
	return writeFileAtomic(certAuthorityKnownHostsPath(domain),
		[]byte(strings.Join(hostLines, "\n")+"\n"), 0o644)
}
