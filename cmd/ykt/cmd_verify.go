package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-piv/piv-go/v2/piv"
	"golang.org/x/crypto/ssh"
)

// publishedCAKey loads the CA public key ykt actually trusts for (domain,role):
// the SSH authorized-key for the user/host CAs, and the X.509 client-CA cert for
// tls (mTLS). This is the material that grants access, so it's what the
// attestation must be bound to.
func publishedCAKey(dn, role, anchor string) (crypto.PublicKey, error) {
	if role == "tls" {
		cert, err := loadCertPEM(clientCACertPath(dn, anchor))
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	}
	f := caPubPath(dn, role, anchor)
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(f), err)
	}
	sshPub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", filepath.Base(f), err)
	}
	ck, ok := sshPub.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("SSH CA pub has no extractable key")
	}
	return ck.CryptoPublicKey(), nil
}

// caPubMatchesAttested reports whether the published, trusted CA key for
// (domain,role) is exactly the attested on-device key (attested = the slot
// attestation cert's subject key, proven on-device by piv.Verify). Without this
// bind, verify would pass even if a committed CA key were swapped for an
// off-device attacker key while the genuine attestation PEMs were left in place.
// Comparison is on PKIX DER, uniform across ed25519/ECDSA and both formats.
func caPubMatchesAttested(dn, role, anchor string, attested crypto.PublicKey) (bool, error) {
	published, err := publishedCAKey(dn, role, anchor)
	if err != nil {
		return false, err
	}
	pa, err := x509.MarshalPKIXPublicKey(attested)
	if err != nil {
		return false, fmt.Errorf("attested key: %w", err)
	}
	pp, err := x509.MarshalPKIXPublicKey(published)
	if err != nil {
		return false, fmt.Errorf("published key: %w", err)
	}
	return bytes.Equal(pa, pp), nil
}

// cmdVerifyAttestation proves — OFFLINE, from the published pub/ material alone —
// that each CA key was generated on the YubiKey and never imported, by verifying
// the stored PIV attestation chain against Yubico's attestation root. It also
// checks the attested serial against the registry, catching a swapped anchor.
func cmdVerifyAttestation(args []string) {
	reg := loadRegistry()
	anchors := args
	if len(anchors) == 0 {
		anchors = reg.anchorNames()
	}

	head("Verify PIV attestations (offline — against Yubico's root)")
	explain("Proves the CA key you TRUST for each domain/role was generated ON the",
		"YubiKey (never imported): chains the attestation to Yubico's root, binds it",
		"to the published CA key, and checks the serial. Public material only.")

	pass, fail, missing := 0, 0, 0
	for _, an := range anchors {
		a, ok := reg.Anchors[an]
		if !ok {
			fatal("unknown anchor %q", an)
		}
		inter, err := loadCertPEM(trustPath("pub", an+"_f9_intermediate.pem"))
		if err != nil {
			warn("[%s] no attestation intermediate (pub/%s_f9_intermediate.pem) — cannot verify", an, an)
			missing++
			continue
		}
		var registered uint32
		haveSerial := false
		if a.YubikeySerial != "unset" && a.YubikeySerial != "" {
			if n, err := parseUint32(a.YubikeySerial); err == nil {
				registered, haveSerial = n, true
			}
		}

		for _, dn := range reg.domainsOn(an) {
			d := reg.domain(dn)
			for _, rs := range domainRoleSlots(d) {
				slot, err := loadCertPEM(caAttestPath(an, dn, rs.role))
				if err != nil {
					continue // this role isn't provisioned on this anchor/domain
				}
				att, err := piv.Verify(inter, slot)
				if err != nil {
					warn("[%s/%s/%s] ATTESTATION FAILED: %v", an, dn, rs.role, err)
					fail++
					continue
				}
				// Bind: the attested on-device key MUST be the published CA key,
				// and the device serial MUST match the registry.
				match, berr := caPubMatchesAttested(dn, rs.role, an, slot.PublicKey)
				switch {
				case berr != nil:
					warn("[%s/%s/%s] cannot bind attestation to the published CA key: %v", an, dn, rs.role, berr)
					fail++
				case !match:
					warn("[%s/%s/%s] PUBLISHED CA KEY IS NOT THE ATTESTED ON-DEVICE KEY — possible substitution", an, dn, rs.role)
					fail++
				case haveSerial && att.Serial != registered:
					warn("[%s/%s/%s] attested serial %d ≠ registered %d", an, dn, rs.role, att.Serial, registered)
					fail++
				default:
					pass++
					say("  [%s/%s/%-4s] on-device + bound ✓  serial=%d  touch=%s pin=%s",
						an, dn, rs.role, att.Serial, touchName(att.TouchPolicy), pinName(att.PINPolicy))
				}
			}
		}
	}

	if fail > 0 {
		fatal("%d attestation(s) FAILED — a key may not be on-device, or its serial doesn't match the registry", fail)
	}
	if missing > 0 {
		warn("%d anchor(s) had no attestation material to check (run genesis, or pull the full store)", missing)
	}
	good("%d attestation(s) verified against Yubico's root", pass)
}

func touchName(p piv.TouchPolicy) string {
	switch p {
	case piv.TouchPolicyNever:
		return "never"
	case piv.TouchPolicyAlways:
		return "always"
	case piv.TouchPolicyCached:
		return "cached"
	default:
		return "?"
	}
}

func pinName(p piv.PINPolicy) string {
	switch p {
	case piv.PINPolicyNever:
		return "never"
	case piv.PINPolicyOnce:
		return "once"
	case piv.PINPolicyAlways:
		return "always"
	default:
		return "?"
	}
}
