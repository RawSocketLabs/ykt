package main

import (
	"fmt"

	"github.com/go-piv/piv-go/v2/piv"
)

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
	explain("Proves each CA key was generated ON the YubiKey (never imported),",
		"using only published pub/ material — no hardware or network needed.")

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
				serialNote := ""
				if haveSerial && att.Serial != registered {
					serialNote = fmt.Sprintf("  ✘ serial %d ≠ registered %d", att.Serial, registered)
					fail++
				} else {
					pass++
				}
				say("  [%s/%s/%-4s] on-device ✓  serial=%d  touch=%s pin=%s%s",
					an, dn, rs.role, att.Serial, touchName(att.TouchPolicy), pinName(att.PINPolicy), serialNote)
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
