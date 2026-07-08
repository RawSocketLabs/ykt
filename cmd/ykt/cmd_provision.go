package main

// The guided YubiKey operations: CA genesis (init ca), user-key enrollment
// (init user), and signing (cert sign). Interaction model: PREFLIGHT the
// hardware → gather ALL inputs → show one PLAN and confirm once → execute
// everything, pausing only for touches (which auto-continue when the tap lands).
//
// All key material operations are native (go-piv + x/crypto/ssh + crypto/x509).
// The single exception is FIDO2 sk-key generation, where the operator runs a
// printed ssh-keygen command (OpenSSH generates a file only OpenSSH consumes).

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

type roleSlot struct{ role, slot string }

func domainRoleSlots(d Domain) []roleSlot {
	return []roleSlot{{"user", d.UserSlot}, {"host", d.HostSlot}, {"tls", d.TLSSlot}}
}

// ---------------------------------------------------------------- init ca

func cmdInitCA(args []string) {
	reg := loadRegistry()
	anchorName := args[0]
	anchor := reg.anchor(anchorName)
	allDomains := reg.domainsOn(anchorName)
	if len(allDomains) == 0 {
		fatal("no domains list anchor %q in config.toml", anchorName)
	}

	// ---- preflight -------------------------------------------------------
	checkDailyKeySlots(reg) // same slot-map sanity as doctor, before any reset
	yk, serial := pickYubiKey(anchor.YubikeySerial)
	if yk != nil {
		defer yk.Close()
		v := yk.Version()
		good("preflight: firmware %d.%d.%d", v.Major, v.Minor, v.Patch)
	}

	// Decide genesis vs additive by inspecting existing published CA material
	// AND on-device slot occupancy. A domain is "present" if its user CA pub
	// file exists; additive mode generates only the missing domains and never
	// factory-resets (which would destroy the existing CA keys).
	var missing, present []string
	for _, dn := range allDomains {
		if _, err := os.Stat(caPubPath(dn, "user", anchorName)); err == nil {
			present = append(present, dn)
		} else {
			missing = append(missing, dn)
		}
	}
	genesis := len(present) == 0
	domains := missing // domains we will actually generate this run
	if len(missing) == 0 {
		good("anchor %q already provisions all its domains (%s) — nothing to do.", anchorName, strings.Join(present, " "))
		return
	}

	if genesis {
		head("GENESIS — provision anchor %q (%s @ %s)", anchorName, anchor.Holder, anchor.Location)
		explain(
			"Provisions CA keys ON-DEVICE for every domain this anchor holds.",
			"Private keys are generated inside the YubiKey and can never leave it.")
	} else {
		head("Additive provisioning for anchor %q (%s @ %s)", anchorName, anchor.Holder, anchor.Location)
		explain(
			"This anchor already provisions: "+strings.Join(present, " "),
			"Generating ONLY the new domain(s) below. No factory reset — existing",
			"CA keys are untouched.")
	}
	say("Domains to generate now: %s", colorize(cBold, strings.Join(domains, " ")))

	// ---- gather all inputs (once) -----------------------------------------
	var pin, newPUK string
	if !dryRun {
		if genesis {
			explain("The PIV applet will be FACTORY-RESET first, so no current PIN/PUK is",
				"needed. A mistyped value here is recoverable by re-running genesis.")
			pin = promptSecret("  NEW PIN (6-8 digits): ")
			newPUK = promptSecret("  NEW PUK (8 digits): ")
		} else {
			pin = promptSecret("  CURRENT PIV PIN of this anchor: ")
			verifyPINOnce(yk, pin)
		}
	}

	// ---- plan -------------------------------------------------------------
	var planLines []string
	if genesis {
		planLines = append(planLines,
			"FACTORY-RESET the PIV applet (wipes ALL existing PIV keys/certs on this YubiKey)",
			"set your new PIN + PUK; generate & store a PIN-protected management key")
	}
	for _, dn := range domains {
		d := reg.domain(dn)
		planLines = append(planLines,
			fmt.Sprintf("[%s] generate 3 CA keys on-device (slots %s/%s/%s) + attestations", dn, d.UserSlot, d.HostSlot, d.TLSSlot),
			fmt.Sprintf("[%s] sign + store slot certificates (touches needed here)", dn))
	}
	planLines = append(planLines,
		"rebuild per-domain trust files (trusted_user_ca.pub, @cert-authority lines)",
		fmt.Sprintf("bind anchor %q to serial %d in config.toml", anchorName, serial),
		fmt.Sprintf("write %s.json (serial, timestamp, per-domain fingerprints — no secrets)", anchorName),
		"print the paper-record fingerprint checklist")
	confirmPlan(planLines)

	// ---- execute -----------------------------------------------------------
	if err := ensureDir(trustPath("pub")); err != nil {
		fatal("%v", err)
	}
	var mk []byte
	if !dryRun {
		if genesis {
			act("factory-reset the PIV applet and set PIN + PUK + management key",
				"Idempotent: safe to retry — each attempt resets to defaults first.",
				func() error { return resetAndProvisionPIV(yk, pin, newPUK, &mk) })
		} else {
			mk = mgmtKey(yk, pin)
		}
	}

	act("export the attestation intermediate (slot f9)",
		"Anyone verifying our CA keys' hardware residency needs this.",
		func() error {
			cert, err := yk.AttestationCertificate()
			if err != nil {
				return err
			}
			return writeCertPEM(trustPath("pub", anchorName+"_f9_intermediate.pem"), cert)
		})

	for _, dn := range domains {
		d := reg.domain(dn)
		for _, rs := range domainRoleSlots(d) {
			dn, role, slotName := dn, rs.role, rs.slot
			var pub crypto.PublicKey
			act(fmt.Sprintf("[%s] generate %s CA key in %s + attestation", dn, role, slotHint(slotName)), "",
				func() error {
					var err error
					pub, err = generateOnDevice(yk, mk, slotName)
					if err != nil {
						return err
					}
					if err := writePubPEM(caPubPEMPath(anchorName, dn, role), pub); err != nil {
						return err
					}
					cert, err := attest(yk, slotName)
					if err != nil {
						return err
					}
					return writeCertPEM(caAttestPath(anchorName, dn, role), cert)
				})

			if role == "tls" {
				actTouch(fmt.Sprintf("[%s] issue + store the client-CA certificate (CA:TRUE) in slot %s", dn, slotName), "",
					func() error {
						signer, err := pivSigner(yk, slotName, pub, pin)
						if err != nil {
							return err
						}
						cert, err := makeClientCACert(signer, fmt.Sprintf("ykt %s client CA %s", dn, anchorName))
						if err != nil {
							return err
						}
						if err := setSlotCertificate(yk, mk, slotName, cert); err != nil {
							return err
						}
						return writeCertPEM(clientCACertPath(dn, anchorName), cert)
					})
			} else {
				actTouch(fmt.Sprintf("[%s] export OpenSSH %s CA public key + store marker certificate", dn, role), "",
					func() error {
						line, err := sshPubFromCryptoPub(pub, fmt.Sprintf("%s-%s-ca-%s", dn, role, anchorName))
						if err != nil {
							return err
						}
						if err := writeFileAtomic(caPubPath(dn, role, anchorName), line, 0o644); err != nil {
							return err
						}
						signer, err := pivSigner(yk, slotName, pub, pin)
						if err != nil {
							return err
						}
						cert, err := makeClientCACert(signer, fmt.Sprintf("ykt %s %s CA %s", dn, role, anchorName))
						if err != nil {
							return err
						}
						return setSlotCertificate(yk, mk, slotName, cert)
					})
			}
		}
	}

	for _, dn := range domains {
		dn := dn
		act(fmt.Sprintf("[%s] rebuild trust files", dn), "", func() error { return assembleTrustFiles(reg, dn) })
	}
	act(fmt.Sprintf("bind anchor %q to serial %d in config.toml", anchorName, serial), "",
		func() error { return reg.setAnchorSerial(anchorName, strconv.FormatUint(uint64(serial), 10)) })

	// ---- anchor record (<anchor>.json — public material, no secrets) ------
	// Cover ALL domains this anchor provisions (present + newly generated), so
	// the record is complete after additive runs too. Skip entirely under
	// dry-run: the pub/ files were never written, so buildAnchorRecord would
	// read missing files and print spurious "CA pub missing" warnings.
	if dryRun {
		note("dry-run: skipping anchor record + fingerprint checklist")
		return
	}
	record := buildAnchorRecord(reg, anchorName, serial)
	act(fmt.Sprintf("write %s.json (anchor record — safe to commit)", anchorName), "",
		func() error { return record.write(trustPath(anchorName + ".json")) })

	if genesis {
		head("Genesis complete — paper record checklist")
		say("Write on paper (NOT in git, NOT in %s.json): PIN, PUK, date.", anchorName)
	} else {
		head("Additive provisioning complete — new fingerprints")
	}
	say("Fingerprints below are also in %s.json; both operators verify out-of-band:", anchorName)
	for _, dn := range allDomains {
		for _, role := range []string{"user", "host", "tls"} {
			if fp, ok := record.Domains[dn][role]; ok {
				say("  %-5s %-5s %s", dn, role, fp)
			}
		}
	}
	say("\nThen: commit pub/ + config.toml + %s.json to git, unplug the anchor, put it away.", anchorName)
}

func randomManagementKey() []byte {
	b := make([]byte, 24)
	mustRandRead(b)
	return b
}

// ---------------------------------------------------------------- user-enroll

func cmdInitUser(args []string, keep, verifyRequired bool) {
	reg := loadRegistry()
	person := args[0]
	domains := args[1:]
	for _, d := range domains {
		reg.domain(d)
	}

	head("P2 · Enroll %q on this machine's daily YubiKey", person)
	explain(
		"Run this ON YOUR OWN machine with YOUR daily YubiKey inserted.",
		"Default is a FULL provision: FIDO + PIV factory resets, then fresh keys.",
		"It queues signing REQUESTS; an anchor holder signs them with 'cert sign'.")

	hostname := shortHost(hostnameOrDie())
	keyFile := filepath.Join(homeDir(), ".ssh", dailyKeyName)
	_, statErr := os.Stat(keyFile + ".pub")
	needSSHKey := statErr != nil || !keep // resets invalidate any existing sk handle

	// ---- preflight ---------------------------------------------------------
	requireCleanDailyKeySlots(reg) // this flow provisions a client_slot — a collision would clobber
	yk, serial := pickYubiKey("")  // the daily key — no registry expectation
	if yk != nil {
		defer func() {
			if yk != nil {
				yk.Close()
			}
		}()
		v := yk.Version()
		good("preflight: firmware %d.%d.%d", v.Major, v.Minor, v.Patch)
	}
	// Refuse to enroll (which factory-resets) an anchor YubiKey — that would
	// destroy the domain CA keys.
	if !keep {
		for _, an := range reg.anchorNames() {
			if s := reg.Anchors[an].YubikeySerial; s != "unset" && s != "" {
				if n, err := parseUint32(s); err == nil && n == serial {
					fatal("YubiKey serial %d is anchor %q — 'init user' factory-resets and would DESTROY its CA keys. Insert a daily key instead.", serial, an)
				}
			}
		}
	}
	caps := capsFor(yk)
	modernFW := caps.ResidentSSH // FIDO2 PIN + resident keys available
	if caps.Known {
		good("capabilities: %s", caps.summary())
	} else {
		note("dry-run: assuming modern-key capabilities (%s)", caps.summary())
	}

	// ---- gather all inputs (once) ------------------------------------------
	var pin, puk string
	if !dryRun {
		if keep {
			pin = promptSecret("  CURRENT PIV PIN of this key: ")
			verifyPINOnce(yk, pin)
		} else {
			explain("One PIN is set on BOTH applets (PIV now; FIDO2 via its own two prompts",
				"later, newer firmware only). A typo is recoverable: just re-run.")
			pin = promptSecret("  NEW PIN (6-8 digits): ")
			puk = promptSecret("  NEW PUK (8 digits): ")
		}
	}

	sshArgv := caps.sshKeygenArgs(keyFile, verifyRequired)
	if !caps.ResidentSSH {
		note("this key's firmware (%d.%d.%d) predates resident Ed25519 sk keys — using %s",
			caps.Version[0], caps.Version[1], caps.Version[2], caps.SSHKeyType)
		note("the sk handle file %s is then the ONLY copy; losing it means re-enrolling.", keyFile)
	}
	if verifyRequired && !caps.VerifyCapable {
		warn("--verify-required requested but this key can't do it — proceeding without")
	}

	// ---- plan --------------------------------------------------------------
	planLines := []string{}
	if !keep {
		planLines = append(planLines,
			"FACTORY-RESET the FIDO2 applet — WIPES ALL passkeys/credentials on this key (ykman, replug + touch)",
			"FACTORY-RESET the PIV applet — wipes all PIV keys/certs",
			"set the new PIN (+PUK, management key)")
		if modernFW {
			planLines = append(planLines, "set the FIDO2 PIN (ykman prompts twice)")
		}
		planLines = append(planLines, "delete stale "+keyFile+"* files (dead after FIDO reset)")
	}
	if needSSHKey {
		planLines = append(planLines, "run inline: "+shellJoin(sshArgv))
	} else {
		planLines = append(planLines, "reuse existing "+keyFile)
	}
	for _, dn := range domains {
		planLines = append(planLines, fmt.Sprintf("[%s] queue SSH user-cert request", dn))
	}
	for _, dn := range domains {
		planLines = append(planLines,
			fmt.Sprintf("[%s] generate mTLS client key in slot %s + CSR into the queue (touch)", dn, reg.domain(dn).ClientSlot))
	}
	planLines = append(planLines, "append @cert-authority lines to ~/.ssh/known_hosts")
	confirmPlan(planLines)

	// ---- execute -----------------------------------------------------------
	var mk []byte // PIN-protected management key (set by resetAndProvisionPIV)
	serialArg := strconv.FormatUint(uint64(serial), 10)
	if !keep && !dryRun {
		yk.Close() // release before the replug dance
		yk = nil
		say("")
		warn("FIDO2 factory reset: destroys every FIDO credential on this key,")
		warn("including website passkeys. The key requires a fresh insertion for it.")
		waitForReplug(serial)
		actCommand("factory-reset the FIDO2 applet",
			[]string{"ykman", "--device", serialArg, "fido", "reset", "--force"},
			"Fired inside the post-insertion window — touch the key when asked.")
		yk = openBySerial(serial)
		act("factory-reset the PIV applet and set PIN + PUK + management key",
			"Idempotent: safe to retry — each attempt resets to defaults first.",
			func() error { return resetAndProvisionPIV(yk, pin, puk, &mk) })
		if modernFW {
			actCommand("set the FIDO2 PIN (needed for resident ssh keys)",
				[]string{"ykman", "--device", serialArg, "fido", "access", "change-pin"},
				"ykman prompts for the new PIN twice — use the same PIN you chose above.")
		}
		act("delete stale sk key + cert files", "The old handle died with the FIDO reset.", func() error {
			stale := []string{keyFile, keyFile + ".pub", keyFile + "-cert.pub"}
			for _, dn := range domains {
				stale = append(stale, filepath.Join(filepath.Dir(keyFile), installedSSHCertName(dn)))
			}
			for _, f := range stale {
				if err := removeIfPresent(f); err != nil {
					return err
				}
			}
			return nil
		})
	}
	if mk == nil { // --keep, or dry-run: use the stored management key
		if !dryRun {
			mk = mgmtKey(yk, pin)
		}
	}
	if needSSHKey {
		actCommand("generate the FIDO2 SSH key", sshArgv,
			"Runs right here. Touch when it blinks; FIDO2 PIN asked on newer firmware.")
	}
	for _, dn := range domains {
		dn := dn
		act(fmt.Sprintf("[%s] queue the SSH user-cert request", dn), "", func() error {
			pub, err := os.ReadFile(keyFile + ".pub")
			if err != nil {
				return err
			}
			return writeFileAtomic(trustPath("queue", dn, queueUserKeyName(person, hostname)), pub, 0o644)
		})
	}
	for _, dn := range domains {
		dn := dn
		slot := reg.domain(dn).ClientSlot
		var pub crypto.PublicKey
		// Under --keep we REUSE the existing slot key (regenerating it would
		// orphan the installed mTLS cert). Only generate on a fresh enroll.
		if !keep {
			act(fmt.Sprintf("[%s] generate the mTLS client key on-device in slot %s", dn, slot), "", func() error {
				var err error
				pub, err = generateOnDevice(yk, mk, slot)
				return err
			})
		}
		actTouch(fmt.Sprintf("[%s] create a CSR into the queue", dn), "", func() error {
			if pub == nil { // --keep or generate skipped — recover from the slot
				cert, err := attest(yk, slot)
				if err != nil {
					return fmt.Errorf("slot %s public key unavailable (no key in slot? run without --keep): %w", slot, err)
				}
				pub = cert.PublicKey
			}
			signer, err := pivSigner(yk, slot, pub, pin)
			if err != nil {
				return err
			}
			csr, err := makeCSR(signer, fmt.Sprintf("%s@%s", person, dn))
			if err != nil {
				return err
			}
			return writeFileAtomic(trustPath("queue", dn, queueTLSName(person, hostname)), csr, 0o644)
		})
	}
	for _, dn := range domains {
		dn := dn
		caf := certAuthorityKnownHostsPath(dn)
		lines, err := os.ReadFile(caf)
		if err != nil {
			warn("[%s] %s not found — pull latest infrax (anchor genesis publishes it)", dn, caf)
			continue
		}
		act(fmt.Sprintf("[%s] trust host CA in ~/.ssh/known_hosts", dn), "", func() error {
			if dryRun {
				return nil
			}
			khPath := filepath.Join(homeDir(), ".ssh", "known_hosts")
			// dedup: skip @cert-authority lines already present (re-enroll must
			// not accumulate duplicates).
			existing, _ := os.ReadFile(khPath)
			var toAdd []string
			for _, l := range strings.Split(strings.TrimRight(string(lines), "\n"), "\n") {
				if l == "" || strings.HasPrefix(l, "#") {
					continue
				}
				if !strings.Contains(string(existing), l) {
					toAdd = append(toAdd, l)
				}
			}
			if len(toAdd) == 0 {
				return nil
			}
			kh, err := os.OpenFile(khPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			defer kh.Close()
			_, err = kh.WriteString(strings.Join(toAdd, "\n") + "\n")
			return err
		})
	}

	head("Enrollment queued")
	if !keep {
		warn("The FIDO reset invalidated any pam_u2f login/sudo registrations this key")
		warn("had. If it was registered (e.g. /etc/Yubico/u2f_keys), re-register now:")
		warn("  pamu2fcfg | sudo tee /etc/Yubico/u2f_keys   (append with -n for extra keys)")
	}
	say("Next: commit + push queue/ (public material), then an anchor holder runs:")
	say("  ykt cert sign <anchor>")
	if pub, err := os.ReadFile(keyFile + ".pub"); err == nil {
		say("Verify this fingerprint with them OUT-OF-BAND (call / verified chat):")
		say("  %s", sshFingerprint(pub))
	}
}

// ---------------------------------------------------------------- cert sign

type signJob struct {
	domain     string
	d          Domain
	kind       string // user | host | tls
	id         string
	qfile      string
	payload    []byte // bytes read + verified at gather time (signed as-is)
	principals string
	validity   string
}

// cleanPrincipals trims whitespace and drops empties from a comma list, so
// "a, b" and a stray empty default never produce unusable principals.
func cleanPrincipals(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func cmdSign(args []string) {
	if len(args) != 1 {
		fatal("usage: ykt cert sign <a1|a2>")
	}
	reg := loadRegistry()
	inv := loadInventory()
	anchorName := args[0]
	anchor := reg.anchor(anchorName)

	head("Signing with anchor %q", anchorName)

	// ---- gather every queued request + per-item decisions up front --------
	var jobs []signJob
	for _, domainName := range reg.domainsOn(anchorName) {
		d := reg.domain(domainName)
		qdir := trustPath("queue", domainName)
		entries, err := os.ReadDir(qdir)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			name := ent.Name()
			if ent.IsDir() {
				continue
			}
			qfile := filepath.Join(qdir, name)
			payload, rerr := os.ReadFile(qfile)
			if rerr != nil {
				continue
			}
			switch {
			case strings.HasPrefix(name, "user_") && strings.HasSuffix(name, ".pub"):
				id := strings.TrimSuffix(strings.TrimPrefix(name, "user_"), ".pub")
				say("\n[%s] user request %s", domainName, id)
				say("  %s", sshFingerprint(payload))
				if !dryRun && !confirm("  Fingerprint verified out-of-band (or local request)?") {
					warn("skipping %s", id)
					continue
				}
				principals := d.DefaultPrincipal
				if !dryRun {
					principals = promptDefault("principals", d.DefaultPrincipal)
				}
				jobs = append(jobs, signJob{domainName, d, "user", id, qfile, payload, principals, d.UserValidity})
			case strings.HasPrefix(name, "host_") && strings.HasSuffix(name, ".pub"):
				id := strings.TrimSuffix(strings.TrimPrefix(name, "host_"), ".pub")
				def := strings.Join(Machine{}.principals(id, d), ",")
				if m, ok := inv.Machines[id]; ok {
					def = strings.Join(m.principals(id, d), ",")
				}
				say("\n[%s] host request %s", domainName, id)
				principals := def
				if !dryRun {
					principals = promptDefault("principals (hostnames/IPs)", def)
				}
				jobs = append(jobs, signJob{domainName, d, "host", id, qfile, payload, principals, d.HostValidity})
			case strings.HasPrefix(name, "tls_") && strings.HasSuffix(name, ".csr"):
				id := strings.TrimSuffix(strings.TrimPrefix(name, "tls_"), ".csr")
				jobs = append(jobs, signJob{domainName, d, "tls", id, qfile, payload, "-",
					fmt.Sprintf("+%dd", d.TLSValidityDays)})
			}
		}
	}
	if len(jobs) == 0 {
		say("Queue is empty for anchor %q — nothing to sign.", anchorName)
		return
	}

	planLines := make([]string, 0, len(jobs)+1)
	for _, j := range jobs {
		planLines = append(planLines,
			fmt.Sprintf("sign %s %s cert %q → %s (%s)", j.domain, j.kind, j.id, j.principals, j.validity))
	}
	planLines = append(planLines, "record everything in the ledger; move requests to queue/done/")
	confirmPlan(planLines)

	// ---- hardware + PIN ----------------------------------------------------
	yk, _ := pickYubiKey(anchor.YubikeySerial)
	if yk != nil {
		defer yk.Close()
	}
	pivPreflight(yk)
	var pin string
	if !dryRun {
		pin = promptSecret("  PIV PIN: ")
		verifyPINOnce(yk, pin)
	}

	// ---- execute -----------------------------------------------------------
	// Ordering per job: sign → write dist (atomic) → append ledger
	// (idempotent by serial) → move queue file to done/ (idempotent). A failure
	// or [r]etry at any point re-runs safely because we sign the payload bytes
	// captured at gather time (not a re-read of the queue file, which may have
	// been moved or changed) and the ledger append is a no-op if already done.
	signed := 0
	for _, j := range jobs {
		j := j
		switch j.kind {
		case "user", "host":
			slotName := j.d.UserSlot
			certType := uint32(ssh.UserCert)
			if j.kind == "host" {
				slotName = j.d.HostSlot
				certType = ssh.HostCert
			}
			principals := cleanPrincipals(j.principals)
			if len(principals) == 0 {
				warn("[%s] %s has no usable principals — skipping (a cert with no principal can never authenticate)", j.domain, j.id)
				continue
			}
			serialNum := nextSerial(j.domain, anchor)
			distName := distHostCertName(j.id)
			if j.kind == "user" {
				distName = "user_" + j.id + "-cert.pub"
			}
			distRel := "dist/" + j.domain + "/" + distName
			if actTouch(fmt.Sprintf("[%s] sign %s cert %s (serial %d)", j.domain, j.kind, j.id, serialNum), "",
				func() error {
					caPub, err := slotPublicKey(yk, slotName)
					if err != nil {
						return err
					}
					signer, err := pivSigner(yk, slotName, caPub, pin)
					if err != nil {
						return err
					}
					cert, err := signSSHCert(signer, certSpec{
						certType: certType, keyID: j.domain + ":" + j.id, serial: serialNum,
						principals: principals, validity: j.validity,
					}, j.payload)
					if err != nil {
						return err
					}
					if err := writeFileAtomic(trustPath("dist", j.domain, distName), cert, 0o644); err != nil {
						return err
					}
					if err := appendLedgerOnce(j.domain, LedgerEntry{Serial: serialNum, Type: j.kind,
						Identity: j.id, Principals: strings.Join(principals, ","), Anchor: anchorName,
						Signed: today(), Expires: expiryFromValidity(j.validity), File: distRel}); err != nil {
						return err
					}
					return moveToDone(j.qfile, j.domain)
				}) {
				signed++
			}
		case "tls":
			distName := "tls_" + j.id + ".crt"
			distRel := "dist/" + j.domain + "/" + distName
			serialNum := nextSerial(j.domain, anchor)
			if actTouch(fmt.Sprintf("[%s] sign TLS client cert %s (serial %d, %d days)", j.domain, j.id, serialNum, j.d.TLSValidityDays), "",
				func() error {
					caCert, err := loadCertPEM(clientCACertPath(j.domain, anchorName))
					if err != nil {
						return err
					}
					caPub, err := slotPublicKey(yk, j.d.TLSSlot)
					if err != nil {
						return err
					}
					signer, err := pivSigner(yk, j.d.TLSSlot, caPub, pin)
					if err != nil {
						return err
					}
					certPEM, err := signClientCert(caCert, signer, j.payload, j.d.TLSValidityDays, serialNum)
					if err != nil {
						return err
					}
					if err := writeFileAtomic(trustPath("dist", j.domain, distName), certPEM, 0o644); err != nil {
						return err
					}
					if err := appendLedgerOnce(j.domain, LedgerEntry{Serial: serialNum, Type: "tls", Identity: j.id,
						Principals: "-", Anchor: anchorName, Signed: today(),
						Expires: expiryDays(j.d.TLSValidityDays), File: distRel}); err != nil {
						return err
					}
					return moveToDone(j.qfile, j.domain)
				}) {
				signed++
			}
		}
	}

	head("Signing complete — %d certificate(s) signed", signed)
	say("1. Commit dist/ + index/ + queue/ to git (all public material).")
	say("2. Unplug the anchor and put it away.")
	say("3. Each person installs their certs:  ykt cert install <name> <domain...>")
	say("   (remote people just pull the repo first — certs are public)")
	say("4. Install host certs:  ykt remote install <domain> [--apply]")
}
