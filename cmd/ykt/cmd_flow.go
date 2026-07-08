package main

// flow: the workflow conductor. Assesses the whole system's state, reports
// what's pending, and walks the operator through the next actionable step —
// including waiting for the right YubiKey to be inserted before each one.
// Deliberately line-oriented, not a TUI: subprocesses (ssh-keygen, ykman)
// share the terminal, and auditable trust tooling beats pretty panels.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type flowAction struct {
	desc       string
	needSerial string // YubiKey serial that must be inserted ("" = none/any)
	keyHint    string // human name of the key to insert
	run        func()
}

func cmdFlow() {
	head("flow — config preflight")
	checkDailyKeySlots(loadRegistry())
	for {
		actions, notes := assessFlow()
		head("flow — system state")
		for _, n := range notes {
			note("%s", n)
		}
		if len(actions) == 0 {
			if len(notes) > 0 {
				note("no CA-level steps pending — see the note(s) above")
			} else {
				good("nothing actionable — system is current")
			}
			return
		}
		say("\nPending steps, in order:")
		for i, a := range actions {
			say("  %d. %s", i+1, a.desc)
		}
		next := actions[0]
		if dryRun {
			note("dry-run: stopping before execution")
			return
		}
		if !confirm(fmt.Sprintf("\nDo step 1 now (%s)?", next.desc)) {
			say("Stopping — run 'ykt flow' again any time.")
			return
		}
		if next.needSerial != "" {
			waitForKeyPresent(next.needSerial, next.keyHint)
		}
		next.run()
		say("")
		if !confirm("Re-assess and continue with the next step?") {
			return
		}
	}
}

// waitForKeyPresent blocks until the YubiKey with the serial is connected.
func waitForKeyPresent(serial, hint string) {
	n, err := parseUint32(serial)
	if err != nil {
		// Don't silently proceed without confirming the right key is inserted.
		if serial == "" || serial == "unset" {
			note("no serial recorded for %s — make sure the right YubiKey is inserted", hint)
		} else {
			warn("registry has a malformed serial %q for %s — can't verify the right key is inserted", serial, hint)
		}
		return
	}
	if presentQuiet(n) {
		return
	}
	fmt.Println(colorize(cYlw, fmt.Sprintf("  👉 INSERT %s (serial %s)…", hint, serial)))
	for !presentQuiet(n) {
		time.Sleep(500 * time.Millisecond)
	}
	good("detected")
}

// assessFlow inspects config, pub/, queue/, dist/, and this machine to build
// the ordered to-do list.
func assessFlow() (actions []flowAction, notes []string) {
	reg := loadRegistry()
	// Enrollment is the first user action, but it factory-resets the key — so
	// surface it as a NOTE, not an auto-run step. Without this, a fresh operator
	// who cloned a configured store is told "nothing actionable".
	if h, err := os.UserHomeDir(); err == nil {
		if _, err := os.Stat(filepath.Join(h, ".ssh", dailyKeyName+".pub")); err != nil {
			notes = append(notes, "this machine has no daily key — enroll with `ykt init user <name> "+strings.Join(reg.domainNames(), " ")+"`")
		}
	}
	hostname, _ := os.Hostname()
	hostname = shortHost(hostname)
	var deferred []flowAction // steps for keys/operators not at this machine
	defer func() { actions = append(actions, deferred...) }()

	// 1. anchors needing genesis
	for _, an := range reg.anchorNames() {
		an := an
		a := reg.Anchors[an]
		domains := reg.domainsOn(an)
		if len(domains) == 0 {
			continue
		}
		var present, missing []string
		for _, dn := range domains {
			if _, err := os.Stat(caPubPath(dn, "user", an)); err == nil {
				present = append(present, dn)
			} else {
				missing = append(missing, dn)
			}
		}
		if len(missing) == 0 {
			notes = append(notes, fmt.Sprintf("anchor %s (%s): initialized, %d domain(s)", an, a.Holder, len(domains)))
			continue
		}
		provisioned := len(present) > 0 // anchor exists, just missing some domains
		verb := "GENESIS"
		if provisioned {
			verb = "add domain(s) " + strings.Join(missing, " ") + " to"
		}
		if a.YubikeySerial == "unset" || a.YubikeySerial == "" {
			notes = append(notes, fmt.Sprintf("anchor %s (%s): %s PENDING — actionable wherever that key is", an, a.Holder, verb))
			deferred = append(deferred, flowAction{
				desc:    fmt.Sprintf("init ca %s — %s (%s's anchor, likely at their site)", an, verb, a.Holder),
				keyHint: "the anchor YubiKey",
				run:     func() { cmdInitCA([]string{an}) },
			})
		} else {
			desc := fmt.Sprintf("init ca %s — GENESIS (serial %s)", an, a.YubikeySerial)
			if provisioned {
				// additive is non-destructive; safe to steer the operator into it
				desc = fmt.Sprintf("init ca %s — additively add %s (no reset; serial %s)", an, strings.Join(missing, " "), a.YubikeySerial)
			}
			actions = append(actions, flowAction{
				desc:       desc,
				needSerial: a.YubikeySerial,
				keyHint:    "anchor " + an,
				run:        func() { cmdInitCA([]string{an}) },
			})
		}
	}

	// 2. pending queue → cert sign (grouped per anchor able to sign)
	pendingByAnchor := map[string]int{}
	for _, dn := range reg.domainNames() {
		entries, err := os.ReadDir(trustPath("queue", dn))
		if err != nil {
			continue
		}
		n := 0
		for _, e := range entries {
			if !e.IsDir() {
				n++
			}
		}
		if n == 0 {
			continue
		}
		for _, an := range reg.domain(dn).AnchorList() {
			pendingByAnchor[an] += n
		}
	}
	for _, an := range reg.anchorNames() {
		an := an
		count := pendingByAnchor[an]
		if count == 0 {
			continue
		}
		a := reg.Anchors[an]
		if a.YubikeySerial == "unset" || a.YubikeySerial == "" {
			continue // can't sign with an unprovisioned anchor
		}
		notes = append(notes, fmt.Sprintf("queue: %d request(s) signable by anchor %s", count, an))
		actions = append(actions, flowAction{
			desc:       fmt.Sprintf("cert sign %s — sign %d queued request(s)", an, count),
			needSerial: a.YubikeySerial,
			keyHint:    "anchor " + an,
			run:        func() { cmdSign([]string{an}) },
		})
		break // one signing per pass; flow re-assesses after
	}

	// 3. signed certs for THIS machine not yet installed, grouped PER PERSON
	//    (multiple people may share a hostname; never mix one person's name
	//    with another's domains).
	pendingByPerson := map[string][]string{}
	home := homeDir()
	for _, dn := range reg.domainNames() {
		entries, err := os.ReadDir(trustPath("dist", dn))
		if err != nil {
			continue
		}
		suffix := "_" + hostname + "-cert.pub"
		for _, e := range entries {
			name := e.Name()
			if !strings.HasPrefix(name, "user_") || !strings.HasSuffix(name, suffix) {
				continue
			}
			person := strings.TrimSuffix(strings.TrimPrefix(name, "user_"), suffix)
			distCert, err := os.ReadFile(trustPath("dist", dn, name))
			if err != nil {
				continue
			}
			installed, _ := os.ReadFile(filepath.Join(home, ".ssh", installedSSHCertName(dn)))
			if string(installed) == string(distCert) {
				continue // already installed for this person's key
			}
			pendingByPerson[person] = append(pendingByPerson[person], dn)
		}
	}
	for _, person := range sortedKeys(pendingByPerson) {
		person := person
		domains := pendingByPerson[person]
		sort.Strings(domains)
		notes = append(notes, fmt.Sprintf("certs for %s@%s signed but not installed: %s", person, hostname, strings.Join(domains, " ")))
		actions = append(actions, flowAction{
			desc:    fmt.Sprintf("cert install %s %s (only if this is your key + machine)", person, strings.Join(domains, " ")),
			keyHint: "your daily YubiKey",
			run:     func() { cmdCertInstall(append([]string{person}, domains...)) },
		})
	}

	// 4. this host not yet configured to trust anything (unified layout)
	if _, err := os.Stat(hostTrustDropIn); err != nil {
		notes = append(notes, "this machine has no ykt-managed sshd trust configured")
		notes = append(notes, "  → run manually (needs sudo): sudo ykt init host <domain>")
	}

	// 5. expiring soon
	cutoff := time.Now().AddDate(0, 0, 21).Format("2006-01-02")
	for _, dn := range reg.domainNames() {
		for _, e := range loadLedger(dn) {
			if !e.Revoked && e.Expires != "" && e.Expires != "?" && e.Expires <= cutoff {
				notes = append(notes, fmt.Sprintf("EXPIRING: %s %s %q on %s — re-enroll/queue before then", dn, e.Type, e.Identity, e.Expires))
			}
		}
	}
	return actions, notes
}
