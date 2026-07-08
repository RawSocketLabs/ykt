package main

// remote logins: harvest SSH certificate logins from hosts — who logged in,
// where, when — by reading sshd's "Accepted publickey" events over SSH. With the
// drop-in's LogLevel VERBOSE, each event carries the cert key ID (domain:person)
// and serial, so the report attributes every login to a person. Read-only and
// best-effort per host; nothing is written to the (synced) store.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

type login struct {
	host, when, user, from, keyID, serial string
}

var (
	loginLineRe = regexp.MustCompile(`Accepted publickey for (\S+) from (\S+) port \d+`)
	loginIDRe   = regexp.MustCompile(`ID (\S+) \(serial (\d+)\)`)
	isoTsRe     = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T[\d:.+\-]+)`)
	sysTsRe     = regexp.MustCompile(`^(\w{3}\s+\d+\s+[\d:]+)`)
)

// harvestScript reads sshd "Accepted publickey" lines from a host, trying
// journald (then sudo), then the classic syslog files. `journalctl -g` greps the
// whole journal, so it catches both sshd and the newer sshd-session process.
func harvestScript(since string) string {
	q := shellQuote(since)
	return "{ journalctl -g 'Accepted publickey' --since " + q + " -o short-iso --no-pager 2>/dev/null " +
		"|| sudo -n journalctl -g 'Accepted publickey' --since " + q + " -o short-iso --no-pager 2>/dev/null " +
		"|| grep -h 'Accepted publickey' /var/log/auth.log /var/log/secure 2>/dev/null " +
		"|| sudo -n grep -h 'Accepted publickey' /var/log/auth.log /var/log/secure 2>/dev/null; } " +
		"| grep 'Accepted publickey' || true"
}

func logTimestamp(line string) string {
	if m := isoTsRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	if m := sysTsRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return "?"
}

func parseLogins(host, text string) []login {
	var out []login
	for _, line := range strings.Split(text, "\n") {
		m := loginLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		l := login{host: host, when: logTimestamp(line), user: m[1], from: m[2], keyID: "-", serial: "-"}
		if id := loginIDRe.FindStringSubmatch(line); id != nil {
			l.keyID, l.serial = id[1], id[2]
		}
		out = append(out, l)
	}
	return out
}

func cmdRemoteLogins(args []string, since, out string) {
	reg, inv := loadRegistry(), loadInventory()

	type target struct{ name, dest string }
	var targets []target
	add := func(names []string) {
		for _, n := range names {
			m := inv.Machines[n]
			targets = append(targets, target{n, m.sshDest(n, reg.domain(m.Domain))})
		}
	}
	if len(args) == 0 {
		if len(inv.Machines) == 0 {
			fatal("inventory is empty — add machines first (ykt data inventory add ...)")
		}
		add(sortedKeys(inv.Machines))
	} else {
		reg.domain(args[0])
		add(resolveMachines(reg, inv, args[0], args[1:]))
	}

	head("Harvest SSH cert logins from %d host(s), since %q", len(targets), since)
	if dryRun {
		note("dry-run: would SSH each host and read sshd 'Accepted publickey' events")
		return
	}

	script := harvestScript(since)
	var all []login
	for _, t := range targets {
		c, err := sshConnect(t.dest)
		if err != nil {
			warn("[%s] connect failed: %v", t.name, err)
			continue
		}
		text, err := remoteRun(c, script)
		c.Close()
		if err != nil {
			warn("[%s] could not read logs (need journal access or passwordless sudo?): %v", t.name, err)
			continue
		}
		rows := parseLogins(t.name, text)
		all = append(all, rows...)
		say("[%s] %d login(s)", t.name, len(rows))
	}

	sort.Slice(all, func(i, j int) bool {
		if all[i].when != all[j].when {
			return all[i].when < all[j].when
		}
		return all[i].host < all[j].host
	})

	head("%d login(s) total", len(all))
	if len(all) > 0 {
		fmt.Printf("%-22s %-12s %-12s %-16s %-18s %s\n", "WHEN", "HOST", "USER", "FROM", "KEY-ID", "SERIAL")
		for _, l := range all {
			fmt.Printf("%-22s %-12s %-12s %-16s %-18s %s\n", l.when, l.host, l.user, l.from, l.keyID, l.serial)
		}
	}
	note("KEY-ID is the cert's domain:person; \"-\" means the host logged at a level below VERBOSE.")

	if out != "" {
		var b strings.Builder
		b.WriteString("when\thost\tuser\tfrom\tkey_id\tserial\n")
		for _, l := range all {
			fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s\t%s\n", l.when, l.host, l.user, l.from, l.keyID, l.serial)
		}
		if err := writeFileAtomic(out, []byte(b.String()), 0o600); err != nil {
			fatal("%v", err)
		}
		good("wrote %d row(s) → %s", len(all), out)
	}
}
