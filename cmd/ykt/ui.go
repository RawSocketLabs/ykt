package main

// Interactive wizard plumbing: every mutating operation is announced with an
// explanation and confirmed before it runs. --dry-run walks every step and
// performs nothing.

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
)

var (
	dryRun bool
	stdin  = bufio.NewReader(os.Stdin)
)

const (
	cBold = "\x1b[1m"
	cDim  = "\x1b[2m"
	cRed  = "\x1b[31m"
	cGrn  = "\x1b[32m"
	cYlw  = "\x1b[33m"
	cRst  = "\x1b[0m"
)

func colorize(c, s string) string {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return s
	}
	return c + s + cRst
}

func say(f string, a ...any)  { fmt.Printf(f+"\n", a...) }
func note(f string, a ...any) { fmt.Println(colorize(cDim, "· "+fmt.Sprintf(f, a...))) }
func good(f string, a ...any) { fmt.Println(colorize(cGrn, "✔ "+fmt.Sprintf(f, a...))) }
func warn(f string, a ...any) { fmt.Println(colorize(cYlw, "! "+fmt.Sprintf(f, a...))) }

func fatal(f string, a ...any) {
	fmt.Fprintln(os.Stderr, colorize(cRed, "✘ "+fmt.Sprintf(f, a...)))
	os.Exit(1)
}

func head(f string, a ...any) {
	fmt.Println()
	fmt.Println(colorize(cBold, "== "+fmt.Sprintf(f, a...)+" =="))
}

func explain(lines ...string) {
	for _, l := range lines {
		fmt.Println(colorize(cDim, l))
	}
}

func prompt(q string) string {
	fmt.Print(q)
	line, _ := stdin.ReadString('\n')
	return strings.TrimSpace(line)
}

func promptDefault(q, def string) string {
	v := prompt(fmt.Sprintf("  %s [%s]: ", q, def))
	if v == "" {
		return def
	}
	return v
}

func confirm(q string) bool {
	v := prompt(q + " [y/N] ")
	return strings.HasPrefix(strings.ToLower(v), "y")
}

func promptSecret(q string) string {
	fmt.Print(q)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fatal("reading input: %v", err)
	}
	return string(b)
}

// confirmPlan shows everything that is about to happen and asks ONCE.
// After approval, execution runs without further keystrokes (touches aside).
func confirmPlan(lines []string) {
	fmt.Println()
	fmt.Println(colorize(cBold, "PLAN — everything below runs with no further prompts (touches excepted):"))
	for _, l := range lines {
		say("  · %s", l)
	}
	if dryRun {
		note("dry-run: plan auto-approved")
		return
	}
	if !confirm(colorize(cBold, "Proceed with ALL of the above?")) {
		fatal("aborted — nothing was done")
	}
	fmt.Println()
}

// act runs a native operation immediately (plan already approved), showing
// what it is doing. On failure it drops to an interactive retry menu.
func act(what string, why string, fn func() error) bool { return runTask(what, why, false, fn) }

// actTouch is act for operations that make the YubiKey blink for a touch.
// piv-go blocks until the touch lands, so execution auto-continues on tap.
func actTouch(what string, why string, fn func() error) bool { return runTask(what, why, true, fn) }

// runTask returns true if the operation ultimately succeeded, false if the
// operator skipped it (or dry-run). Callers that count work (e.g. the cert-sign
// "N signed" tally) use this instead of incrementing inside the closure, which
// would double-count on a [r]etry.
func runTask(what, why string, touch bool, fn func() error) bool {
	fmt.Println("  " + colorize(cBold, "▶ "+what))
	if why != "" {
		fmt.Println(colorize(cDim, "    "+why))
	}
	if dryRun {
		note("dry-run: not executed")
		return false
	}
	if touch {
		fmt.Println(colorize(cYlw, "    👉 TOUCH the YubiKey when it blinks — continues by itself"))
	}
	logLine("ACT " + what)
	for {
		err := fn()
		if err == nil {
			good("%s", what)
			return true
		}
		warn("operation failed: %v", err)
		if strings.Contains(err.Error(), "6982") {
			warn("6982 usually means a missed TOUCH — retry and watch for the blink (~15s window)")
		}
		if strings.Contains(err.Error(), "6983") {
			warn("6983 = PIN/PUK BLOCKED — retrying will not help. Unblock first:")
			warn("  ykman piv access unblock-pin   (needs the PUK; factory 12345678)")
			warn("or reset the applet: ykman piv reset — then re-run this command")
		}
		if strings.Contains(err.Error(), "63c") || strings.Contains(err.Error(), "retries") {
			warn("wrong PIN — each retry burns an attempt; 0 left = blocked. Check before retrying.")
		}
		logLine(fmt.Sprintf("FAIL %s: %v", what, err))
		switch strings.ToLower(prompt("  [r]etry · [s]kip this step · [q]uit > ")) {
		case "r":
			continue
		case "s":
			return false
		default:
			fatal("stopped after failure — nothing after this step was run")
		}
	}
}

// actCommand runs an external program attached to this terminal — its
// prompts (FIDO2 PIN, touch) happen right here in the same shell. This is
// the ONE place the binary executes a subprocess: sk-key generation, which
// belongs to OpenSSH by design. The exact command is always shown first.
func actCommand(what string, argv []string, why ...string) {
	fmt.Println("  " + colorize(cBold, "▶ "+what))
	for _, l := range why {
		fmt.Println(colorize(cDim, "    "+l))
	}
	fmt.Println("    " + colorize(cBold, "$ "+shellJoin(argv)))
	if dryRun {
		note("dry-run: not executed")
		return
	}
	logLine("CMD " + strings.Join(argv, " "))
	for {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		err := cmd.Run()
		if err == nil {
			good("%s", what)
			return
		}
		warn("command failed: %v", err)
		if argv[0] == "ssh-keygen" {
			warn("firmware < 5.2.3? ed25519-sk and '-O resident' are unsupported there.")
		}
		logLine(fmt.Sprintf("CMD FAIL %v", err))
		switch strings.ToLower(prompt("  [r]etry · [s]kip this step · [q]uit > ")) {
		case "r":
			continue
		case "s":
			return
		default:
			fatal("stopped after failure — nothing after this step was run")
		}
	}
}

// shellJoin renders argv for display, making empty args visible as ”.
func shellJoin(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		if a == "" {
			a = "''"
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}

func logLine(s string) {
	p := logFilePath() // machine-local XDG state dir, not the (synced) trust store
	if p == "" {
		return
	}
	// Owner-only: the log records provisioned/revoked domains, hosts, and people.
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s\n", time.Now().Format("2006-01-02 15:04:05"), s)
}
