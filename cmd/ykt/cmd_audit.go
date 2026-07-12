package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// The audit log is machine-local (XDG state), append-only, and best-effort — it
// records every ykt action on this machine. It rotates to <log>.1 past a size
// cap (see maxLogBytes); these commands read both generations so a rotation
// hides nothing, and make the log viewable/exportable without hunting for it.

// readLogLines returns the audit log lines: the rotated generation (path+".1")
// first, then the current file. Returns os.ErrNotExist only if neither exists.
func readLogLines(path string) ([]string, error) {
	var lines []string
	found := false
	for _, f := range []string{path + ".1", path} {
		data, err := os.ReadFile(f)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		found = true
		for _, l := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if l != "" {
				lines = append(lines, l)
			}
		}
	}
	if !found {
		return nil, os.ErrNotExist
	}
	return lines, nil
}

func cmdAudit(args []string) {
	p := logFilePath()
	if p == "" {
		fatal("cannot determine the log path (is $HOME set?)")
	}

	limit := 40 // default: the recent tail
	if len(args) == 1 {
		if args[0] == "all" {
			limit = -1
		} else if n, err := strconv.Atoi(args[0]); err == nil && n >= 0 {
			limit = n
		} else {
			fatal("argument must be a line count or \"all\"")
		}
	}

	lines, err := readLogLines(p)
	if err != nil {
		if os.IsNotExist(err) {
			note("no audit log yet at %s", p)
			return
		}
		fatal("%v", err)
	}

	head("audit log — %s", p)
	start := 0
	if limit >= 0 && len(lines) > limit {
		start = len(lines) - limit
		note("showing last %d of %d lines (`ykt audit all` for everything)", limit, len(lines))
	}
	for _, l := range lines[start:] {
		fmt.Println(l)
	}
}

func cmdAuditExport(dst string) {
	p := logFilePath()
	lines, err := readLogLines(p)
	if err != nil {
		fatal("no audit log to export (nothing logged on this machine yet)")
	}
	if err := writeFileAtomic(dst, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		fatal("%v", err)
	}
	good("audit log (%d lines) → %s", len(lines), dst)
}

func cmdAuditPath() {
	p := logFilePath()
	if p == "" {
		fatal("cannot determine the log path (is $HOME set?)")
	}
	fmt.Println(p)
}
