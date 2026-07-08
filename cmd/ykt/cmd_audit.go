package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
)

// The audit log is machine-local (XDG state), append-only, and best-effort — it
// records every ykt action on this machine. These commands make it viewable and
// exportable without hunting for the file.

func cmdAudit(args []string) {
	p := logFilePath()
	if p == "" {
		fatal("cannot determine the log path (is $HOME set?)")
	}
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			note("no audit log yet at %s", p)
			return
		}
		fatal("%v", err)
	}
	defer f.Close()

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

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
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
	if p == "" || !fileExists(p) {
		fatal("no audit log to export (nothing logged on this machine yet)")
	}
	if err := copyFile(p, dst, 0o600); err != nil {
		fatal("%v", err)
	}
	good("audit log → %s", dst)
}

func cmdAuditPath() {
	p := logFilePath()
	if p == "" {
		fatal("cannot determine the log path (is $HOME set?)")
	}
	fmt.Println(p)
}
