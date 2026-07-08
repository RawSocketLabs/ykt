package main

// XDG-style user directories. ykt's *trust store* (config.toml + CA material) is
// a git repo you clone — NOT a hidden user dir — because it's synced between
// operators. But two machine-local things belong in standard user dirs:
//   - the audit log  → $XDG_STATE_HOME/ykt   (per-machine, never synced)
//   - a store pointer → $XDG_CONFIG_HOME/ykt  (so an installed binary finds the
//     store from any working directory, written by `ykt setup home`)

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// xdgConfigDir is $XDG_CONFIG_HOME/ykt, else the OS config dir (~/.config on
// Linux, ~/Library/Application Support on macOS, %AppData% on Windows) + /ykt.
// Returns "" if it can't be determined (never fatals — callers handle "").
func xdgConfigDir() string {
	base := os.Getenv("XDG_CONFIG_HOME") // honored on every OS for consistency
	if base == "" {
		var err error
		if base, err = os.UserConfigDir(); err != nil || base == "" {
			return ""
		}
	}
	return filepath.Join(base, "ykt")
}

// homePointerPath records the trust-store directory for global invocation.
func homePointerPath() string {
	if d := xdgConfigDir(); d != "" {
		return filepath.Join(d, "home")
	}
	return ""
}

// xdgStateDir is $XDG_STATE_HOME/ykt, else ~/.local/state/ykt (or
// %LOCALAPPDATA%\ykt on Windows). For machine-local, non-synced data.
func xdgStateDir() string {
	if s := os.Getenv("XDG_STATE_HOME"); s != "" {
		return filepath.Join(s, "ykt")
	}
	if runtime.GOOS == "windows" {
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			return filepath.Join(la, "ykt")
		}
	}
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return ""
	}
	return filepath.Join(h, ".local", "state", "ykt")
}

// logFilePath is the machine-local audit log ("" if undeterminable → no log).
func logFilePath() string {
	if d := xdgStateDir(); d != "" {
		return filepath.Join(d, "ykt.log")
	}
	return ""
}

// readHomePointer returns the trust-store path recorded by `ykt setup home`, or
// "" if none is set (or it no longer contains a config.toml).
func readHomePointer() string {
	p := homePointerPath()
	if p == "" {
		return ""
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	dir := strings.TrimSpace(string(data))
	if dir == "" {
		return ""
	}
	if _, err := os.Stat(filepath.Join(dir, "config.toml")); err != nil {
		return ""
	}
	return dir
}

// cmdSetupHome records the trust store so `ykt` finds it from any directory.
func cmdSetupHome(args []string) {
	var target string
	if len(args) == 1 {
		abs, err := filepath.Abs(args[0])
		if err != nil {
			fatal("bad path %q: %v", args[0], err)
		}
		target = abs
	} else if initTrustHome() {
		target = trustHome
	} else {
		fatal("run this from inside your trust store (the dir with config.toml), or pass it: ykt setup home <path>")
	}
	if _, err := os.Stat(filepath.Join(target, "config.toml")); err != nil {
		fatal("no config.toml at %s — point this at your ykt trust-store directory", target)
	}
	if homePointerPath() == "" {
		fatal("cannot determine your config directory (is $HOME set?)")
	}
	if err := writeFileAtomic(homePointerPath(), []byte(target+"\n"), 0o644); err != nil {
		fatal("%v", err)
	}
	good("recorded trust store → %s", homePointerPath())
	say("`ykt` now uses %s from any directory.", target)
	say("(Overridden by $YKT_HOME, or by a nearer config.toml when you're inside another store.)")
}
