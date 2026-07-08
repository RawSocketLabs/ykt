package main

// repo: manage the trust store as its own git repository — the recommended way
// to keep and share the public CA material between operators WITHOUT forking the
// tool's source. Install the binary (`go install` or a release), then:
//
//	ykt repo init [--remote URL]   turn a directory into a data-only store repo
//	ykt repo sync                  git pull the latest (fast-forward)
//	ykt repo push [-m msg]         commit local changes and push
//	ykt repo status                git status of the store
//
// The store tracks config.toml + pub/ + index/ + queue/ + dist/ + inventory +
// <anchor>.json (all public material); only secrets, logs, and build output are
// ignored. Nothing here needs the tool's Go source.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	ykt "github.com/RawSocketLabs/ykt"
)

// repoGitignore is the .gitignore a trust-store data repo uses.
const repoGitignore = `# ykt trust store — a DATA repo of public CA material, synced between operators.
# config.toml, pub/, index/, queue/, dist/, inventory.toml and <anchor>.json are
# tracked on purpose; only genuine secrets, logs, and build output are ignored.

# secrets — never commit (PINs/PUKs are paper-only; keys live on the YubiKey)
*.age
*.key
*.puk
info.json

# machine-local / scratch
ykt.log
*.tmp
/bin/
.DS_Store
`

// git runs git in dir, wired to this terminal (so auth prompts / progress show).
func git(dir string, args ...string) error {
	c := exec.Command("git", args...)
	c.Dir = dir
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	return c.Run()
}

// gitOK reports whether a git command succeeds (for predicate checks).
func gitOK(dir string, args ...string) bool {
	c := exec.Command("git", args...)
	c.Dir = dir
	return c.Run() == nil
}

// gitOutput returns a git command's trimmed stdout ("" on error).
func gitOutput(dir string, args ...string) string {
	c := exec.Command("git", args...)
	c.Dir = dir
	out, err := c.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func cmdRepoClone(url, dir string) {
	if _, err := exec.LookPath("git"); err != nil {
		fatal("git is not installed — install git first")
	}
	if dir == "" {
		base := strings.TrimSuffix(filepath.Base(url), ".git")
		if base == "" || base == "." || base == "/" {
			fatal("could not derive a directory name from %q — pass one: ykt repo clone <url> <dir>", url)
		}
		dir = base
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		fatal("bad path %q: %v", dir, err)
	}
	head("Clone trust store %s → %s", url, abs)
	if dryRun {
		note("dry-run: would git clone and record it with `ykt setup home`")
		return
	}
	if err := git("", "clone", url, abs); err != nil {
		fatal("git clone: %v", err)
	}
	if !isTrustStore(abs) {
		warn("cloned, but %s has no config.toml — is this a ykt store?", abs)
		return
	}
	cmdSetupHome([]string{abs}) // record the pointer so `ykt` finds it anywhere
	good("cloned + recorded — run `ykt status` from any directory.")
}

func cmdRepoInit(args []string, remote string) {
	if _, err := exec.LookPath("git"); err != nil {
		fatal("git is not installed — install git first")
	}
	dir := "."
	if len(args) == 1 {
		dir = args[0]
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		fatal("bad path %q: %v", dir, err)
	}
	if err := ensureDir(abs); err != nil {
		fatal("%v", err)
	}

	head("Initialize a ykt trust-store repo in %s", abs)
	// Seed a starter config only when NONE exists — never overwrite a config.toml
	// that's already there (ours or a user's).
	seedConfig := !fileExists(filepath.Join(abs, "config.toml")) && len(ykt.ConfigExample) > 0
	if dryRun {
		if seedConfig {
			note("dry-run: would seed a starter config.toml from the bundled example")
		}
		note("dry-run: would git-init, write .gitignore%s, and make the first commit", remoteSuffix(remote))
		return
	}
	if seedConfig {
		if err := writeFileAtomic(filepath.Join(abs, "config.toml"), ykt.ConfigExample, 0o644); err != nil {
			fatal("%v", err)
		}
		note("wrote a starter config.toml from the bundled example — edit it (domains, anchors, slots) before `ykt init ca`.")
	}

	if _, err := os.Stat(filepath.Join(abs, ".git")); err != nil {
		if err := git(abs, "init"); err != nil {
			fatal("git init: %v", err)
		}
	} else {
		note("already a git repo — leaving history intact")
	}

	gi := filepath.Join(abs, ".gitignore")
	if !fileExists(gi) {
		if err := writeFileAtomic(gi, []byte(repoGitignore), 0o644); err != nil {
			fatal("%v", err)
		}
	}

	if remote != "" {
		_ = git(abs, "remote", "remove", "origin") // replace any existing origin
		if err := git(abs, "remote", "add", "origin", remote); err != nil {
			fatal("git remote add: %v", err)
		}
	}

	if err := git(abs, "add", "-A"); err != nil {
		fatal("git add: %v", err)
	}
	if !gitOK(abs, "diff", "--cached", "--quiet") { // staged changes present
		if err := git(abs, "commit", "-m", "chore: initialize ykt trust store"); err != nil {
			fatal("git commit: %v", err)
		}
	}
	good("trust store repo ready at %s", abs)
	if remote != "" {
		say("Publish it:  ykt repo push")
	} else {
		say("Add a remote when ready:  cd %s && git remote add origin <url> && ykt repo push", abs)
	}
}

func remoteSuffix(remote string) string {
	if remote != "" {
		return ", set origin=" + remote
	}
	return ""
}

// storeDir returns the resolved trust store for sync/push/status (PreRun's
// requireTrustHome has already set trustHome for these non-optional commands).
func storeDir() string {
	if trustHome == "" {
		requireTrustHome()
	}
	if !gitOK(trustHome, "rev-parse", "--is-inside-work-tree") {
		fatal("%s is not a git repo — run `ykt repo init` there first", trustHome)
	}
	return trustHome
}

func cmdRepoSync(rebase bool) {
	dir := storeDir()
	head("Sync trust store (git pull) — %s", dir)
	if dryRun {
		note("dry-run: would git pull %s", ternary(rebase, "--rebase", "--ff-only"))
		return
	}
	if rebase {
		if err := git(dir, "pull", "--rebase"); err != nil {
			fatal("rebase pull hit a conflict — resolve in %s, then `git rebase --continue`: %v", dir, err)
		}
	} else if err := git(dir, "pull", "--ff-only"); err != nil {
		fatal("can't fast-forward (your local commits have diverged). Push your work with `ykt repo push`, or re-run as `ykt repo sync --rebase`. (%s)", dir)
	}
	good("up to date")
}

func cmdRepoPush(msg string) {
	dir := storeDir()
	head("Push trust store (commit + push) — %s", dir)
	if dryRun {
		note("dry-run: would git add -A, commit, rebase onto origin, and push")
		return
	}
	if err := git(dir, "add", "-A"); err != nil {
		fatal("git add: %v", err)
	}
	if gitOK(dir, "diff", "--cached", "--quiet") {
		note("no local changes to commit — pushing any pending commits")
	} else {
		if msg == "" {
			msg = "chore: update trust material"
		}
		if err := git(dir, "commit", "-m", msg); err != nil {
			fatal("git commit: %v", err)
		}
	}
	// Incorporate the other operator's pushes first, so two people sharing the
	// mailbox don't clobber each other; then push.
	branch := gitOutput(dir, "rev-parse", "--abbrev-ref", "HEAD")
	if branch != "" && branch != "HEAD" {
		_ = git(dir, "fetch", "origin", branch)
		if gitOK(dir, "rev-parse", "--verify", "origin/"+branch) {
			if err := git(dir, "rebase", "origin/"+branch); err != nil {
				fatal("conflict rebasing onto origin/%s — resolve in %s, run `git rebase --continue`, then re-run `ykt repo push`: %v", branch, dir, err)
			}
		}
		if err := git(dir, "push", "-u", "origin", branch); err != nil {
			fatal("git push: %v", err)
		}
	} else if err := git(dir, "push"); err != nil {
		fatal("git push: %v", err)
	}
	good("pushed")
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func cmdRepoStatus() {
	dir := storeDir()
	head("Trust store git status — %s", dir)
	_ = git(dir, "status", "-sb")
}
