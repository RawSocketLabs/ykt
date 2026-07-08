# Contributing to ykt

Thanks for your interest! ykt is a small, security-sensitive tool, so we value
correctness and clarity over feature count. This guide covers how to build,
test, and submit changes.

## Ground rules

- **Never commit secrets.** No PINs, PUKs, private keys, or `.age` files. Only
  public CA material and non-secret config belong in a checkout, and even that
  stays in your *own* private fork — never in this repo. CI runs a secret scan.
- **Security issues go through private disclosure**, not public issues or PRs.
  See [SECURITY.md](SECURITY.md).
- Be kind. See the [Code of Conduct](CODE_OF_CONDUCT.md).

## Development setup

You need **Go 1.24+** and the PC/SC development headers (piv-go uses cgo on
Linux and macOS; Windows builds are pure-syscall, no cgo).

| OS | Dependency |
|---|---|
| Linux (Debian/Ubuntu) | `sudo apt-get install libpcsclite-dev pcscd` |
| Linux (Fedora) | `sudo dnf install pcsc-lite-devel pcsc-lite` |
| macOS | PC/SC ships with the OS |
| Windows | none (build with `CGO_ENABLED=0`) |

```
git clone https://github.com/RawSocketLabs/ykt
cd ykt
make build        # → bin/ykt
make check        # gofmt + go vet + go test
make lint         # golangci-lint
```

Hardware-dependent tests skip automatically when no YubiKey is present, so
`go test ./...` is safe on CI and dev machines without a key. If you have a
spare/test key, exercise the real flow against a throwaway `test`/`lab` domain
— never your production anchor.

## Making a change

1. Fork and branch from `main`.
2. Keep changes focused; match the surrounding code's style and comment density.
3. Run `make check` and `make lint` before pushing.
4. Update docs when you change behavior or commands.
5. Open a PR. **The PR title must be a [Conventional Commit](https://www.conventionalcommits.org/)**
   — it becomes the squash-merge commit and drives the next release.

### Conventional Commit types

| Type | Use for | Version effect (pre-1.0) |
|---|---|---|
| `feat:` | a new capability | minor bump |
| `fix:` | a bug fix | patch bump |
| `docs:`, `test:`, `refactor:`, `chore:`, `ci:`, `build:`, `perf:` | non-user-facing | no release on its own |
| `feat!:` / `fix!:` or a `BREAKING CHANGE:` footer | incompatible change | minor bump while <1.0, major at ≥1.0 |

Examples:

```
feat: add `cert export` to write a KRL bundle
fix: gate cert-install on daily-key slot collisions
docs: clarify the carry-only-the-key flow
```

## Releases

Releases are automated from `main` — no manual tagging and no release PRs (the
org disallows Actions creating PRs). On each push to `main` a workflow reads the
merged Conventional Commits and, when a `feat:` or `fix:` is present, tags the
next semver and publishes a GitHub Release with binaries for Linux, macOS, and
Windows (`docs:`/`chore:`-only pushes don't release). To cut a specific version
by hand, push a `vX.Y.Z` tag — the same workflow builds and publishes it.

## Project layout

The CLI is `package main` under `cmd/ykt/` (so `go install github.com/RawSocketLabs/ykt/cmd/ykt@latest`
works); a small root `package ykt` (`docs.go`) exists only to embed the bundled
documentation. Command handlers are named to mirror their CLI path (`cmdInitCA`,
`cmdCertSign`, `cmdSetupKey`, `cmdRepoInit`, …). See [README.md](README.md) for
the command map and [RECOVERY.md](RECOVERY.md) for the trust and break-glass
model.
