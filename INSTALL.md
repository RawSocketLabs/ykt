# Installing ykt

`ykt` talks to YubiKeys over the platform's PC/SC smart-card stack and
shells out to exactly two external tools (`ssh-keygen` for FIDO2 key
generation, `ykman` for FIDO2 factory resets). What you need per OS:

## Runtime dependencies

### Linux (Fedora / RHEL)
```
sudo dnf install pcsc-lite yubikey-manager openssh-clients
sudo systemctl enable --now pcscd.socket
```

### Linux (Debian / Ubuntu)
```
sudo apt-get install pcscd yubikey-manager openssh-client
sudo systemctl enable --now pcscd.socket
```

### macOS
PC/SC is built into the OS — nothing to install for card access. But
**Apple's bundled OpenSSH has FIDO/security-key support disabled**, so
hardware-backed ssh keys need the Homebrew build:
```
brew install openssh ykman
```
Make sure `which ssh-keygen` resolves to the Homebrew one (`brew` prepends
`/opt/homebrew/bin` to PATH in its shellenv).

### Windows
PC/SC (Winscard) is built into the OS; ensure the **Smart Card** service is
running (`sc start SCardSvr`). Install:
```
winget install Yubico.YubiKeyManagerCLI
winget install Microsoft.OpenSSH.Preview   # bundled OpenSSH predates sk support
```
*Windows support is theoretical — the PC/SC layer is pure syscalls so the
binary builds and runs, but no full signing flow has been exercised on Windows yet.*

## Verify (and auto-fix)

```
ykt doctor          # reports missing/broken dependencies, exit 1 if any
ykt doctor --fix    # plans the package-manager commands, confirms once, runs them
```

`doctor` checks: PC/SC reachability, connected YubiKeys (firmware + PIN
retry counters), `ssh-keygen` presence **and sk support** (`ssh -Q key`),
`ykman`, config + trust files, and ssh-agent.

## Getting the binary

**Via `go install`:** `go install github.com/RawSocketLabs/ykt/cmd/ykt@latest` (needs Go
1.24+ and, on Linux, the PC/SC dev headers below).

**From releases:** grab the artifact for your platform from the
[Releases page](https://github.com/RawSocketLabs/ykt/releases) (built by CI):
`ykt-linux-amd64`, `ykt-darwin-arm64`, `ykt-windows-amd64.exe`. Put it on your
`PATH`.

**Finding your trust store.** `ykt` locates `config.toml` in this order:
`$YKT_HOME` → the binary's own directory → walking up from the current directory
→ a pointer you record once. So running `ykt` from inside your store checkout
just works. To use an installed `ykt` from *anywhere*, run this once from inside
the store:

```
ykt setup home            # records this store in ~/.config/ykt/home
# ykt setup home /path     # or point at a specific directory
```

The store itself (config + CA material) stays a git repo you clone — it is *not*
kept in hidden user dirs, because it's synced between operators. Only two
machine-local things use standard user dirs: the store pointer
(`$XDG_CONFIG_HOME/ykt/home`) and the audit log (`$XDG_STATE_HOME/ykt/ykt.log`).

**Building locally** (from the repo root):

| OS | Build prerequisites | Command |
|---|---|---|
| Linux | `go` ≥ 1.24, `gcc`, `pkg-config`, pcsc headers: `dnf install pcsc-lite-devel` / `apt-get install libpcsclite-dev` | `make build` |
| macOS | `go` ≥ 1.24, Xcode CLT (`xcode-select --install`) — links the system PCSC framework | `make build` |
| Windows | `go` ≥ 1.24 only (no C toolchain — Winscard via syscalls) | `go build -o bin\ykt.exe .` |

Cross-compiling `GOOS=windows` from Linux/macOS works (no cgo on Windows; see
`make cross`). Linux and macOS targets require building on their own OS (cgo).

Run the test suite from the repo root: `go test ./...` (needs the Linux pcsc
headers to compile, but no YubiKey — hardware paths are integration-only).

## Repo hygiene (both operators, once per clone)

```
git config core.hooksPath .githooks
```

This enables the pre-commit secret guard (blocks private keys, PIN/PUK-like
values, and known-sensitive filenames from being committed). CI runs the
same scan with gitleaks on every push.
