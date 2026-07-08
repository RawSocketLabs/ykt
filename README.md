# ykt — YubiKey-anchored offline CA for SSH & mTLS

[![CI](https://github.com/RawSocketLabs/ykt/actions/workflows/ci.yml/badge.svg)](https://github.com/RawSocketLabs/ykt/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/RawSocketLabs/ykt?sort=semver)](https://github.com/RawSocketLabs/ykt/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/RawSocketLabs/ykt)](https://goreportcard.com/report/github.com/RawSocketLabs/ykt)
[![Go Reference](https://pkg.go.dev/badge/github.com/RawSocketLabs/ykt.svg)](https://pkg.go.dev/github.com/RawSocketLabs/ykt)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)

`ykt` turns a pair of YubiKeys into an offline certificate authority that issues
short-lived SSH certificates and mTLS client certificates across your own trust
domains. No CA service runs anywhere — the private keys live inside the
YubiKeys and never leave; you sign at a brief, touch-gated signing session a few
times a quarter. Native Go: PIV via go-piv, SSH certs via x/crypto/ssh, X.509 via
crypto/x509, KRLs via a validated PROTOCOL.krl writer, remote install over
native SSH. Only `pcscd` is required at runtime — no ykman/OpenSC/OpenSSL/p11tool.

> **Bring your own config.** Nothing in the code is specific to any one setup —
> your domains, anchors, and machines are all config. Copy `config.toml.example`
> → `config.toml`, edit it, and run `ykt init ca` with your own YubiKeys. Your
> populated trust tree (`config.toml`, `pub/`, `index/`, …) is *data* — keep it
> in its **own** private git repo managed by [`ykt repo`](#run-your-own-ca-dont-fork-the-tool),
> not in a fork of this tool.

## Install

```
# from source (needs Go 1.24+ and PC/SC dev headers — see INSTALL.md)
go install github.com/RawSocketLabs/ykt/cmd/ykt@latest

# or grab a prebuilt binary for your OS from the Releases page:
# https://github.com/RawSocketLabs/ykt/releases
```

## Quickstart

```
make build                              # → bin/ykt  (needs Go 1.24 + pcsc-lite-devel on Linux)
bin/ykt doctor                          # preflight: PC/SC, YubiKeys, tools, slot map, USB interfaces
bin/ykt doctor --fix                    # install missing deps + enable disabled PIV/FIDO interfaces
cp config.toml.example config.toml      # then edit: your domains, anchors, slots
bin/ykt --dry-run init ca a1            # rehearse genesis; touches nothing
bin/ykt flow                            # guided: assess state and do the next step
```

`ykt flow` is the conductor: it assesses the whole system, lists the pending
steps in order, waits for the right YubiKey to be inserted, and runs each with
your approval. When unsure what to do next, run it.

## Run your own CA (don't fork the tool)

You don't fork this repository to use `ykt`. Install the **binary**, then keep
your CA material in its **own private git repo** — tool and data stay separate,
so upstream code never mixes with your secrets and updating the tool is just
another `go install`.

```
# 1. install the tool (same command updates it later)
go install github.com/RawSocketLabs/ykt/cmd/ykt@latest

# 2. create your trust store as its own private data repo
mkdir my-trust && cd my-trust
curl -fsSLO https://raw.githubusercontent.com/RawSocketLabs/ykt/main/config.toml.example
mv config.toml.example config.toml && $EDITOR config.toml    # your domains, anchors, slots
ykt repo init --remote git@github.com:you/my-trust.git       # git repo + data .gitignore + first commit

# 3. build your CA (see the Quickstart above, or `ykt flow`)
ykt init ca a1

# 4. share the public material with co-operators
ykt repo push          # commit local changes and push
ykt repo sync          # fast-forward pull teammates' updates
ykt repo status        # what's changed locally
```

`ykt repo init` writes a data-oriented `.gitignore` that **tracks** the public
CA material (`config.toml`, `pub/`, `index/`, `queue/`, `dist/`, inventory,
`<anchor>.json`) and **ignores** secrets, the audit log, and build output. PINs,
PUKs, and private keys are never written to disk by `ykt` — they live on paper
and inside the YubiKeys — so they can't be committed by accident. A second
operator just clones your store repo and uses `ykt repo sync` / `push`; no fork,
no code involved.

## Forking & contributing

Fork this repo only to **change the tool itself** (fix a bug, add a feature) —
not to run your own CA (that's `ykt repo`, above). If you do fork:

- **Kill the pipelines you don't need.** Releases are already gated to the
  canonical repo, so a fork never publishes. To turn CI off too, set repository
  variable `YKT_DISABLE_CI=true` (Settings → Secrets and variables → Actions →
  Variables), or disable Actions in the fork's settings.
- **Nothing to re-point.** No org, domain, or path is hardcoded — names are all
  config, and config lives in your separate `ykt repo` store, not here.
- **Send changes upstream** with Conventional Commits (`feat:`, `fix:`, …); see
  [CONTRIBUTING.md](CONTRIBUTING.md). Merged `feat`/`fix` commits on `main`
  auto-tag and publish a release.

Prefer a browser? **`ykt docs`** serves this documentation offline (it's embedded
in the binary) and opens it in your browser.

## Platform support

`ykt` runs on **Linux, macOS, and Windows** — prebuilt binaries are published for
each. YubiKey **PIV** works natively everywhere (cgo + pcsc-lite on Linux, the
system PC/SC framework on macOS, the Windows smart-card API — no cgo — on Windows).

| Capability | Linux | macOS | Windows |
|---|---|---|---|
| PIV — anchor genesis, mTLS, cert stash, `setup key` | ✅ | ✅ | ✅ |
| FIDO2 daily key (`init user`, via `ssh-keygen -t …-sk`) | ✅ | ✅ | ⚠️ needs a recent Win32-OpenSSH with security-key support |
| Store discovery, XDG dirs, `setup home`, `docs` | ✅ | ✅ | ✅ |
| SSH client config + certs in `~/.ssh` | ✅ | ✅ | ✅ |
| `init host` (run **on** a host to trust a CA) | ✅ systemd | ⚠️ manual `sshd` reload | ❌ different `sshd` model |

You **operate** ykt from any of the three — sign, install certs, manage config,
carry only the key. `init host` provisions a host's `sshd` in place and expects a
Unix host (systemd for the auto-reload); you can still push trust to Unix hosts
*from* Windows/macOS with `remote install`. The one client-side caveat is Windows
FIDO2 key generation, which depends on your OpenSSH build's security-key support —
every PIV-based flow is unaffected.

## Interaction model

**Preflight → gather all inputs → one PLAN confirmation → execute.** Preflight
verifies the expected YubiKey is inserted (serial from `config.toml`), reports
firmware, and checks the PIN isn't blocked; your PIN is verified the moment you
type it. Touch prompts print when the key blinks and continue automatically once
tapped. `--dry-run` on any command rehearses it end to end, touching no files or
hardware.

## Command map

| Phase | Command | Where it runs |
|---|---|---|
| Genesis (P1) | `ykt init ca <anchor>` | anchor holder; auto-resets PIV, additive for new domains |
| User enrollment (P2) | `ykt init user <name> <domain...>` | each person's machine (resets FIDO+PIV; `--keep` to skip) |
| Signing | `ykt cert sign <anchor>` | anchor holder, anchor inserted |
| Last mile | `ykt cert install <name> <domain...>` | the enrollee's machine |
| Carry only the key | `ykt setup key [domain...]` | a fresh machine, key inserted (no files to bring) |
| Host trust (local) | `sudo ykt init host <domain>` | ON the host (guided; optional password-off) |
| Host trust (remote) | `ykt remote collect` / `ykt remote install [--apply] [--all]` | operator machine (`--all` re-pushes KRLs everywhere after a revoke) |
| SSH config | `ykt setup ssh init [--include top\|bottom]\|add\|sync\|list\|remove` | client machines; all under `~/.ssh/ykt/<domain>/` (never collides) |
| mTLS edge | `ykt setup caddy <domain...>` | generates Caddy client-auth config |
| Test boxes | `ykt setup bootstrap cloud-init\|install-script\|trust` | throwaway VPS onboarding |
| Renew / revoke | `ykt cert renew <name> <domain...>` · `ykt cert revoke` · `ykt remote install --all` | renew (no reset) → sign; revoke → sweep |
| Store (git) | `ykt repo clone\|sync\|push\|status` | share the trust store between operators |
| Verify / audit | `ykt verify attestation` · `ykt audit` | prove keys are on-device (offline); view the local action log |
| Ops | `ykt status` · `ykt flow` · `ykt cert expiring` · `ykt data record\|inventory` | anywhere |

`ykt help <command>` for details; `ykt completion <shell>` for tab completion.

## Notable behaviors

- **One key, many domains.** Your daily FIDO2 SSH key (`~/.ssh/id_yk`) serves
  every domain; the *certificate* distinguishes them. `ykt setup ssh` wires up
  `~/.ssh/config` so `ssh web1` connects to the FQDN with the right cert (and
  `ssh add --address <ip>` pins an IP while keeping the FQDN for verification).
- **Carry only the key.** When a domain reserves an `ssh_cert_slot`,
  `cert install` also stashes the SSH certificate and the `id_yk` key stub into
  spare PIV slots on the daily key (as X.509 carrier objects). On a fresh
  machine, insert the key and run `ykt setup key` — it reads them back, writes
  `~/.ssh`, and wires the config. No files to bring; reading needs no PIN, only
  the key. (An SSH certificate can't live in the FIDO2 applet, so it rides in
  PIV instead — same physical key.)
- **Firmware-adaptive keys.** `init user` picks `ed25519-sk` resident on
  firmware ≥ 5.2.3, `ecdsa-sk` non-resident below — each key used to its fullest.
- **One domain per host** by default (`init host`/`remote install`); `--multi`
  opts in with a shared-principal warning. Both paths write the same
  `/etc/ssh/sshd_config.d/20-ykt.conf` + `/etc/ssh/ykt_user_ca.pub`.
- **Break-glass:** `init host --break-glass <pubkey>` appends an offline
  emergency key to the recovery account's `authorized_keys`; disabling password
  auth is refused without one (or an explicit console-access ack). See
  [RECOVERY.md](RECOVERY.md).
- **Renewals & revocation:** short user-cert lifetimes are the revocation story;
  `ykt cert revoke <domain> <serial>` writes a KRL, pushed by `remote install` /
  `init host`. `ykt cert expiring` lists what's due.

## The signing rhythm (quarterly, ~15 min)

1. Pull queued requests (git, if you use the two-operator model).
2. `ykt cert expiring` — anything within 3 weeks gets re-queued (`init user --keep`).
3. Insert your anchor → `ykt cert sign a1` (PIN once, touch per signature; verify
   remote-request fingerprints out-of-band before confirming).
4. Distribute certs (public — any channel) and `ykt cert install` / `remote install`.
5. Unplug the anchor, put it away.

## Security notes

- **Public vs. private.** CA public keys, certs, KRLs, and the ledger are public
  material (safe to commit in a *private* fork). **PINs, PUKs, and the
  break-glass private key never go in git** — paper record or a password vault.
- **The private CA keys never leave the YubiKey.** A host compromise during a signing
  session can *use* the CA to mint bounded, revocable certs while the card is
  inserted and unlocked, but cannot *extract* it. Consider `touch-policy=always`
  and/or a clean signing machine if that risk matters to you.
- **Keep out-of-band access** (provider console / IPMI / physical) on any host
  where you disable password auth, and keep the second anchor off-site.

## Development

From the repo root: `make check` (fmt + vet + test), `make lint`
(golangci-lint), `make build`, `make cross` (windows). CI runs a secret scan +
lint + cross-platform build/test on every push; Dependabot watches Go modules
and Actions; releases are cut automatically by release-please from Conventional
Commits. See [INSTALL.md](INSTALL.md) for per-OS dependencies and
[CONTRIBUTING.md](CONTRIBUTING.md) to get started.

## Layout

```
config.toml     domains → slots → patterns → serials → anchors (your data)
inventory.toml  your machines
pub/            CA public keys, client-CA certs, attestations, @cert-authority, KRLs
queue/          pending signing requests (.pub/.csr); done/ after signing
dist/           signed certificates awaiting delivery
index/          issuance ledger, one TSV per domain
<anchor>.json   anchor record (serial, timestamp, per-domain fingerprints)
```

Private keys never exist in this tree, or anywhere outside YubiKey hardware. If
a command ever seems to want a private key as input, the design is being
violated — stop.

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). PR titles follow
[Conventional Commits](https://www.conventionalcommits.org/); releases and the
changelog are automated. Please be kind ([Code of Conduct](CODE_OF_CONDUCT.md)).

## Security

Report vulnerabilities privately via a
[GitHub Security Advisory](https://github.com/RawSocketLabs/ykt/security/advisories/new),
not a public issue. See [SECURITY.md](SECURITY.md) for the policy and threat model.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in this work, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.
