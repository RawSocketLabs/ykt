# Recovery & Break-Glass

The trust system is deliberately layered so that no single loss locks you out.
This is the map of what to do when something goes wrong.

## The three ways into a host

1. **Certificate** — normal path: your YubiKey-backed key + a valid user cert.
2. **Break-glass key** — an *offline* emergency keypair whose public half is
   installed on critical hosts (`init host --break-glass`). Used when the CA
   or your daily YubiKey is unavailable.
3. **Out-of-band console** — the VPS provider's web console, IPMI, or physical
   access. Always the final backstop; never disable it.

`init host` refuses to turn off password authentication unless a break-glass
key is installed **or** you explicitly confirm you have out-of-band access.

## Setting up break-glass (do this once, up front)

Generate an offline emergency key on an air-gapped or trusted machine and store
the private half in the safe / a second YubiKey — NOT on any host, NOT in git:

```
ssh-keygen -t ed25519 -C "ykt-break-glass" -f break-glass
# put break-glass (private) in the safe; break-glass.pub is what hosts trust
```

Install it while provisioning a host, before disabling passwords:

```
sudo ykt init host work --break-glass /path/to/break-glass.pub
```

It is appended (marked `ykt-break-glass`) to the recovery account's
`~/.ssh/authorized_keys` — the invoking sudo user by default, so you recover as
yourself even if root login is disabled. It is NOT a global `AuthorizedKeysFile`
directive, so it never affects other accounts and `remote install` can never strip
it. **Test a login with it before you rely on it**, then re-store the private
key offline.

## Scenarios

### A user cert expired and there's no signing scheduled
Short-lived certs (13 weeks) are the norm. If yours lapses: run a quick re-issue path
(`init user --keep` → `cert sign` → `cert install`), or
use the break-glass key to get in and fix things. Never let *both* operators'
certs expire in the same window — stagger renewals.

### Daily YubiKey lost or dead
1. Get in via the break-glass key (or provider console).
2. Revoke the lost key's certs: `ykt cert revoke <domain> <serial...>` then
   `ykt remote install <domain> --apply` (pushes the KRL everywhere).
3. Enroll a replacement key: `ykt init user <you> <domains...>` →
   `cert sign` → `cert install`.

### An anchor YubiKey dies (not stolen)
Nothing stops working — existing certs stay valid, and the *other* anchor can
sign. Provision a replacement with `init ca` (additive if the domain set is
partial) and add its public keys everywhere at leisure. Keep trusting the dead
anchor's keys until issued certs age out.

### An anchor is stolen / compromised
1. Remove that anchor's public keys from `pub/`, from every host's
   `ykt_user_ca.pub`, from `known_hosts` `@cert-authority` lines, and from
   Caddy client-CA lists.
2. Re-sign that anchor's outstanding certs with the surviving anchor.
3. PIN + touch policies make actual key *use* by a thief hard; extraction is
   impossible. Budget ~1 hour of re-signing.

### Locked out of a host (cert fails, no break-glass)
Use the provider console / IPMI / physical access. Then:
`sudo rm /etc/ssh/sshd_config.d/30-ykt-nopassword.conf && sudo systemctl reload sshd`
to re-enable passwords temporarily while you fix trust.

### CA material lost entirely (both anchors + any backups)
Full re-key: new anchors via `init ca`, replace the trust files on every
host/client/Caddy, re-issue all certs. Painful but bounded (~2 users + N hosts);
the scripted flows make it a half-day. This is the scenario the offline,
duplicated-anchor design exists to prevent — keep the second anchor off-site.

## Undo cheatsheet

| To undo | Command (on the host, sudo) |
|---|---|
| Password-auth off | `rm /etc/ssh/sshd_config.d/30-ykt-nopassword.conf && systemctl reload sshd` |
| All ykt trust | `rm /etc/ssh/sshd_config.d/20-ykt.conf && systemctl reload sshd` |
| A revocation | edit `index/<domain>.tsv` (remove the REVOKED column), re-run `revoke` for the rest |

## Non-negotiables

- The break-glass **private** key never touches a host or git.
- Never disable password auth on a host you can't reach out-of-band.
- Stagger the two operators' cert lifetimes so they never expire together.
- Keep the second anchor off-site.
