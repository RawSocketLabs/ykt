# Security Policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Instead, open a private report via GitHub Security Advisories:

➡️ **https://github.com/RawSocketLabs/ykt/security/advisories/new**

Include as much as you can: affected version (`ykt --version`), a description of
the issue, reproduction steps, and impact. We aim to acknowledge within a few
business days and will coordinate a fix and disclosure timeline with you. We're
happy to credit reporters who want it.

## Supported versions

ykt is pre-1.0. Security fixes land on the latest released minor version; please
upgrade to the newest release before reporting. Once 1.0 ships, this section
will document the supported range.

## Scope & threat model

ykt is an **offline** certificate authority: the CA private keys are generated
on YubiKeys and never leave the hardware. Useful context for reports:

- **In scope:** anything that could expose a private key, mint a certificate
  without the intended touch/PIN, bypass revocation (KRL), silently corrupt
  trust material, cause `ykt` to trust an attacker-supplied CA, or leak secrets
  into git/logs/argv.
- **The design already accepts:** a host compromised *during* a signing session,
  while an unlocked anchor is inserted, can *use* the CA to mint bounded,
  revocable certificates — it cannot *extract* the key. Mitigations (touch
  policy, a clean signing machine) are documented in the README. Reports that
  deepen or bypass these bounds are welcome.
- **Out of scope:** physical attacks requiring possession of an unlocked
  YubiKey plus its PIN; issues in third-party dependencies (report upstream, but
  do tell us so we can pin/patch).

## Verifying releases

Release binaries are checksummed, keyless-signed with [cosign](https://github.com/sigstore/cosign)
(recorded in the Sigstore transparency log), carry an SPDX SBOM, and have SLSA
build provenance. To verify a downloaded binary:

```
# checksum
sha256sum -c ykt-linux-amd64.sha256

# cosign signature (identity = the release workflow)
cosign verify-blob ykt-linux-amd64 \
  --bundle ykt-linux-amd64.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/RawSocketLabs/ykt/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# build provenance (needs the gh CLI)
gh attestation verify ykt-linux-amd64 --repo RawSocketLabs/ykt
```

## Handling secrets

Never include PINs, PUKs, private keys, or `~/.ssh` private material in a report.
Public CA keys, certificates, KRLs, and command output are fine.
