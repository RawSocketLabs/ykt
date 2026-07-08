<!--
PR titles must follow Conventional Commits (e.g. "feat: add krl export").
The title becomes the squash-merge commit and drives the next version.
-->

## What & why

<!-- What does this change do, and why? Link any issue: "Closes #123". -->

## How it was tested

<!-- Commands run, hardware exercised (which YubiKey firmware), OSes. -->
- [ ] `make check` (fmt + vet + test) passes
- [ ] `make lint` passes
- [ ] Exercised on real hardware, or explained why not

## Checklist

- [ ] No secrets/PINs/private keys added (public CA material only)
- [ ] Docs updated if behavior or commands changed
- [ ] Conventional Commit PR title
