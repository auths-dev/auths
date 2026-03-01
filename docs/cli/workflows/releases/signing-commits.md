# Signing Commits

Every commit you push can carry a cryptographic signature that proves it came from you. This page covers how to configure Git to sign commits automatically with Auths, how to verify them locally, and how to enforce verification in CI with [`auths verify-commit`](../../commands/primary.md#auths-verify).

## Prerequisites

- Auths identity initialized (`auths id init-did`) — see [Single Device Workflow](../single-device.md)
- `auths-sign` in your PATH (`cargo install --path crates/auths-cli` or `brew install auths`)

## 1. Configure Git

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program auths-sign
git config --global user.signingKey "auths:main"
git config --global commit.gpgSign true
```

Replace `main` with your key alias (`auths key list` to check).

## 2. Unlock your key

Auths signs through the agent daemon. Unlock once per session and all subsequent commits sign automatically:

```bash
auths agent start
auths agent unlock --key main
```

## 3. Sign commits

With `commit.gpgSign true` set, signing is automatic:

```bash
git commit -m "your message"
```

To sign a one-off commit without the global setting:

```bash
git commit -S -m "your message"
```

## 4. Verify locally

```bash
auths verify-commit HEAD
```

Or verify a specific commit:

```bash
auths verify-commit <hash>
```

See [`auths verify-commit`](../../commands/primary.md#auths-verify) for full output options including `--json`.

## 5. Set up the allowed_signers file

`auths verify-commit` and `git log --show-signature` both require an `allowed_signers` file that maps email addresses to public keys.

### Generate it

```bash
auths git allowed-signers --output .auths/allowed_signers
```

This creates a file in the format Git expects:

```
you@example.com ssh-ed25519 AAAA... main
```

!!! warning "Format matters"
    The email principal must appear first. A file containing only `ssh-ed25519 AAAA...` (no email) will cause **"incorrect signature"** errors even though the key is correct. Always use `auths git allowed-signers` to generate this file rather than exporting the key manually.

### Configure Git to use it

```bash
git config --global gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers
```

Or commit it to the repo for team and CI use:

```bash
git add .auths/allowed_signers
git commit -S -m "Add allowed signers"
```

### Add teammates

Each developer generates their own entry and adds it to the file:

```bash
# Teammate runs on their machine:
auths git allowed-signers

# Output (append to .auths/allowed_signers):
# teammate@example.com ssh-ed25519 AAAA...
```

## Connection to `auths verify-commit`

[`auths verify-commit`](../../commands/primary.md#auths-verify) is the underlying command that both local verification and CI use. It:

1. Reads the SSH signature embedded in the Git commit object
2. Looks up the signer's email against the `--allowed-signers` file
3. Verifies the signature cryptographically using `ssh-keygen`

```bash
# Local
auths verify-commit HEAD --allowed-signers .auths/allowed_signers

# CI (via auths-verify-action)
auths verify-commit --allowed-signers .auths/allowed_signers --json <range>
```

The `--json` flag is used by the [GitHub Actions integration](github-actions.md) to parse per-commit results.

## Enforcing in CI

Use the [`bordumb/auths-verify-action`](https://github.com/auths-dev/auths-verify-action) to block PRs with unsigned commits:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0

- uses: bordumb/auths-verify-action@v1
  with:
    allowed-signers: '.auths/allowed_signers'
    fail-on-unsigned: 'true'
```

The action runs `auths verify-commit` across the PR's commit range, writes a results table to the GitHub Step Summary, and fails the check if any commit is unsigned or unverifiable.

---

## Troubleshooting

### "Incorrect signature" on a signed commit

The signature exists but verification fails. Almost always caused by a malformed `allowed_signers` file.

**Check the file format:**

```bash
cat .auths/allowed_signers
```

It must start with the signer's email:

```
# Correct
you@example.com ssh-ed25519 AAAA...

# Wrong — missing email principal
ssh-ed25519 AAAA...
```

**Fix:** regenerate with `auths git allowed-signers` instead of `auths key export`.

**Also check** that the email in the file matches `git config user.email` exactly.

---

### Passphrase with special characters rejected

Shell metacharacters (`$`, `!`, `&`) in passphrases are expanded before Auths sees them.

```bash
# Wrong — $ gets interpreted by the shell
auths agent unlock --key main --passphrase MyPass$1!

# Correct — single quotes pass the string literally
auths agent unlock --key main --passphrase 'MyPass$1!'
```

---

### "No signature found" in CI

The commit was never signed. Verify your local git config is correct:

```bash
git config user.signingKey   # should be auths:<alias>
git config commit.gpgSign    # should be true
git config gpg.ssh.program   # should be auths-sign
```

Then re-sign and force-push:

```bash
# Single commit
git commit --amend --no-edit -S
git push --force-with-lease

# Multiple commits
git rebase HEAD~<N> --exec 'git commit --amend --no-edit -S'
git push --force-with-lease
```

---

### "Shallow clone" error in CI

```
Shallow clone detected. Commit verification requires full git history.
```

Add `fetch-depth: 0` to your checkout step:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
```

---

### Key alias not found

```
No cached pubkey for alias 'main'
```

The alias in `user.signingKey` doesn't match any stored key.

```bash
auths key list                              # see what aliases exist
git config --global user.signingKey "auths:<correct-alias>"
```

---

## Next steps

- [`auths verify-commit` reference](../../commands/primary.md#auths-verify)
- [GitHub Actions integration](github-actions.md)
- [Multi-device signing](../multi-device/index.md) — sign from multiple machines with one identity
- [Commit signing troubleshooting](../../troubleshooting/commit-signing.md) — agent failures, keychain issues
