# Your First Identity

Create a cryptographic identity, store it in your platform keychain, and view your DID.

!!! tip "Want proof before setup?"
    `auths demo` signs and verifies a sample artifact in-process — no identity, no
    prompts, no configuration. Run it any time to confirm the binary works.

## Prerequisites

- Auths installed ([Installation](install.md))
- Git 2.34+ (`git --version`)

## Run the setup wizard

```bash
auths init --profile developer
```

The wizard walks you through:

1. **Check prerequisites** -- verifies keychain access and Git version
2. **Set up identity** -- generates a P-256 keypair (the default; Ed25519 is available) and derives your permanent `did:keri` identity from it
3. **Configure Git** -- sets `gpg.format=ssh`, `gpg.ssh.program=auths-sign`, and `commit.gpgSign=true`
4. **Install the commit hook** -- a `prepare-commit-msg` hook (wired via `core.hooksPath`) stamps every commit with the identity trailers that make it verifiable
5. **Pin your trust root** -- if you run init inside a Git repository, your identity is pinned in that repo's `.auths/roots`

You will be prompted for:

- A **key alias** (default: `main`) -- the name used to look up your key in the keychain
- A **passphrase** -- protects your private key at rest (12+ characters, 3 of 4 character classes: lowercase, uppercase, digit, symbol)
- **Git signing scope** -- global (all repos) or local (current repo only)
- **Platform verification** -- optionally link a GitHub account to your identity

!!! warning "Remember your passphrase"
    There is no recovery mechanism. Write it down or use a password manager.

### Non-interactive mode

For scripted setups, skip all prompts:

```bash
auths init --profile developer --non-interactive
```

This uses sensible defaults: key alias `main` and global Git signing. Nothing is
published anywhere — registry registration is opt-in via `--register`.

## What just happened

After `auths init` completes, four things exist on your machine:

| Artifact | Location | Purpose |
|----------|----------|---------|
| Encrypted private key | Platform keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) | Signs commits and attestations |
| Identity repository | `~/.auths` (a bare Git repo) | Stores your identity document and key event log under Git refs |
| Git config entries | `~/.gitconfig` (global) or `.git/config` (local) | Tells Git to use `auths-sign` for signing and the auths hook for identity trailers |
| Commit hook | `~/.auths/githooks/prepare-commit-msg` | Stamps each commit with your identity, so `auths verify` knows whose key log to check |

## View your identity

```bash
auths status
```

```
Identity:    did:keri:EGOASorjKXRvDzrmdX7WdCTu-5sFxzvhdUkY8YJeQrP9
Key aliases: main, main--next-0
Witnesses:   none designated
Agent:      stopped
Devices:    this device (did:keri:EGOASorjKXRvDzrmdX7WdCTu-5sFxzvhdUkY8YJeQrP9)

Next steps:
  • Add another device
    → auths pair
  • Start the agent service
    → auths agent start
```

For machine-readable output including your current public key:

```bash
auths whoami --json
```

```json
{
  "success": true,
  "command": "whoami",
  "data": {
    "identity_did": "did:keri:EGOASorjKXRvDzrmdX7WdCTu-5sFxzvhdUkY8YJeQrP9",
    "device_did": "did:keri:EGOASorjKXRvDzrmdX7WdCTu-5sFxzvhdUkY8YJeQrP9",
    "public_key_hex": "026f1bef5d73c10fdef442fada6a1243a4445b4bf08088ee...",
    "curve": "p256"
  }
}
```

## View your keys

```bash
auths key list
```

```
Using key storage: encrypted-file
Stored keys:
- main
- main--next-0
```

`main--next-0` is your **pre-committed rotation key**. Auths promises your *next* key
in advance (a hash of it lives in your identity's event log), so even an attacker who
steals your current key cannot rotate your identity to a key they control. You never
use it directly — `auths id rotate` does.

## Run a health check

If anything looks wrong, the doctor command checks every prerequisite and prints an exact fix for each failure:

```bash
auths doctor
```

```
Auths Doctor (v0.1.2)
--------------------------

[✓] Git version: 2.39.5 (>= 2.34.0)
[✓] ssh-keygen installed: ssh-keygen found on PATH
[✓] Git user identity: Dev <dev@example.com>
[✓] Git signing config:
[✓] System keychain: macOS Keychain (accessible)
[✓] Auths directory: ~/.auths (valid git repository)
[✓] Auths identity: 2 key(s) found
[✓] Commit trailer hook: prepare-commit-msg hook installed
[✓] Repo hook override: no repo-local core.hooksPath override

Summary: all critical checks passed
```

Exit codes: `0` all checks pass · `1` a critical check failed (Auths is non-functional)
· `2` only advisory checks failed (functional, environment could be better).

## Next: Signing Commits

Your identity is ready. Continue to [Signing Commits](signing-commits.md) to make your first signed commit.
