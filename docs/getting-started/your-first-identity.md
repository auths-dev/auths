# Your First Identity

Create a cryptographic identity, store it in your platform keychain, and view your DID.

## Prerequisites

- Auths installed ([Installation](install.md))
- Git 2.34+ (`git --version`)

## Run the setup wizard

```bash
auths init --profile developer
```

The wizard walks you through five steps:

1. **Check prerequisites** -- verifies keychain access and Git version
2. **Set up identity** -- generates an Ed25519 keypair and derives a `did:keri` identity
3. **Link device** -- authorizes your current machine via a signed device attestation
4. **Configure Git** -- sets `gpg.format=ssh`, `gpg.ssh.program=auths-sign`, and `commit.gpgSign=true`
5. **Health check** -- runs `auths doctor` to verify everything works

You will be prompted for:

- A **key alias** (default: `main`) -- the name used to look up your key in the keychain
- A **passphrase** -- protects your private key at rest
- **Git signing scope** -- global (all repos) or local (current repo only)
- **Platform verification** -- optionally link a GitHub account to your identity

!!! warning "Remember your passphrase"
    There is no recovery mechanism. Write it down or use a password manager.

### Non-interactive mode

For scripted setups, skip all prompts:

```bash
auths init --profile developer --non-interactive
```

This uses sensible defaults: key alias `main`, global Git signing, and automatic registry registration.

## What just happened

After `auths init` completes, three things exist on your machine:

| Artifact | Location | Purpose |
|----------|----------|---------|
| Encrypted private key | Platform keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager) | Signs commits and attestations |
| Identity repository | `~/.auths` (a bare Git repo) | Stores your identity document, device attestations, and key event log under Git refs |
| Git config entries | `~/.gitconfig` (global) or `.git/config` (local) | Tells Git to use `auths-sign` for commit signing |

## View your identity

```bash
auths status
```

```
Identity:   did:keri:EAbcd1234...
Devices:    1 linked
```

For full details including the storage ID and metadata:

```bash
auths id show
```

```
Identity: did:keri:EAbcd1234...
Storage ID (RID): EAbcd1234
```

## View your keys

```bash
auths key list
```

```
Stored keys:
- main
```

## Run a health check

If anything looks wrong, the doctor command checks every prerequisite and prints an exact fix for each failure:

```bash
auths doctor
```

```
[ok] Git installed: 2.43.0
[ok] ssh-keygen installed
[ok] Git signing config
[ok] System keychain: macOS Keychain (accessible)
[ok] Auths identity: 1 key(s) found

Summary: 5 passed, 0 failed
All checks passed! Your system is ready.
```

## Next: Signing Commits

Your identity is ready. Continue to [Signing Commits](signing-commits.md) to make your first signed commit.
