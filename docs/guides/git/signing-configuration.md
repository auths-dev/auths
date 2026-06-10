# Signing Configuration

This guide covers how to configure Git to sign commits using Auths, the differences between global and per-repository configuration, and how signed commits appear on GitHub and GitLab.

## Prerequisites

- Auths identity initialized (`auths init`) -- see the quickstart guide
- `auths-sign` binary in your PATH (`cargo install --path crates/auths-cli` or install from a release)

Verify both are available:

```bash
auths --version
which auths-sign
```

## One-Command Setup

The fastest path is `auths init`, which creates your identity **and** configures Git signing in one step:

```bash
auths init
```

The interactive wizard prompts you to choose between global and per-repository signing scope. If you prefer non-interactive mode:

```bash
auths init --profile developer --non-interactive
```

This sets `gpg.format`, `gpg.ssh.program`, `user.signingKey`, `commit.gpgSign`, and
`core.hooksPath` automatically. The sections below explain each setting for manual
configuration or debugging.

## The Commit Hook (`core.hooksPath`)

Beyond the signature itself, a verifiable commit needs the `Auths-Id` /
`Auths-Device` identity trailers in its message — they tell `auths verify` whose key
event log to replay. `auths init` installs a `prepare-commit-msg` hook at
`~/.auths/githooks/` and points the global `core.hooksPath` at it. The hook:

- appends the identity trailers to every commit message (idempotent — amending never
  duplicates them)
- seeds the repo's committed `.auths/roots` trust file on your first signed commit
- chains to the repository's own `prepare-commit-msg` hook if one exists

!!! warning "Hook managers (husky, lefthook)"
    A repository that sets a *local* `core.hooksPath` bypasses the global auths hook —
    commits in that repo won't carry trailers. `auths doctor` detects this and tells
    you how to chain the auths hook from your hook manager's directory.

To backfill commits made before the hook existed, use `auths sign <ref>` — it amends
the commit (the SHA changes), so never backfill pushed commits without coordinating.

## Manual Git Configuration

### Global (all repositories)

```bash
git config --global gpg.format ssh
git config --global gpg.ssh.program auths-sign
git config --global user.signingKey "auths:main"
git config --global commit.gpgSign true
```

Replace `main` with your key alias. Check available aliases with:

```bash
auths key list
```

### Per-Repository

To sign commits only in a specific repository:

```bash
cd /path/to/your/repo
git config --local gpg.format ssh
git config --local gpg.ssh.program auths-sign
git config --local user.signingKey "auths:main"
git config --local commit.gpgSign true
```

Local configuration takes precedence over global. This is useful when you use different identities for personal and work repositories.

### What Each Setting Does

| Setting | Value | Purpose |
|---|---|---|
| `gpg.format` | `ssh` | Tells Git to use SSH signatures instead of GPG |
| `gpg.ssh.program` | `auths-sign` | Points Git to the Auths signing binary |
| `user.signingKey` | `auths:<alias>` | Identifies which key in your Auths keychain to use |
| `commit.gpgSign` | `true` | Automatically sign every commit |

## Agent Setup for Passphrase-Free Signing

The `auths-sign` binary uses a three-tier signing strategy:

1. **Agent signing** -- if the agent is running with keys loaded, signing happens without any passphrase prompt.
2. **Auto-start + load key** -- if the agent is not running, `auths-sign` auto-starts it, prompts for the passphrase once, and loads the key.
3. **Direct signing** -- if the agent approach fails, falls back to direct passphrase-based signing.

For the smoothest experience, start the agent once per session:

```bash
auths agent start
auths agent unlock --key main
```

After unlocking, all subsequent commits sign automatically via the agent without a passphrase prompt.

### Persistent Agent (Auto-Start on Login)

Install the agent as a system service so it starts automatically:

```bash
# macOS (launchd)
auths agent install-service

# Linux (systemd)
auths agent install-service
```

Preview the service file before installing:

```bash
auths agent install-service --dry-run
```

## Signing Commits

With `commit.gpgSign true` set, signing is automatic:

```bash
git commit -m "your message"
```

To sign a one-off commit without the global setting:

```bash
git commit -S -m "your message"
```

Signed commits carry an `Auths-Device` trailer with your device's `did:keri:` identifier — that trailer is how verifiers map the SSH signature back to your identity's key event log (KEL).

### Re-Signing Existing Commits

To re-sign the most recent commit:

```bash
auths sign HEAD
```

To re-sign a range of commits:

```bash
auths sign main..HEAD
```

This runs `git rebase --exec` under the hood to amend each commit with a fresh signature.

## How Verification Finds Your Key

Verification is KEL-native: `auths verify` reads the commit's `Auths-Device` trailer and resolves the signer's current key state from their key event log — no key list file to generate, distribute, or keep in sync. Keys are resolved from the local identity store by default, with opt-in remote resolution (`--remote` / `--oobi`) and explicit trust pinning (`auths trust pin`). See [Verifying Commits](verifying-commits.md).

> **Note on native Git verification:** Git's own `git verify-commit` / `git log --show-signature` rely on Git's `gpg.ssh.allowedSignersFile` mechanism, which Auths no longer generates. Use `auths verify` instead — it understands the identity model behind the signature, not just the raw SSH key.

## GitHub Signature Verification

GitHub displays a "Verified" badge on commits signed with SSH keys. For Auths-signed commits to show as verified on GitHub:

1. Export your public key:

    ```bash
    auths key export --key-alias main --passphrase '<your-passphrase>' --format pub
    ```

2. Add the key to your GitHub account under **Settings > SSH and GPG keys > New SSH key**, selecting **Signing Key** as the key type.

3. Ensure `git config user.email` matches the email on your GitHub account.

Commits pushed after this will show the "Verified" badge in the GitHub UI.

## GitLab Signature Verification

GitLab also supports SSH signature verification:

1. Export your public key with `auths key export --key-alias main --passphrase '<your-passphrase>' --format pub`.
2. Add it under **User Settings > SSH Keys**, checking the **Signing** usage type.
3. Ensure `git config user.email` matches your GitLab email.

## CI/CD Configuration

For CI pipelines that need to sign commits:

```bash
auths init --profile ci --non-interactive
```

This creates an ephemeral identity with a memory-backed keychain. Set the environment variable `AUTHS_KEYCHAIN_BACKEND=memory` in your CI environment.

### GitHub Actions Example

```yaml
steps:
  - uses: actions/checkout@v4
  - name: Setup Auths
    run: |
      auths init --profile ci --non-interactive
    env:
      AUTHS_KEYCHAIN_BACKEND: memory
```

### Headless / Non-Interactive Signing

For environments without a TTY, provide the passphrase via environment variable:

```bash
export AUTHS_PASSPHRASE="your-passphrase"
export AUTHS_KEYCHAIN_BACKEND=file
```

## Verifying Configuration

Check that your signing configuration is correct:

```bash
auths status
```

This shows your identity, agent status, and device summary. To check the raw Git configuration:

```bash
git config user.signingKey       # should be auths:<alias>
git config commit.gpgSign        # should be true
git config gpg.ssh.program       # should be auths-sign
git config gpg.format            # should be ssh
```

## Troubleshooting

### "No cached pubkey for alias '...'"

The alias in `user.signingKey` does not match any stored key.

```bash
auths key list                                    # see what aliases exist
git config --global user.signingKey "auths:<correct-alias>"
```

### "Agent running but no keys loaded"

The agent is running but keys have been cleared (restart, idle timeout, or manual lock).

```bash
auths agent unlock --key main
```

### "Cannot sign: no keys in agent and keychain is unavailable"

When Git calls `auths-sign` as a subprocess, the environment may restrict keychain access. Pre-load keys into the agent:

```bash
auths agent start
auths agent unlock --key main
```

### "failed to write commit object"

This is Git's generic error when `auths-sign` returned a non-zero exit code. The actual error appears in the lines above it. Check:

```bash
auths agent status
cat ~/.auths/agent.log
```

### Passphrase with special characters rejected

Shell metacharacters (`$`, `!`, `&`) are expanded before Auths sees them. Set the passphrase via the environment variable with single quotes:

```bash
AUTHS_PASSPHRASE='MyPass$1!' auths agent unlock --key main
```

### Local config overriding global

A local `.git/config` can override your global `~/.gitconfig`:

```bash
git config --local user.signingKey    # check for local override
git config --local --unset user.signingKey  # remove it
```

## Next Steps

- [Verifying Commits](verifying-commits.md) -- verify signatures locally and in CI
- [Team Workflows](team-workflows.md) -- trust pinning, organizations, and onboarding teammates
