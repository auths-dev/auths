# Git Signing and Verification with Auths

This guide explains how to use Auths's Git signing tools (`auths-sign`, `auths-verify`) to sign and verify Git commits with your Auths identity.

## Overview

Auths provides three binaries for Git integration:
- **auths-sign**: A Git SSH signing program that signs commits with your Auths keys
- **auths-verify**: Verifies SSH signatures against allowed signers
- **auths** (with `git` subcommand): Manages allowed_signers files and hooks

## Prerequisites

1. **Install Auths CLI**:
   ```bash
   cargo install auths_cli
   ```

   This installs three binaries:
   - `auths` - Main CLI
   - `auths-sign` - Git signing program
   - `auths-verify` - Signature verification

2. **Git 2.34 or later** (required for SSH signatures):
   ```bash
   git --version
   # 2.34.0 or higher required
   ```

3. **An Auths identity with a stored key**:
   ```bash
   # Create identity if you don't have one
   auths id init --metadata-file metadata.json --local-key-alias my-key

   # Verify key exists
   auths key list
   ```

## Quick Setup (60 seconds)

Configure Git to use Auths for commit signing:

```bash
# 1. Set SSH as the signature format
git config --global gpg.format ssh

# 2. Set auths-sign as the signing program
git config --global gpg.ssh.program auths-sign

# 3. Set your signing key (auths:<alias>)
git config --global user.signingKey "auths:my-key"

# 4. Enable automatic signing
git config --global commit.gpgSign true
```

That's it! Your commits will now be signed with your Auths key.

## How It Works

### Signing Flow

When you run `git commit`:

1. Git calls `auths-sign -Y sign -n git -f <key_identifier> <buffer_file>`
2. `auths-sign` parses the key identifier (e.g., `auths:my-key`)
3. Prompts for your passphrase to unlock the key
4. Creates an SSHSIG signature of the buffer contents
5. Writes the signature to `<buffer_file>.sig`
6. Git embeds the signature in the commit

### Verification Flow

When verifying with `git log --show-signature`:

1. Git extracts the signature and data
2. Uses `ssh-keygen -Y verify` against the allowed_signers file
3. Reports whether the signature is valid

## Signing Commits

### Manual Signing

Sign a specific commit:
```bash
git commit -S -m "Signed commit message"
```

### Automatic Signing

With `commit.gpgSign = true`, all commits are signed automatically:
```bash
git commit -m "This will be signed automatically"
```

### Verifying Your Setup

Test that signing works:
```bash
# Make a test commit
echo "test" > test.txt
git add test.txt
git commit -m "test: verify signing works"

# Check the signature
git cat-file -p HEAD | grep "gpgsig"
```

## Verifying Commits

### Using Git's Built-in Verification

```bash
# View commit with signature status
git log --show-signature -1

# Verify all commits in a range
git log --show-signature main..HEAD
```

### Using auths-verify

The `auths-verify` binary provides direct signature verification:

```bash
# Verify a file signature
auths-verify file --file document.txt --signature document.txt.sig

# SSH-keygen compatible mode
auths-verify -Y verify -f allowed_signers -I user@example.com -n git -s commit.sig < data
```

### Using auths verify-commit

For detailed commit verification:
```bash
# Verify HEAD
auths verify-commit

# Verify specific commit
auths verify-commit abc1234

# JSON output for scripting
auths verify-commit --json
```

## Team Setup

### Generate Allowed Signers from Attestations

Use Auths's Git integration to generate an allowed_signers file from your identity's device attestations:

```bash
# Generate allowed_signers to stdout
auths git allowed-signers

# Write to file
auths git allowed-signers --output .auths/allowed_signers

# Configure Git to use it
git config gpg.ssh.allowedSignersFile .auths/allowed_signers
```

### Install Auto-Update Hooks

Install a post-merge hook that regenerates allowed_signers after pulls:

```bash
# Install the hook
auths git install-hooks

# Or specify custom paths
auths git install-hooks \
  --auths-repo ~/.auths \
  --allowed-signers-path .auths/allowed_signers
```

This creates `.git/hooks/post-merge` that runs:
```bash
auths git allowed-signers --output .auths/allowed_signers
```

### Team Workflow

For a team project:

1. **Each team member**: Create an Auths identity and link devices
2. **Repository maintainer**: Run `auths git allowed-signers` to generate team file
3. **Commit allowed_signers**: Track it in the repository
4. **Install hooks**: Each clone runs `auths git install-hooks`

```bash
# One-time setup per repository
auths git allowed-signers --output .auths/allowed_signers
git add .auths/allowed_signers
git commit -m "chore: add team allowed_signers"
git config gpg.ssh.allowedSignersFile .auths/allowed_signers
```

## Storage Layout Presets

Auths supports different storage layouts for ecosystem compatibility:

```bash
# Default Auths layout (refs/auths/*)
auths id init --preset default ...

# Radicle-compatible layout (refs/rad/*)
auths id init --preset radicle ...

# Gitoxide-compatible layout
auths id init --preset gitoxide ...
```

## Troubleshooting

### "error: cannot run auths-sign: No such file or directory"

**Cause**: `auths-sign` is not in your PATH.

**Solution**:
```bash
# Check if auths-sign is installed
which auths-sign

# If not found, reinstall
cargo install auths_cli --force

# Or add cargo bin to PATH
export PATH="$HOME/.cargo/bin:$PATH"
```

### Passphrase prompt not appearing

**Cause**: auths-sign reads passphrase from `/dev/tty`.

**Solution**: Run Git from a terminal with TTY access. This won't work in non-interactive environments without modification.

### "Bad signature" or "No principal matched"

**Cause**: The signing key isn't in allowed_signers.

**Solution**:
```bash
# Regenerate allowed_signers
auths git allowed-signers --output .auths/allowed_signers

# Verify your email matches
git config user.email
# The email/principal in allowed_signers must match
```

### Wrong key format in config

**Cause**: Using file path instead of auths: prefix.

**Solution**:
```bash
# Wrong
git config user.signingKey ~/.ssh/id_ed25519

# Correct for auths-sign
git config user.signingKey "auths:my-key-alias"
```

### Verification fails in CI

**Cause**: ssh-keygen or allowed_signers not available in CI.

**Solution**:
```yaml
# GitHub Actions example
steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0

  - name: Install Auths
    run: cargo install auths_cli

  - name: Verify commits
    run: |
      auths verify-commit --json || exit 1
```

## Configuration Reference

### Git Config Options

| Option | Value | Description |
|--------|-------|-------------|
| `gpg.format` | `ssh` | Use SSH signatures |
| `gpg.ssh.program` | `auths-sign` | Signing program |
| `user.signingKey` | `auths:<alias>` | Key identifier |
| `commit.gpgSign` | `true` | Auto-sign commits |
| `gpg.ssh.allowedSignersFile` | `.auths/allowed_signers` | Verification file |

### Key Identifier Format

The signing key format for auths-sign is: `auths:<key-alias>`

Examples:
- `auths:default` - Use key with alias "default"
- `auths:my-controller-key` - Use key with alias "my-controller-key"
- `auths:work-laptop` - Use key with alias "work-laptop"

### Allowed Signers File Format

```
# principal namespaces="git" key-type key-data
user@example.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
z6MkDID...@auths.local namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

## Related Commands

```bash
# Identity management
auths id init         # Create identity
auths id show         # Show identity details
auths id show-devices # List linked devices

# Key management
auths key list        # List stored keys
auths key export      # Export public key

# Git integration
auths git allowed-signers  # Generate allowed_signers
auths git install-hooks    # Install post-merge hook

# Verification
auths verify-commit   # Verify commit signatures
auths-verify          # Low-level signature verification
```

## See Also

- [Replacing GPG with Auths](replacing-gpg-with-auths.md) - Migration guide from GPG
- [Auths CLI Reference](../../cli/overview.md) - Full CLI documentation
- [Git SSH Signing Documentation](https://git-scm.com/docs/git-config#Documentation/git-config.txt-gpgformat)
