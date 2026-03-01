# Replacing GPG Commit Signing with Auths

This guide walks you through migrating from GPG commit signing to Auths's SSH-based signatures. Auths provides better key management, multi-device support, and simpler key rotation.

## Why Migrate?

### GPG Limitations

- **Key management complexity**: GPG keys require manual backup, synchronization across devices, and complex trust models
- **No native multi-device support**: Copying GPG keys between devices is error-prone and reduces security
- **Key rotation is painful**: Rotating a GPG key means losing verification history unless you carefully manage transitions
- **Web of Trust confusion**: GPG's trust model is often misunderstood and underutilized

### Auths Advantages

- **Identity-based signing**: Sign commits with your Auths identity, not individual keys
- **Multi-device support**: Link multiple devices to one identity, all signatures trace back to you
- **Simple key rotation**: Rotate keys while maintaining identity continuity
- **Attestation chain**: Cryptographic proof linking devices to identities
- **Modern tooling**: Built for Git workflows and CI/CD pipelines

## Prerequisites

1. **Git 2.34 or later** (required for SSH signature support)

   ```bash
   git --version
   # Should be 2.34.0 or higher
   ```

2. **Auths CLI installed**

   ```bash
   # Install auths (adjust for your package manager)
   cargo install auths_cli

   # Verify installation
   auths --version
   ```

3. **OpenSSH with ssh-keygen** (for signature verification)

   ```bash
   ssh-keygen -?
   # Should show help output
   ```

4. **Existing Auths identity** (or create one)

   ```bash
   # Check if you have an identity
   auths id show

   # Or create a new identity
   auths id init --metadata-file metadata.json --local-key-alias my-identity
   ```

## Step-by-Step Migration

### Step 1: Export Your Auths Key for Git Signing

Export your Auths identity's public key in SSH format:

```bash
# Get your current signing key
auths key list

# Export the key in SSH format (replace 'my-identity' with your key alias)
auths key export --alias my-identity --format ssh > ~/.ssh/auths_signing.pub
```

### Step 2: Configure Git to Use SSH Signatures

Tell Git to use your Auths key for commit signing:

```bash
# Enable SSH signing (instead of GPG)
git config --global gpg.format ssh

# Point to your Auths SSH key
git config --global user.signingkey ~/.ssh/auths_signing.pub

# Enable automatic signing (optional but recommended)
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

### Step 3: Set Up Allowed Signers File

Create an allowed signers file for verification:

```bash
# Create the .auths directory
mkdir -p .auths

# Add your public key to allowed signers
echo "your-email@example.com $(cat ~/.ssh/auths_signing.pub)" > .auths/allowed_signers

# Configure Git to use it for verification
git config --global gpg.ssh.allowedSignersFile .auths/allowed_signers
```

The allowed signers file format is:
```
# One entry per line: principal namespaces key-type key-data
user@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

### Step 4: Test Signing a Commit

Create a test commit to verify signing works:

```bash
# Make a test commit
echo "test" >> test.txt
git add test.txt
git commit -m "test: verify Auths signing works"

# View the signature
git log --show-signature -1
```

You should see output like:
```
Good "git" signature for your-email@example.com with ED25519 key SHA256:...
```

### Step 5: Verify with Auths

Use Auths's verification command for detailed results:

```bash
# Verify the HEAD commit
auths verify-commit

# Verify with JSON output
auths verify-commit --json

# Verify a specific commit
auths verify-commit abc1234
```

## Team Setup

### Shared Allowed Signers File

For team projects, maintain a shared allowed signers file in the repository:

```bash
# Create team allowed signers file
mkdir -p .auths

# Add team members' public keys
cat >> .auths/allowed_signers << 'EOF'
alice@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
bob@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
charlie@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
EOF

# Commit to repository
git add .auths/allowed_signers
git commit -m "chore: add team signing keys to allowed signers"
```

### CI/CD Integration

Add the Auths verify action to your GitHub workflow:

```yaml
# .github/workflows/verify-commits.yml
name: Verify Commits

on:
  pull_request:
  push:
    branches: [main, develop]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Required to access commit history

      - name: Verify commit signatures
        uses: ./.github/actions/verify-action
        with:
          allowed-signers: '.auths/allowed_signers'
          fail-on-unsigned: 'true'
```

### Key Rotation Workflow

When rotating keys, update the allowed signers file:

```bash
# 1. Rotate your Auths identity key
auths id rotate --alias my-identity

# 2. Export the new key
auths key export --alias my-identity-rotated --format ssh > ~/.ssh/auths_signing_new.pub

# 3. Update your Git config
git config --global user.signingkey ~/.ssh/auths_signing_new.pub

# 4. Add new key to allowed signers (keep old key for history)
echo "your-email@example.com $(cat ~/.ssh/auths_signing_new.pub)" >> .auths/allowed_signers

# 5. Commit the update
git add .auths/allowed_signers
git commit -m "chore: rotate signing key for your-email@example.com"
```

## Troubleshooting

### "Bad signature" Error

**Problem**: Git shows "Bad signature" when viewing commits.

**Solutions**:

1. Verify the key is in allowed signers:
   ```bash
   grep "your-email" .auths/allowed_signers
   ```

2. Check the allowed signers path is correct:
   ```bash
   git config gpg.ssh.allowedSignersFile
   ```

3. Ensure the email matches exactly:
   ```bash
   git config user.email
   # Must match the principal in allowed_signers
   ```

### Key Not in Allowed Signers

**Problem**: Verification fails with "no principal matched"

**Solution**: Add your public key to the allowed signers file:
```bash
# Get your SSH public key
cat ~/.ssh/auths_signing.pub

# Add to allowed signers
echo "your-email@example.com <paste-key-here>" >> .auths/allowed_signers
```

### GPG vs SSH Format Confusion

**Problem**: Git is still trying to use GPG

**Solution**: Ensure SSH format is configured:
```bash
# Check current format
git config gpg.format
# Should be "ssh"

# Set if needed
git config --global gpg.format ssh
```

### ssh-keygen Not Found

**Problem**: Verification fails with "OpenSSH required"

**Solution**: Install OpenSSH:
```bash
# macOS (usually pre-installed)
ssh-keygen -?

# Ubuntu/Debian
sudo apt install openssh-client

# Windows
# OpenSSH is included in Windows 10+
# Enable via Settings > Apps > Optional Features > OpenSSH Client
```

### Old Commits Show as Unverified

**Problem**: Commits signed before migration show as unverified.

**Explanation**: This is expected. Old GPG-signed commits require GPG for verification. You have two options:

1. Keep both verification methods active
2. Accept that history before migration won't verify with SSH

To keep GPG verification for old commits while using SSH for new ones, don't remove your GPG configuration entirely.

## Related Documentation

- [auths verify-commit CLI Reference](../../cli/commands/primary.md#auths-verify)
- [Auths Identity Management](../../concepts/identity/index.md)
- [Key Rotation Guide](../../concepts/key-rotation.md)

## Getting Help

If you encounter issues not covered here:

1. Check the [Auths GitHub Issues](https://github.com/auths/auths/issues)
2. Search existing discussions
3. Open a new issue with:
   - Your Git and Auths versions
   - The exact error message
   - Steps to reproduce
