# Quickstart: Identity in 5 Minutes

Get up and running with Auths in 5 minutes. By the end, you'll have a cryptographic identity, a linked device key, and signed your first Git commit.

## Prerequisites

- **Rust toolchain**: Rust 1.70+ with Cargo ([install](https://rustup.rs/))
- **Git 2.34+**: Required for SSH signature support
- **Platform keychain**: macOS Keychain, Windows Credential Manager, or file-based fallback

Check your versions:
```bash
rustc --version   # 1.70.0 or higher
git --version     # 2.34.0 or higher
```

## Step 1: Install Auths

Install from source:
```bash
cargo install --git https://github.com/auths-dev/auths auths_cli
```

This installs three binaries:
- `auths` — Main CLI for identity and key management
- `auths-sign` — Git SSH signing program
- `auths-verify` — Signature verification tool

Verify installation:
```bash
auths --version
```

## Step 2: Create Your Identity

Initialize a new identity with a controller key:

```bash
# Create a metadata file for your identity
cat > ~/auths-meta.json << 'EOF'
{
  "name": "My Identity",
  "email": "you@example.com"
}
EOF

# Initialize your identity
auths id init-did \
  --local-key-alias my-key \
  --metadata-file ~/auths-meta.json
```

You'll be prompted for a passphrase. This encrypts your private key in the platform keychain.

**Expected output:**
```
Generated new Ed25519 keypair
Storing key with alias: my-key
Enter passphrase for new key: ********
Confirm passphrase: ********
Key stored successfully in keychain
Identity initialized at ~/.auths
Controller DID: did:keri:E...
```

Verify your identity:
```bash
auths id show
```

## Step 3: Link a Device (Optional)

If you have multiple devices, link them to your identity:

```bash
# First, import or generate a key on the new device
# Then link it to your identity:

auths device link \
  --device-alias laptop-key \
  --expires-days 365
```

You'll be prompted for passphrases for both the controller key and device key.

View linked devices:
```bash
auths id show-devices
```

## Step 4: Sign Git Commits

Configure Git to use Auths for commit signing:

```bash
# Set SSH as the signature format
git config --global gpg.format ssh

# Use auths-sign as the signing program
git config --global gpg.ssh.program auths-sign

# Set your signing key
git config --global user.signingKey "auths:my-key"

# Enable automatic signing
git config --global commit.gpgSign true
```

Now make a signed commit:
```bash
cd your-project
echo "test" > test.txt
git add test.txt
git commit -m "My first signed commit"
```

When prompted, enter your key passphrase. The commit will be signed with your Auths identity.

## Step 5: Verify Signatures

Verify your commit signature:
```bash
# View signature info
auths verify-commit HEAD

# With JSON output for scripting
auths verify-commit HEAD --json
```

**Expected output:**
```json
{
  "valid": true,
  "commit": "abc1234...",
  "signer_did": "did:keri:E...",
  "signed_at": "2024-01-15T10:30:00Z"
}
```

For team verification, generate an allowed_signers file:
```bash
auths git allowed-signers --output .auths/allowed_signers
git config gpg.ssh.allowedSignersFile .auths/allowed_signers
```

## Step 6: Rotate Keys (When Needed)

Auths uses KERI (Key Event Receipt Infrastructure) which supports secure key rotation with pre-commitment. This means you can rotate to a new key without losing your identity.

```bash
# Rotate your identity key
auths id rotate --alias my-key

# Or specify a custom alias for the new key
auths id rotate --alias my-key --next-key-alias my-key-v2
```

You'll be prompted for your current passphrase. After rotation:
- Your DID (`did:keri:E...`) stays the same
- The new key is now active for signing
- Previous signatures remain valid (verified against historical key state)

View your key rotation history:
```bash
auths id show
```

## What You've Accomplished

- Created a cryptographic identity stored in your platform's secure keychain
- (Optionally) Linked device keys for multi-device access
- Configured Git to sign commits with your identity
- Verified commit signatures
- (Optionally) Rotated keys while preserving your identity

## Next Steps

- **[Threat Model](../security/threat-model.md)** — Understand what Auths protects and its trust boundaries
- **[Integration Guide](integration-guide.md)** — Use `auths-core` and `auths-verifier` as libraries
- **[Git Signing Guide](guides/git-signing.md)** — Deep dive into Git integration
- **[FAQ](faq.md)** — Common questions about Auths vs GPG, blockchain, etc.

## Quick Reference

```bash
# Identity management
auths id show              # Show your identity
auths id show-devices      # List linked devices
auths id rotate            # Rotate identity keys

# Key management
auths key list             # List stored keys
auths key export my-key    # Export public key

# Git signing
auths verify-commit        # Verify HEAD signature
auths git allowed-signers  # Generate team signers file

# Help
auths --help               # Full command reference
auths <command> --help     # Command-specific help
```

## Troubleshooting

**"auths-sign: command not found"**
```bash
# Ensure cargo bin is in PATH
export PATH="$HOME/.cargo/bin:$PATH"
```

**"Key not found"**
```bash
# List available keys
auths key list

# Check you're using the correct alias format
git config user.signingKey "auths:my-key"  # Note the auths: prefix
```

**Passphrase prompt not appearing**
Auths reads passphrases from `/dev/tty`. Run Git from an interactive terminal.

---

*For more detailed information, see the [Git Signing Guide](guides/git-signing.md).*
