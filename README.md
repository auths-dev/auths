# Auths

Decentralized identity for developers. One identity, multiple devices, Git-native storage.

## Install

Homebrew:
```bash
brew install bordumb/auths-cli/auths
```

Install from source:
```bash
cargo install --git https://github.com/bordumb/auths.git auths_cli
```

This installs `auths`, `auths-sign`, and `auths-verify`.

## Quick Start

### 1. Initialize your identity (30 seconds)

```bash
auths init
```

Follow the prompts. This creates your cryptographic identity and stores the key securely in your system keychain.

### 2. See what you created

```bash
auths status
```

Output:
```
Identity: did:keri:EBf...
Key Alias: controller
Devices: 1 linked

Ready to sign commits.
```

### 3. Sign your first commit

Configure Git to use Auths:

```bash
auths git setup
```

Now sign a commit:

```bash
git commit -S -m "My first signed commit"
```

Verify it:

```bash
auths verify-commit HEAD
```

Output:
```
Commit abc123 is valid
  Signed by: did:keri:EBf...
  Device: did:key:z6Mk...
  Status: VALID
```

That's it. Your commits are now cryptographically signed with your decentralized identity.

---

## What can you do with Auths?

**Link multiple devices to one identity**

```bash
# On your laptop
auths device link --device-did did:key:z6Mk...

# Now both devices can sign as the same identity
```

**Revoke a compromised device**

```bash
auths device revoke --device-did did:key:z6Mk...
```

**Verify any attestation**

```bash
auths verify attestation.json
```

**Export allowed-signers for Git verification**

```bash
auths git allowed-signers >> ~/.ssh/allowed_signers
```

---

## How it works

Auths stores your identity and device attestations in a Git repository (`~/.auths` by default). Each device link is a cryptographically signed attestation stored as a Git ref.

- **Identity**: A `did:keri` derived from your Ed25519 key
- **Devices**: `did:key` identifiers linked via signed attestations
- **Keys**: Stored in your OS keychain (macOS Keychain, or encrypted file fallback)
- **Attestations**: Stored in Git refs under `refs/auths/`

No central server. No blockchain. Just Git and cryptography.

---

## Commands

| Command | Description |
|---------|-------------|
| `auths init` | Initialize identity with guided setup |
| `auths status` | Show identity and device overview |
| `auths id show` | Display identity details |
| `auths device link` | Link a new device |
| `auths device revoke` | Revoke a device |
| `auths key list` | List stored keys |
| `auths verify` | Verify an attestation |
| `auths verify-commit` | Verify a signed commit |
| `auths git setup` | Configure Git for signing |
| `auths git allowed-signers` | Generate allowed-signers file |

Run `auths --help` for full documentation.

---

## License

Apache 2.0
