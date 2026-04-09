# Auths

[![CI](https://github.com/auths-dev/auths/actions/workflows/ci.yml/badge.svg)](https://github.com/auths-dev/auths/actions/workflows/ci.yml)
[![Verify Commits](https://github.com/auths-dev/auths/actions/workflows/verify-commits.yml/badge.svg)](https://github.com/auths-dev/auths/actions/workflows/verify-commits.yml?query=branch%3Amain+event%3Apush)

[![Verified with Auths](https://img.shields.io/badge/identity-verified%20with%20auths-brightgreen)](https://auths.dev)

<!-- Auths Verification Badge (renders in HTML contexts, not on GitHub) -->
<!-- <auths-verify repo="https://github.com/auths-dev/auths" mode="badge" size="md"></auths-verify> -->
<!-- <script type="module" src="https://unpkg.com/@auths-dev/verify@0.3.0/dist/auths-verify.mjs"></script> -->

Cryptographic identity and signing for software supply chains.

No central authority. No CA. No server. Just Git and cryptography.

## Quick Start

```bash
brew tap auths-dev/auths-cli
brew install auths
auths init                       # create your identity
auths sign ./release.tar.gz      # sign an artifact
auths verify ./release.tar.gz    # verify it
```

## Install

Homebrew:
```bash
brew tap auths-dev/auths-cli
brew install auths
```

Install from source:
```bash
cargo install --git https://github.com/auths-dev/auths.git auths_cli
```

This installs `auths`, `auths-sign`, and `auths-verify`.

## Walkthrough

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
| `auths signers sync` | Sync allowed-signers from registry |
| `auths signers list` | List allowed signers |
| `auths signers add` | Add a manual signer |

Run `auths --help` for full documentation.

---

## License

Apache 2.0
