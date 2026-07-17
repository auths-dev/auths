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
Identity:    did:keri:EBf2cE...
Key aliases: main
Witnesses:   none designated
Agent:       stopped
Devices:     none
```

### 3. Sign your first commit

`auths init` already configured Git commit signing (`gpg.format`, `commit.gpgsign`), so just commit:

```bash
git commit -m "My first signed commit"
```

Verify it:

```bash
auths verify HEAD
```

Output:
```
Commit a1b2c3d verified: signed by did:keri:EBf2cE...
```

That's it. Your commits are now cryptographically signed with your decentralized identity.

Want the whole loop in one shot? `auths demo` signs and verifies a sample artifact in under 30 seconds.

---

## How it works

Auths stores your identity and device attestations in a Git repository (`~/.auths` by default). Each device link is a cryptographically signed attestation stored as a Git ref.

- **Identity**: A `did:keri` derived from your P-256 key (Ed25519 is also supported; P-256 is the default because it is what the iOS Secure Enclave can hold)
- **Devices**: `did:key` identifiers linked via signed attestations
- **Keys**: Stored in your OS keychain (macOS Keychain, or encrypted file fallback)
- **Attestations**: Stored in Git refs under `refs/auths/`
- **Trust**: Your repo commits `.auths/roots` — the trusted root a clone anchors to — and your KEL travels to that repo's remote alongside your code, so `git clone && auths verify HEAD` works with no setup

No central server. No blockchain. Just Git and cryptography.

### What "verify" actually checks

Auths signs commits with a standard SSH signature (`ecdsa-sha2-nistp256`), so `auths verify` replays the signer's key history — their KEL — and checks the signature against the key that was valid **at signing time**, then confirms that key chains back to a root the repository pins.

Sigstore and GitHub can verify offline too. The difference is narrower than "offline vs online" and worth stating precisely: their offline path checks a signature against a **trust-root snapshot** you refreshed at some point, so a key rotation or revocation you have not downloaded is one you cannot see. A KEL carries its own rotation history, so key state verifies without refreshing a trust root. That matters most for **long-lived device keys**, which is Auths's model.

---

## Commands

| Command | Description |
|---------|-------------|
| `auths init` | Initialize identity (also configures Git signing) |
| `auths demo` | Sign + verify a sample artifact in 30 seconds |
| `auths sign <file>` | Sign an artifact |
| `auths verify <target>` | Verify a commit (e.g. `HEAD`) or signed artifact |
| `auths status` | Show identity and device overview |
| `auths whoami` | Print your identity DID |
| `auths pair` | Link another device via QR / short code |
| `auths trust pin` | Pin a trusted identity |
| `auths doctor` | Diagnose setup issues |
| `auths tutorial` | Interactive guided tour |

Run `auths --help` for full documentation, or `auths --help-all` to include advanced commands.

---

## License

Apache 2.0
