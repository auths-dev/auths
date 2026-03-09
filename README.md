# Auths

Decentralized identity for individuals, AI agents, and their organizations.

One identity, multiple devices, Git-native storage.

## Install

Homebrew:
```bash
brew install auths-dev/auths-cli/auths
```

Install from source:
```bash
cargo install --git https://github.com/auths-dev/auths.git auths_cli
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

**Sync allowed-signers for Git verification**

```bash
auths signers sync
```

---

## Agent & Workload Identity

Auths treats AI agents and CI/CD runners as first-class identity holders — not borrowers of human credentials.

**Give an agent its own identity:**

```bash
# Create a dedicated agent identity
auths init --profile agent

# Issue a scoped, time-limited attestation from a human to the agent
auths attestation issue \
  --subject did:key:z6MkAgent... \
  --signer-type Agent \
  --capabilities "sign:commit,deploy:staging" \
  --delegated-by did:keri:EHuman... \
  --expires-in 24h
```

The agent now holds a cryptographic attestation chain traceable back to the human who authorized it. Every action the agent takes is signed under its own key, scoped to only the capabilities it was granted, and verifiable by anyone — offline, without contacting a central authority.

**How delegation works:** A human creates a signed attestation granting specific capabilities to an agent. The agent can further delegate a subset of those capabilities to sub-agents. Verifiers walk the chain back to the human sponsor. Capabilities can only narrow at each hop, never widen. See the [Delegation Guide](docs/getting-started/delegation.md) for a full walkthrough.

**Cloud integration via OIDC:** The [OIDC bridge](docs/architecture/oidc-bridge.md) verifies an agent's attestation chain and issues a standard JWT consumable by AWS STS, GCP Workload Identity, and Azure AD — no cloud provider changes required.

**MCP compatibility:** Auths attestations serve as the cryptographic identity layer behind MCP's OAuth-based authorization, providing verifiable delegation chains from human principals to AI agents.

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
