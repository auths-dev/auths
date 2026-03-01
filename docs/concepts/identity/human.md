# Human Identity

A human identity is the root of trust in Auths. It represents a developer across all their devices and is the starting point for all delegation chains.

## Setup

### Interactive (recommended)

```bash
auths init --profile developer
```

This walks you through:

1. **Prerequisites** -- Checks keychain access and Git version (2.34+ required for SSH signing)
2. **Identity creation** -- Generates an Ed25519 keypair, derives `did:keri:E...`, stores the key in your platform keychain
3. **Device linking** -- Links your current device via a signed attestation
4. **Git configuration** -- Sets `gpg.format=ssh`, `gpg.ssh.program=auths-sign`, and `commit.gpgsign=true`
5. **Health checks** -- Verifies the signing pipeline works end-to-end
6. **Shell completions** -- Optionally installs tab completion for your shell

### Non-interactive

```bash
auths init --profile developer --non-interactive
```

Uses sensible defaults. Useful for scripted provisioning of developer machines.

## Identity metadata

A human identity commit contains:

```json
{
  "controller_did": "did:keri:EBf...",
  "metadata": {
    "created_at": "2026-02-20T10:00:00Z",
    "setup_profile": "developer",
    "name": "Alice",
    "email": "alice@example.com"
  }
}
```

Metadata is informational -- it is not cryptographically bound to the DID and can be updated independently.

## Key storage

Human keys are stored in your platform's secure keychain:

| Platform | Backend |
|----------|---------|
| macOS | Security Framework (Keychain) |
| Linux | Secret Service (GNOME Keyring / KWallet) |
| Windows | Credential Manager |
| Fallback | Encrypted file (`~/.auths/keys/`) |

The key never leaves the keychain in plaintext. Signing operations decrypt the key in memory, use it, and zeroize the decrypted material immediately.

## Signing commits

Once set up, signing is automatic:

```bash
git commit -m "my signed commit"
```

Git calls `auths-sign` (configured as `gpg.ssh.program`), which:

1. Checks if an agent daemon has keys loaded (passphrase-free)
2. If not, prompts for your passphrase (cached for the session)
3. Decrypts the key, signs, and zeroizes the key material

## Multi-device

A human identity can span multiple devices. Each device gets its own `did:key` identifier, linked to the root `did:keri` identity via a signed attestation:

```
did:keri:Ehuman...  (your identity)
  ├── did:key:z6MkLaptop...   (laptop attestation)
  ├── did:key:z6MkPhone...    (phone attestation)
  └── did:key:z6MkCI...       (CI server attestation)
```

Link a new device:

```bash
auths device link \
  --identity-key-alias main \
  --device-key-alias laptop-key \
  --device-did "$DEVICE_DID"
```

See [Multi-Device workflows](../../cli/workflows/multi-device/index.md) for details.

## Delegation to agents

Human identities are the root of trust for agent delegation. When you provision an agent, the agent's attestation includes `delegated_by: did:keri:Ehuman...` and inherits a subset of your capabilities.

```bash
auths init --profile agent
```

See [Agent Identity](agent.md) for the full agent provisioning flow.

!!! danger "Don't reuse your personal identity for agents"
    Always create a **separate identity** for agents and bots. If an agent's key is compromised, you want to revoke the agent's identity without affecting your personal signing.

## Key rotation

KERI pre-rotation lets you replace your signing key while preserving your `did:keri` identity:

```bash
auths key rotate --alias main
```

Past signatures remain valid. The Key Event Log (KEL) records the transition. See [Key Rotation](../key-rotation.md).

## Revocation

If a device is lost or compromised:

```bash
# Revoke a specific device
auths device revoke --device-did "did:key:z6MkLost..."

# Emergency: freeze everything
auths emergency freeze
```

See [Key Compromise Recovery](../../security/key-compromise-recovery.md) for the full recovery procedure.
