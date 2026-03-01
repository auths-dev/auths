# Identity

An Auths identity is a **stable cryptographic identifier** expressed as a `did:keri` DID:

```
did:keri:EBf7Y2pAnRd2cf6rbP7hbUkJvWMz3RRJPpL...
```

This is derived deterministically from an Ed25519 public key using Base64 encoding with the KERI `E` prefix. The same key always produces the same DID.

## Identity types

Auths supports two identity profiles, both using the same `did:keri` format and cryptographic foundation:

<div class="grid cards" markdown>

-   :material-account: **Human Identity**

    ---

    For developers. Interactive setup, platform keychain storage, Git signing. The root of trust for all delegation.

    [Human identities](human.md)

-   :material-robot: **Agent Identity**

    ---

    For AI agents, CI bots, and automated workloads. Headless provisioning, capability scoping, and revocation controls.

    [Agent identities](agent.md)

</div>

## What they share

Both identity types:

- Use `did:keri:E...` identifiers derived from Ed25519 keys
- Store keys in platform keychains (or encrypted file fallback)
- Sign commits via Git's native SSH signing interface
- Are verified by the same `auths-verifier` library
- Support key rotation via KERI Key Event Logs

## What's different

| | Human | Agent |
|---|---|---|
| **Setup** | Interactive (`auths init --profile developer`) | Headless API or `auths init --profile agent` |
| **Metadata `type`** | `"developer"` | `"ai_agent"` |
| **`signer_type`** | `Human` | `Agent` |
| **Storage** | `~/.auths` | `~/.auths-agent` (or in-memory) |
| **Delegation** | Root of trust | Always delegated from a human |
| **Capabilities** | Unrestricted | Scoped subset of delegator's |
| **Typical lifetime** | Years | Hours to months |
| **Passphrase** | Interactive prompt or cached | `AUTHS_PASSPHRASE` env var or `PassphraseProvider` trait |

## Identity vs. key

The identity (DID) and the key are related but distinct:

| | Identity | Key |
|---|---|---|
| **Format** | `did:keri:E...` | Ed25519 keypair |
| **Lifetime** | Permanent (survives rotation) | Rotatable |
| **Storage** | Git ref (`refs/auths/identity`) | Platform keychain |
| **Shared?** | Public (the DID) | Private (never leaves keychain) |

With KERI key rotation, you can replace the underlying key while keeping the same DID. The Key Event Log (KEL) records these transitions.

## Verification

Both human and agent signatures are verified identically:

```bash
auths verify-commit HEAD
```

The output shows the signer's DID and `signer_type`, making it clear whether a human or agent signed the commit.
