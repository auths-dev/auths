# Agent Identity

An agent identity is a `did:keri` identity provisioned for AI agents, CI bots, and automated workloads. Agents receive the same cryptographic identity format as humans but are always **delegated** from a human identity, **scoped** to specific capabilities, and designed for **headless** operation.

## Setup

### CLI

```bash
# Interactive -- prompts for capability selection
auths init --profile agent

# Non-interactive -- defaults to sign_commit only
auths init --profile agent --non-interactive

# Preview what would be created without doing anything
auths init --profile agent --dry-run
```

### Library API (Rust)

For programmatic provisioning in CI/CD pipelines and orchestration systems:

```rust
use auths_id::agent_identity::{
    provision_agent_identity, AgentProvisioningConfig, AgentStorageMode,
};

let config = AgentProvisioningConfig {
    agent_name: "ci-bot".to_string(),
    capabilities: vec!["sign_commit".to_string()],
    expires_in_secs: Some(86400), // 24 hours
    delegated_by: Some("did:keri:Ehuman123...".to_string()),
    storage_mode: AgentStorageMode::Persistent { repo_path: None },
};

let keychain = auths_core::storage::keychain::get_platform_keychain()?;
let bundle = provision_agent_identity(config, &passphrase_provider, keychain)?;

println!("Agent DID: {}", bundle.agent_did);
```

## Identity metadata

Agent metadata includes `"type": "ai_agent"` to distinguish agents from human identities:

```json
{
  "controller_did": "did:keri:Eagent...",
  "metadata": {
    "created_at": "2026-02-20T10:00:00Z",
    "setup_profile": "agent",
    "type": "ai_agent",
    "name": "ci-bot"
  }
}
```

Ephemeral agents additionally carry `"ephemeral": true`.

## Storage modes

| Mode | Use case | Path | Persistence |
|------|----------|------|-------------|
| **Persistent** | Long-running agents, CI servers | `~/.auths-agent` (configurable) | Survives restarts |
| **InMemory** | Stateless containers (Fargate, Docker, Lambda) | Temp directory | Process lifetime only |

### Persistent agent

```rust
AgentStorageMode::Persistent {
    repo_path: Some("/opt/agent/.auths".into()),
}
```

An `auths-agent.toml` config file is written to the repo directory.

### Ephemeral agent

```rust
AgentStorageMode::InMemory
```

No config file is written. The identity exists only in memory and is discarded when the process exits. This explicitly trades persistence for statelessness -- useful for containers that should leave no trace.

## Delegation and capabilities

Every agent identity is linked to a human authorizer:

```
Human (did:keri:Ehuman...) ──delegates──> Agent (did:keri:Eagent...)
         |                                      |
         |-- signer_type: Human                 |-- signer_type: Agent
         |-- capabilities: [*]                  |-- capabilities: [sign_commit]
         '-- delegated_by: None                 '-- delegated_by: did:keri:Ehuman...
```

### Capability attenuation

Agents can never hold more capabilities than their delegator. Each delegation step computes `C(agent) = C(human) ∩ C(granted)`, which is always a subset. This invariant holds through any chain depth:

```
C(0) ⊇ C(1) ⊇ C(2) ⊇ ... ⊇ C(n)
```

A compromised agent cannot grant itself new capabilities or escalate beyond what was granted at provisioning.

### Available capabilities

| Capability | Description |
|-----------|-------------|
| `sign_commit` | Sign Git commits |
| `sign_release` | Sign releases and tags |
| `manage_members` | Manage organization members |
| `rotate_keys` | Rotate identity keys |

## Policy enforcement

The policy engine provides signer-type predicates to enforce rules about who can sign:

```json
{
  "And": [
    "IsHuman",
    { "HasCapability": "sign_commit" },
    { "BranchMatches": "main" }
  ]
}
```

This requires a human signer for commits to `main`. Agents are restricted to feature branches.

For multi-signature workflows, `QuorumPolicy` supports mixed human/agent thresholds:

```json
{
  "min_approve": 2,
  "min_human_approve": 1,
  "max_reject": 0
}
```

This requires at least 2 approvals with at least 1 from a human -- an agent alone cannot satisfy it.

See [Policy](../policy.md) for the full predicate reference.

## Passphrase management

Agents need non-interactive passphrase access:

**Development/testing** -- Use the `AUTHS_PASSPHRASE` environment variable:

```bash
export AUTHS_PASSPHRASE="agent-passphrase"
```

!!! warning
    `AUTHS_PASSPHRASE` is suitable for development and testing only. Store the value in CI secrets, never hardcode it.

**Production** -- Implement the `PassphraseProvider` trait to integrate with your secrets manager:

```rust
use auths_core::signing::PassphraseProvider;
use zeroize::Zeroizing;

struct VaultPassphraseProvider { /* ... */ }

impl PassphraseProvider for VaultPassphraseProvider {
    fn get_passphrase(&self, _prompt: &str)
        -> Result<Zeroizing<String>, auths_core::error::AgentError>
    {
        let secret = self.vault_client.read_secret(&self.path)?;
        Ok(Zeroizing::new(secret))
    }
}
```

The `Zeroizing<String>` wrapper ensures the passphrase is scrubbed from memory when dropped.

## Witness receipts

Agents can produce witness receipts stored as Git trailers, enabling independent verification that a witness observed the commit:

```
feat: automated release

Auths-Witness-Receipt: eyJ2IjoiS0VSSTEwSlNPTjAwMDAwMF8i...
```

Receipts sign the tree hash and parent hashes (not the commit SHA) to avoid a chicken-and-egg problem where embedding the receipt would change the hash.

See the [Governance Guide](../../agentic_identity.md#4-witness-receipt-verification) for the full verification flow.

## Revocation

### Revoking an agent

```bash
# Revoke by the agent's device DID
auths device revoke --device-did "did:key:z6MkAgent..."

# Verify revocation
auths device list
```

### Cascading revocation

Revoking the human who delegated the agent **automatically** invalidates the agent. The verification logic walks the delegation chain upward -- if any link is revoked, the entire chain fails.

```
Human Alice (REVOKED)
  '-- Agent CI-Bot     (automatically invalid)
        '-- Sub-Agent  (automatically invalid)
```

### Emergency freeze

```bash
auths emergency freeze
```

Freezes all identities and all delegated agents immediately.

See the [Revocation Playbook](../../agentic_identity.md#5-agent-revocation-playbook) for detailed procedures.

## API reference

| Type | Description |
|------|-------------|
| `AgentProvisioningConfig` | Configuration: name, capabilities, expiry, storage mode |
| `AgentStorageMode` | `Persistent { repo_path }` or `InMemory` |
| `AgentIdentityBundle` | Result: agent DID, key alias, attestation, repo path |
| `AgentProvisioningError` | Error variants for each failure mode |
| `provision_agent_identity()` | Main entry point for provisioning |

See the [full API reference](../../agentic_identity.md#6-api-reference) for signatures and field details.
