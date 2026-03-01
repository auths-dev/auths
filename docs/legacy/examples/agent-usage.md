# Agent Usage

Using Auths with automation, scripts, and AI agents.

## Quick Start (CLI)

The fastest way to create an agent identity:

```bash
# Interactive setup
auths init --profile agent

# Non-interactive with defaults
auths init --profile agent --non-interactive

# Preview without creating anything
auths init --profile agent --dry-run
```

## Provisioning API (Rust)

For programmatic agent provisioning (CI/CD pipelines, orchestration systems):

### Persistent Agent

```rust
use auths_id::agent_identity::{
    provision_agent_identity, AgentProvisioningConfig, AgentStorageMode,
};

let config = AgentProvisioningConfig {
    agent_name: "ci-bot".to_string(),
    capabilities: vec!["sign_commit".to_string(), "sign_release".to_string()],
    expires_in_secs: Some(86400), // 24-hour attestation
    delegated_by: Some("did:keri:Ehuman123...".to_string()),
    storage_mode: AgentStorageMode::Persistent { repo_path: None }, // ~/.auths-agent
};

let keychain = auths_core::storage::keychain::get_platform_keychain()?;
let bundle = provision_agent_identity(config, &passphrase_provider, keychain)?;

println!("Agent DID: {}", bundle.agent_did);
println!("Key alias: {}", bundle.key_alias);
println!("Config: {}", bundle.repo_path.unwrap().display());
```

### Ephemeral Agent (Containers)

For stateless containers (Docker, Fargate, Lambda):

```rust
let config = AgentProvisioningConfig {
    agent_name: "ephemeral-worker".to_string(),
    capabilities: vec!["sign_commit".to_string()],
    expires_in_secs: Some(3600), // 1-hour lifetime
    delegated_by: Some("did:keri:Ehuman123...".to_string()),
    storage_mode: AgentStorageMode::InMemory, // No disk persistence
};

let bundle = provision_agent_identity(config, &passphrase_provider, keychain)?;
// bundle.repo_path is None — identity lives only in memory
```

## Non-interactive Signing

For automated environments, bypass the interactive passphrase prompt:

```bash
export AUTHS_PASSPHRASE="your-passphrase"
export AUTHS_KEYCHAIN_BACKEND=file  # For environments without a system keychain
```

Then sign normally:

```bash
git commit -m "automated commit"
```

!!! warning
    Store the passphrase securely (e.g., CI secrets, vault). Never hardcode it.
    The `AUTHS_PASSPHRASE` env var is MVP-only. For production, implement the
    `PassphraseProvider` trait to integrate with Vault, AWS Secrets Manager, etc.

!!! danger "Don't reuse your personal identity for agents"
    Always create a **separate identity** for agents and bots. If an agent's key is compromised, you want to revoke the agent's identity without affecting your personal signing. Sharing a key between a human and an agent also makes it impossible to distinguish who authored a commit.

## Verifying Agent Signatures

Agent signatures are verified identically to human signatures:

```bash
auths verify-commit HEAD
```

The output will show the agent's DID and `signer_type: Agent`, making it clear whether a human or agent signed the commit.

## Capability-Based Authorization

Agent attestations carry explicit capability grants and a `signer_type` field:

```rust
// The attestation created by provision_agent_identity:
Attestation {
    signer_type: Some(SignerType::Agent),
    delegated_by: Some("did:keri:Ehuman123..."),
    // ... capabilities embedded in attestation metadata
}
```

### Policy-Based Enforcement

Use the policy engine to enforce signer-type requirements:

```json
{
  "And": [
    "IsHuman",
    { "HasCapability": "sign_commit" },
    { "BranchMatches": "main" }
  ]
}
```

This policy requires a human signer for commits to `main`. Agents are restricted to feature branches.

### Mixed Human/Agent Quorum

```json
{
  "min_approve": 2,
  "min_human_approve": 1,
  "max_reject": 0
}
```

Requires 2 approvals with at least 1 from a human — an agent alone cannot approve.

## Short-Lived Attestations

For agents, use short expiration windows to limit blast radius:

```rust
let config = AgentProvisioningConfig {
    expires_in_secs: Some(3600), // 1-hour attestation
    // ...
};
```

Or via CLI:

```bash
auths device link \
  --identity-key-alias admin-key \
  --device-key-alias agent-key \
  --device-did "$AGENT_DID" \
  --expires-in-days 1
```

## Revoking an Agent

If an agent is compromised:

```bash
# Immediate revocation
auths device revoke --device-did "did:key:z6MkAgent..."

# Nuclear option: freeze everything
auths emergency freeze
```

Revoking the authorizing human cascades to all delegated agents automatically.

See [Agentic Identity & Governance](../agentic_identity.md#5-agent-revocation-playbook) for the full revocation playbook.
