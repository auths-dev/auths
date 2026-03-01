# Agentic Identity & Governance

Enterprise guide for AI agent identity, capability scoping, policy enforcement, and revocation.

---

## 1. Overview

Agents — CI bots, AI assistants, automated pipelines — get their own cryptographic identity linked to a parent human or org identity. They are not second-class citizens: an agent's attestation is the same structure as a human's, carries the same verifiable chain of custody, and is stored the same way in Git.

What makes agents distinct is that they are always **delegated**, always **scoped**, and always **independently revocable**.

```
Human (did:keri:Ehuman...)
  └── Agent (did:keri:Eagent...)
        ├── capabilities: [sign_commit]        ← subset of delegator's capabilities
        ├── delegated_by: did:keri:Ehuman...   ← explicit link to authorizer
        └── signer_type: Agent                 ← distinguishable from human signers
```

Key properties:

- **Every action is attributable** — each commit, release, or org action signed by an agent carries a chain back to the human who authorized it
- **Capabilities are scoped at attestation time** — an agent can never hold more capabilities than its delegator granted
- **Revocation is independent** — revoking an agent doesn't touch the parent identity; revoking the parent cascades to all its agents automatically

---

## 2. Provisioning

### CLI (recommended)

```bash
# Interactive — prompts for capability selection
auths init --profile agent

# Non-interactive — defaults to sign_commit only
auths init --profile agent --non-interactive

# Preview what would be created without doing anything
auths init --profile agent --dry-run
```

`auths init --profile agent` creates an identity at `~/.auths-agent` and writes an `auths-agent.toml` config file with the agent DID, key alias, and capabilities.

### Rust API (programmatic provisioning)

For CI/CD pipelines and orchestration systems that need to provision agents at runtime:

**Persistent agent** (survives restarts, stores to disk):

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

println!("Agent DID:  {}", bundle.agent_did);
println!("Key alias:  {}", bundle.key_alias);
println!("Config at:  {}", bundle.repo_path.unwrap().display());
```

**Ephemeral agent** (stateless containers — Docker, Fargate, Lambda):

```rust
let config = AgentProvisioningConfig {
    agent_name: "ephemeral-worker".to_string(),
    capabilities: vec!["sign_commit".to_string()],
    expires_in_secs: Some(3600), // 1-hour lifetime
    delegated_by: Some("did:keri:Ehuman123...".to_string()),
    storage_mode: AgentStorageMode::InMemory, // no disk writes, no trace left behind
};

let bundle = provision_agent_identity(config, &passphrase_provider, keychain)?;
// bundle.repo_path is None
```

### Storage modes

| Mode | Use case | Persistence |
|------|----------|-------------|
| `Persistent { repo_path }` | Long-running agents, dedicated CI servers | Survives restarts |
| `InMemory` | Stateless containers, ephemeral jobs | Process lifetime only |

### Identity metadata

Agent metadata carries `"type": "ai_agent"` to distinguish agents from humans in audit trails and policy decisions:

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

!!! danger "Never reuse a personal identity for agents"
    Always provision a **separate identity** for each agent. If an agent key is compromised, you revoke the agent without touching your personal signing key. Sharing a key between a human and an agent also makes it impossible to distinguish who authored a commit.

---

## 3. Delegation and Capability Attenuation

Every agent is explicitly linked to a human authorizer at provisioning time. The `delegated_by` field in the attestation records this link and enables cascading revocation.

### Capability attenuation invariant

Agents can never hold more capabilities than their delegator. The system computes `C(agent) = C(delegator) ∩ C(granted)` at every delegation step. This invariant holds at any chain depth:

```
C(0) ⊇ C(1) ⊇ C(2) ⊇ ... ⊇ C(n)
```

A compromised agent cannot grant itself new capabilities or escalate beyond what was declared at provisioning.

### Available capabilities

| Capability | Allows |
|------------|--------|
| `sign_commit` | Sign Git commits |
| `sign_release` | Sign releases, tags, and tarballs |
| `manage_members` | Add/remove organization members |
| `rotate_keys` | Trigger identity key rotation |

Grant capabilities at provisioning:

```bash
# Via pair (interactive)
auths pair --capabilities sign_commit,sign_release

# Via device link (manual)
auths device link \
  --identity-key-alias admin-key \
  --device-key-alias agent-key \
  --device-did "$AGENT_DID" \
  --expires-in-days 1
```

### Short-lived attestations

For agents, always use short expiration windows to limit blast radius on compromise:

```bash
auths device link \
  --identity-key-alias admin-key \
  --device-key-alias agent-key \
  --device-did "$AGENT_DID" \
  --expires-in-days 1          # re-provision daily in CI
```

Expired attestations fail verification immediately, even without an explicit revocation event.

---

## 4. Policy Enforcement

Policies express organizational rules about who can sign what, in what context. The `IsAgent` and `IsHuman` predicates let you enforce signer-type requirements explicitly.

### Restrict `main` to humans only

```json
{
  "And": [
    "NotRevoked",
    "NotExpired",
    "IsHuman",
    { "HasCapability": "sign_commit" },
    { "BranchMatches": "main" }
  ]
}
```

Agents can sign commits on feature branches but are blocked from merging to `main` directly.

### Mixed human/agent quorum for releases

```json
{
  "min_approve": 2,
  "min_human_approve": 1,
  "max_reject": 0
}
```

Requires 2 approvals, at least 1 from a human. An agent alone cannot satisfy this policy — useful for release gating where you want automation to participate but not be the sole authority.

### Scope an agent to specific repos

```json
{
  "And": [
    "NotRevoked",
    "NotExpired",
    "IsAgent",
    { "HasCapability": "sign_commit" },
    { "RepoIn": ["org/frontend", "org/backend"] }
  ]
}
```

### Policy workflow

```bash
# Lint before committing the policy file
auths policy lint org-policy.json

# Compile (enforces size/depth limits, produces content hash for auditing)
auths policy compile org-policy.json

# Test against known allow/deny scenarios
auths policy test org-policy.json --tests org-tests.json

# Review changes before deploying
auths policy diff old-policy.json org-policy.json
```

See [Policy concepts](concepts/policy.md) and the [`auths policy` reference](cli/commands/advanced.md#auths-policy) for the full predicate list.

---

## 5. Passphrase Management

Agents need non-interactive passphrase access. Two approaches:

**Development and CI secrets** — use the `AUTHS_PASSPHRASE` environment variable:

```bash
export AUTHS_PASSPHRASE="agent-passphrase"
export AUTHS_KEYCHAIN_BACKEND=file  # for environments without a system keychain

git commit -m "automated commit"    # signs without a prompt
```

!!! warning
    Store the passphrase value in CI secrets (GitHub Actions secrets, GitLab CI variables, etc.). Never hardcode it in source.

**Production** — implement the `PassphraseProvider` trait to integrate with your secrets manager:

```rust
use auths_core::signing::PassphraseProvider;
use zeroize::Zeroizing;

struct VaultPassphraseProvider { /* vault client */ }

impl PassphraseProvider for VaultPassphraseProvider {
    fn get_passphrase(&self, _prompt: &str)
        -> Result<Zeroizing<String>, auths_core::error::AgentError>
    {
        let secret = self.vault_client.read_secret(&self.secret_path)?;
        Ok(Zeroizing::new(secret))
    }
}
```

The `Zeroizing<String>` wrapper scrubs the passphrase from memory when dropped. This pattern works with Vault, AWS Secrets Manager, GCP Secret Manager, or any secret store with a Rust client.

---

## 6. Witness Receipt Verification

When witness quorum is configured, agent attestations must include receipts from the required threshold of witness servers before they are accepted as valid.

### What witnesses sign

Witnesses sign the tree hash and parent hashes of a commit — not the commit SHA itself. This avoids the chicken-and-egg problem where embedding the receipt would change the hash being signed.

```
feat: automated release

Auths-Witness-Receipt: eyJ2IjoiS0VSSTEwSlNPTjAwMDAwMF8i...
```

### Verification flow

1. Verify the attestation signature (agent key → identity key chain)
2. Check that witness receipts meet the configured quorum threshold
3. Confirm the attestation has not expired or been revoked

```bash
# Verify a standalone attestation file
auths verify <attestation.json>

# Verify a commit (includes witness receipt check if configured)
auths verify-commit HEAD
```

Output on a passing agent signature:

```
Commit abc1234 is valid
  Signed by:   did:keri:Eagent...
  Signer type: Agent
  Delegated:   did:keri:Ehuman...
  Witnesses:   2/2 receipts verified
  Status:      VALID
```

---

## 7. Agent Revocation Playbook

### Planned decommission

When retiring an agent cleanly:

```bash
# Revoke the device attestation
auths device revoke \
  --identity-key-alias main \
  --device-did "did:key:z6MkAgent..."

# Confirm it no longer appears in the active list
auths id show-devices

# Verify it shows up with revocation noted (for audit trail)
auths id show-devices --include-revoked
```

Existing signatures made before revocation remain verifiable — they will show `Status: VALID (revoked after signing)` so history is preserved.

### Emergency: agent key compromised

```bash
# Step 1: Immediately revoke the agent
auths emergency revoke-device --device "did:key:z6MkAgent..." --yes

# Step 2: Generate an incident report
auths emergency report --file incident-$(date +%Y%m%d).json

# Step 3: Provision a replacement agent
auths init --profile agent --non-interactive

# Step 4: Update any CI secrets with the new agent's DID and passphrase
```

### Emergency: freeze everything

If you suspect broader compromise and need to stop all signing immediately:

```bash
auths emergency freeze --duration 24h
```

All signing operations across all devices and agents are disabled for the duration. To unfreeze early:

```bash
auths emergency unfreeze
```

### Cascading revocation

Revoking the human who authorized an agent **automatically** invalidates the agent. The verification engine walks the delegation chain upward — if any link is revoked, the entire chain fails:

```
Human Alice (REVOKED)
  └── Agent CI-Bot     ← automatically invalid
        └── Sub-Agent  ← automatically invalid
```

This means you never need to hunt down and revoke individual agents if the authorizing human is compromised — one revocation covers the whole tree.

---

## 8. API Reference

### Provisioning

| Symbol | Description |
|--------|-------------|
| `AgentProvisioningConfig` | Input: agent name, capabilities, expiry, delegator DID, storage mode |
| `AgentStorageMode` | `Persistent { repo_path: Option<PathBuf> }` or `InMemory` |
| `AgentIdentityBundle` | Output: `agent_did`, `key_alias`, `attestation`, `repo_path` |
| `AgentProvisioningError` | Typed error variants for each failure mode |
| `provision_agent_identity(config, passphrase_provider, keychain)` | Main provisioning entry point |

### Verification

| Function | Description |
|----------|-------------|
| `verify_chain(attestation)` | Verifies the full attestation chain from device key to identity key, checking revocation and expiry |
| `verify_with_keys(attestation, public_keys)` | Verifies against a pre-fetched key set — useful in WASM and FFI contexts where you can't do network lookups |
| `did_key_to_ed25519(did)` | Extracts the raw Ed25519 public key bytes from a `did:key` DID string |

These functions are exposed by the `auths-verifier` crate, which has minimal dependencies and supports FFI (`feature = "ffi"`) and WASM (`feature = "wasm"`) embedding. See the [SDKs overview](sdks/overview.md) for language-specific bindings.

### Attestation fields relevant to agents

| Field | Type | Description |
|-------|------|-------------|
| `signer_type` | `"Human"` \| `"Agent"` \| `"Workload"` | Distinguishes agent signatures in policy and audit |
| `delegated_by` | `did:keri:...` | DID of the human who authorized this agent |
| `capabilities` | `string[]` | Scoped capability grants |
| `expires_at` | ISO 8601 timestamp | Hard expiry; verification fails after this time |
| `device_public_key` | hex | Agent's Ed25519 public key |
| `identity_signature` | base64 | Signed by the parent identity key |
| `device_signature` | base64 | Signed by the agent's own key (dual signature) |
