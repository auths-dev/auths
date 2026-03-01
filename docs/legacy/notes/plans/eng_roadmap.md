# Auths Engineering Roadmap: Top 10 Epics

---

## Epic 1: Typed Capability System

**Priority:** Critical | **Area:** Security | **Effort:** M

### Problem

Capabilities are stringly-typed throughout the attestation layer. While `CanonicalCapability` validates format in the policy engine, the core attestation creation path accepts raw strings. This means `sign_commit` vs `sign-commit` vs `signCommit` can all exist as distinct capabilities—a classic "capability injection" vector where typos create silent authorization bypasses.

### Theoretical Backing

Capability-based security (Dennis & Van Horn, 1966) requires that capabilities are *unforgeable tokens*, not arbitrary strings. Allowing free-form strings at the boundary means the security model degenerates into an ACL with no structural guarantees. The type system should enforce the principle of least authority (POLA) at compile time.

### Subtasks

#### 1.1 — Define a canonical capability registry enum

```rust
// crates/auths-core/src/capability.rs

use serde::{Deserialize, Serialize};
use std::fmt;

/// Well-known capabilities with compile-time guarantees.
///
/// Custom capabilities are supported via `Custom(CanonicalCapability)` but
/// must pass validation. Well-known variants prevent typo-squatting attacks
/// on security-critical operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    SignCommit,
    SignRelease,
    SignTag,
    ManageMembers,
    ManageDevices,
    ManagePolicy,
    ReadOnly,
    Delegate,
    #[serde(untagged)]
    Custom(ValidatedCustomCapability),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ValidatedCustomCapability(String);

impl ValidatedCustomCapability {
    const MAX_LEN: usize = 64;
    const PREFIX: &'static str = "x-";

    pub fn parse(raw: &str) -> Result<Self, CapabilityError> {
        let trimmed = raw.trim().to_lowercase();
        if !trimmed.starts_with(Self::PREFIX) {
            return Err(CapabilityError::MissingPrefix(trimmed));
        }
        if trimmed.len() > Self::MAX_LEN {
            return Err(CapabilityError::TooLong(trimmed.len()));
        }
        if !trimmed.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ':') {
            return Err(CapabilityError::InvalidChars(trimmed));
        }
        Ok(Self(trimmed))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CapabilityError {
    #[error("custom capabilities must start with 'x-', got: {0}")]
    MissingPrefix(String),
    #[error("capability exceeds 64 chars: {0}")]
    TooLong(usize),
    #[error("invalid characters in capability: {0}")]
    InvalidChars(String),
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SignCommit => write!(f, "sign_commit"),
            Self::SignRelease => write!(f, "sign_release"),
            Self::SignTag => write!(f, "sign_tag"),
            Self::ManageMembers => write!(f, "manage_members"),
            Self::ManageDevices => write!(f, "manage_devices"),
            Self::ManagePolicy => write!(f, "manage_policy"),
            Self::ReadOnly => write!(f, "read_only"),
            Self::Delegate => write!(f, "delegate"),
            Self::Custom(c) => write!(f, "{}", c.0),
        }
    }
}
```

#### 1.2 — Migration layer for existing string capabilities

```rust
// crates/auths-core/src/capability.rs

impl Capability {
    /// Parse a legacy string capability into the typed system.
    ///
    /// Maps known strings to well-known variants, treats unknown strings
    /// as custom capabilities (must have `x-` prefix after migration).
    pub fn from_legacy(s: &str) -> Result<Self, CapabilityError> {
        match s.trim().to_lowercase().as_str() {
            "sign_commit" | "sign-commit" | "signcommit" => Ok(Self::SignCommit),
            "sign_release" | "sign-release" | "signrelease" => Ok(Self::SignRelease),
            "sign_tag" | "sign-tag" | "signtag" => Ok(Self::SignTag),
            "manage_members" | "manage-members" => Ok(Self::ManageMembers),
            "manage_devices" | "manage-devices" => Ok(Self::ManageDevices),
            "manage_policy" | "manage-policy" => Ok(Self::ManagePolicy),
            "read_only" | "read-only" | "readonly" => Ok(Self::ReadOnly),
            "delegate" => Ok(Self::Delegate),
            other => Ok(Self::Custom(ValidatedCustomCapability::parse(other)?)),
        }
    }
}
```

#### 1.3 — Wire `Capability` through attestation creation and policy eval

Replace all `String` capability fields in `Attestation`, `EvalContext`, and `CompiledExpr::HasCapability` with `Capability`. The `CanonicalCapability` in `auths-policy` becomes a thin wrapper over `Capability`.

---

## Epic 2: Witness Network MVP

**Priority:** Critical | **Area:** Security | **Effort:** L

### Problem

The current `witness.rs` is a conversion layer for Git OIDs—it doesn't actually implement KERI's witness model. Without active witnesses, the entire system is vulnerable to **split-view attacks**: a malicious Git host can serve different KEL histories to different verifiers, and there is no mechanism to detect the fork.

### Theoretical Backing

KERI's security model relies on *duplicity detection* through witnesses. Witnesses are lightweight—they don't need BFT consensus. Each witness simply: (1) receives a KEL event, (2) signs a receipt, (3) stores the event. A verifier collecting receipts from *k-of-n* witnesses can detect if the controller has presented different histories (duplicity). This is fundamentally different from blockchain consensus—it's *ambient verifiability* without a global ordering requirement.

### Subtasks

#### 2.1 — Define the witness protocol trait

```rust
// crates/auths-core/src/witness/protocol.rs

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A signed receipt from a witness confirming it has seen an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessReceipt {
    pub witness_id: String,
    pub event_said: String,
    pub prefix: String,
    pub sequence: u64,
    pub signature: Vec<u8>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Configuration for witness requirements on an identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessPolicy {
    pub threshold: usize,
    pub witnesses: Vec<WitnessEndpoint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessEndpoint {
    pub id: String,
    pub url: String,
    pub public_key: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("witness {id} unreachable: {reason}")]
    Unreachable { id: String, reason: String },
    #[error("duplicity detected: witness {id} has conflicting event at seq {sequence}")]
    DuplicityDetected { id: String, sequence: u64 },
    #[error("insufficient receipts: got {got}, need {need}")]
    InsufficientReceipts { got: usize, need: usize },
    #[error("invalid receipt from witness {id}: {reason}")]
    InvalidReceipt { id: String, reason: String },
}

/// Witness interaction protocol.
///
/// Implementations handle the network transport (HTTP, gRPC, etc.)
/// while the trait defines the logical operations.
#[async_trait]
pub trait WitnessClient: Send + Sync {
    async fn submit_event(
        &self,
        endpoint: &WitnessEndpoint,
        event_bytes: &[u8],
    ) -> Result<WitnessReceipt, WitnessError>;

    async fn query_event(
        &self,
        endpoint: &WitnessEndpoint,
        prefix: &str,
        sequence: u64,
    ) -> Result<Option<(Vec<u8>, WitnessReceipt)>, WitnessError>;

    async fn query_latest(
        &self,
        endpoint: &WitnessEndpoint,
        prefix: &str,
    ) -> Result<Option<u64>, WitnessError>;
}
```

#### 2.2 — Implement receipt collection and duplicity detection

```rust
// crates/auths-core/src/witness/collector.rs

use super::protocol::{WitnessClient, WitnessError, WitnessPolicy, WitnessReceipt};
use futures::future::join_all;

/// Collects witness receipts with threshold enforcement and duplicity detection.
pub struct ReceiptCollector<C: WitnessClient> {
    client: C,
}

impl<C: WitnessClient> ReceiptCollector<C> {
    pub fn new(client: C) -> Self {
        Self { client }
    }

    /// Submit an event to all witnesses, collecting receipts.
    ///
    /// Returns once `policy.threshold` receipts are collected.
    /// Detects duplicity if any witness reports a conflicting event.
    pub async fn collect_receipts(
        &self,
        policy: &WitnessPolicy,
        event_bytes: &[u8],
    ) -> Result<Vec<WitnessReceipt>, WitnessError> {
        let futures: Vec<_> = policy
            .witnesses
            .iter()
            .map(|endpoint| self.client.submit_event(endpoint, event_bytes))
            .collect();

        let results = join_all(futures).await;

        let mut receipts = Vec::new();
        let mut errors = Vec::new();

        for result in results {
            match result {
                Ok(receipt) => receipts.push(receipt),
                Err(WitnessError::DuplicityDetected { .. }) => return Err(result.unwrap_err()),
                Err(e) => errors.push(e),
            }
        }

        if receipts.len() >= policy.threshold {
            Ok(receipts)
        } else {
            Err(WitnessError::InsufficientReceipts {
                got: receipts.len(),
                need: policy.threshold,
            })
        }
    }
}
```

#### 2.3 — Lightweight HTTP witness server

A minimal Axum-based witness that stores events in SQLite. This becomes the reference implementation operators can deploy alongside their Git infrastructure.

#### 2.4 — Integrate receipt storage into KEL events

Store witness receipts alongside events in the registry tree at `v1/identities/{shard}/{prefix}/receipts/{seq}.json`.

---

## Epic 3: `auths setup` — Zero-to-Signing in 60 Seconds

**Priority:** Critical | **Area:** UX / Developer Experience | **Effort:** M

### Problem

The current onboarding requires understanding KERI, pre-rotation keys, attestation chains, and Git ref layout. Running `auths init` still demands familiarity with `--repo`, `--identity-ref`, key aliases, and passphrase management. This friction kills adoption before anyone sees the value.

### Subtasks

#### 3.1 — Unified interactive setup command

```rust
// crates/auths-cli/src/commands/setup.rs

use anyhow::Result;
use clap::Args;
use dialoguer::{Confirm, Input, Select};

#[derive(Args, Debug)]
pub struct SetupCommand {
    /// Skip interactive prompts with sensible defaults.
    #[clap(long)]
    non_interactive: bool,

    /// Preset profile: "developer", "ci", or "agent".
    #[clap(long, value_enum)]
    profile: Option<SetupProfile>,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum SetupProfile {
    Developer,
    Ci,
    Agent,
}

pub fn handle_setup(cmd: SetupCommand) -> Result<()> {
    let profile = match cmd.profile {
        Some(p) => p,
        None if cmd.non_interactive => SetupProfile::Developer,
        None => prompt_profile()?,
    };

    match profile {
        SetupProfile::Developer => setup_developer(cmd.non_interactive)?,
        SetupProfile::Ci => setup_ci(cmd.non_interactive)?,
        SetupProfile::Agent => setup_agent(cmd.non_interactive)?,
    }

    Ok(())
}

fn setup_developer(non_interactive: bool) -> Result<()> {
    println!("🔐 Setting up Auths for local development\n");

    // Step 1: Create identity (handles key generation, KERI inception, keychain storage)
    println!("Step 1/4: Creating your identity...");
    let identity = create_identity_with_defaults()?;
    println!("  ✓ Identity created: {}", short_did(&identity.controller_did));

    // Step 2: Link this device
    println!("Step 2/4: Linking this device...");
    let device = link_current_device(&identity)?;
    println!("  ✓ Device linked: {}", device.alias);

    // Step 3: Configure Git signing
    println!("Step 3/4: Configuring Git...");
    configure_git_signing(&identity)?;
    println!("  ✓ Git configured for SSH signing via Auths");

    // Step 4: Verify
    println!("Step 4/4: Verifying setup...");
    run_doctor_checks()?;

    println!("\n✅ Setup complete! Your next commit will be signed with Auths.");
    println!("   Run `auths status` anytime to check your identity.\n");

    Ok(())
}

fn setup_ci(non_interactive: bool) -> Result<()> {
    println!("🤖 Setting up Auths for CI/CD\n");

    // Generate ephemeral identity with auto-revocation
    println!("Step 1/3: Creating ephemeral CI identity...");
    let identity = create_ephemeral_identity()?;
    println!("  ✓ CI identity: {}", short_did(&identity.controller_did));

    // Output env vars for CI
    println!("Step 2/3: Generating CI configuration...");
    let env_block = generate_ci_env(&identity)?;
    println!("{}", env_block);

    // Write GitHub Action / GitLab CI snippet
    println!("Step 3/3: Writing CI integration...");
    detect_and_write_ci_config(&identity)?;

    println!("\n✅ CI setup complete. Add the environment variables to your CI secrets.");

    Ok(())
}

fn setup_agent(non_interactive: bool) -> Result<()> {
    println!("🤖 Setting up Auths for an AI agent\n");

    // Agent identity with scoped capabilities
    println!("Step 1/3: Creating agent identity...");
    let identity = create_agent_identity()?;
    println!("  ✓ Agent identity: {}", short_did(&identity.controller_did));

    println!("Step 2/3: Setting capability scope...");
    let caps = select_agent_capabilities(non_interactive)?;
    apply_agent_capabilities(&identity, &caps)?;
    println!("  ✓ Capabilities: {:?}", caps);

    println!("Step 3/3: Generating agent configuration...");
    let config = generate_agent_config(&identity)?;
    println!("{}", config);

    println!("\n✅ Agent setup complete.");

    Ok(())
}

fn short_did(did: &str) -> String {
    if did.len() > 24 {
        format!("{}...{}", &did[..16], &did[did.len() - 8..])
    } else {
        did.to_string()
    }
}
```

#### 3.2 — `auths doctor` enhancements

Extend the existing doctor command to validate the full setup chain: keychain health → Git signing config → identity integrity → device attestation validity → witness connectivity. Output a single pass/fail summary with actionable fix commands.

#### 3.3 — Shell completion auto-install

During `auths setup`, detect the shell and offer to install completions automatically (currently `auths completions` exists but requires manual piping).

---

## Epic 4: Offline-First Verification with Freshness Guarantees

**Priority:** High | **Area:** Security / Product | **Effort:** M

### Problem

The verifier is currently stateless — `VerifyAttestation(json, pubkey)` checks the signature but doesn't know if the key has been rotated or revoked since signing. This is a TOCTOU (time-of-check to time-of-use) vulnerability. Without fetching the latest KEL state, a revoked key can still pass verification.

### Theoretical Backing

The verification model needs two modes: **optimistic** (offline, uses cached state, fast) and **strict** (fetches latest KEL, blocks on freshness). This maps to the real-time vs. eventual consistency tradeoff. The key insight is that *most verifications should be offline-capable* but *high-security gates must enforce freshness*.

### Subtasks

#### 4.1 — Verification modes with freshness policy

```rust
// crates/auths-verifier/src/freshness.rs

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// Controls how aggressively the verifier checks for revocation/rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FreshnessPolicy {
    /// Accept cached KEL state without network calls.
    /// Suitable for offline environments or low-risk operations.
    Offline,

    /// Accept cached state if refreshed within the given duration.
    /// Falls back to network fetch if stale.
    MaxAge(Duration),

    /// Always fetch the latest KEL state before verification.
    /// Required for high-security gates (merge to main, release signing).
    Strict,
}

impl Default for FreshnessPolicy {
    fn default() -> Self {
        Self::MaxAge(Duration::minutes(5))
    }
}

/// Result of a verification with freshness metadata.
#[derive(Debug, Clone)]
pub struct FreshVerificationResult {
    pub valid: bool,
    pub kel_sequence: u64,
    pub kel_freshness: KelFreshness,
    pub key_status: KeyStatus,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum KelFreshness {
    /// KEL was fetched fresh from the source.
    Fresh { fetched_at: DateTime<Utc> },
    /// KEL is from cache, within acceptable age.
    Cached { cached_at: DateTime<Utc>, age: Duration },
    /// KEL could not be refreshed (offline mode or network failure).
    Stale { last_known_at: DateTime<Utc> },
}

#[derive(Debug, Clone)]
pub enum KeyStatus {
    Active,
    Rotated { rotated_at_seq: u64 },
    Revoked,
    Unknown,
}
```

#### 4.2 — KEL state cache with TTL

```rust
// crates/auths-verifier/src/cache.rs

use std::collections::HashMap;
use std::sync::RwLock;

use chrono::{DateTime, Utc};

struct CachedKelState {
    sequence: u64,
    current_key: Vec<u8>,
    is_abandoned: bool,
    fetched_at: DateTime<Utc>,
}

/// Thread-safe in-memory cache for KEL states.
///
/// Designed for embedding in long-lived processes (CI runners,
/// admission controllers) where repeated verifications of the
/// same identities benefit from caching.
pub struct KelCache {
    entries: RwLock<HashMap<String, CachedKelState>>,
    max_entries: usize,
}

impl KelCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_entries,
        }
    }

    pub fn get(&self, prefix: &str, max_age: chrono::Duration) -> Option<(u64, Vec<u8>, bool)> {
        let entries = self.entries.read().ok()?;
        let cached = entries.get(prefix)?;
        let age = Utc::now() - cached.fetched_at;
        if age > max_age {
            return None;
        }
        Some((cached.sequence, cached.current_key.clone(), cached.is_abandoned))
    }

    pub fn put(&self, prefix: &str, sequence: u64, current_key: Vec<u8>, is_abandoned: bool) {
        let mut entries = self.entries.write().unwrap();
        if entries.len() >= self.max_entries && !entries.contains_key(prefix) {
            if let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, v)| v.fetched_at)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest_key);
            }
        }
        entries.insert(
            prefix.to_string(),
            CachedKelState {
                sequence,
                current_key,
                is_abandoned,
                fetched_at: Utc::now(),
            },
        );
    }
}
```

#### 4.3 — Wire freshness into all verifier bindings

Update the Go, Python, Swift, and WASM verifiers to accept an optional `FreshnessPolicy` parameter, defaulting to `MaxAge(5min)`.

---

## Epic 5: GitHub Action & CI/CD Adapter

**Priority:** High | **Area:** Distribution / Developer Experience | **Effort:** M

### Problem

The single biggest adoption blocker is that there's no turnkey CI integration. Developers won't manually configure KERI key management in every pipeline. A GitHub Action that "just works" is the Trojan horse.

### Subtasks

#### 5.1 — `auths-action` GitHub Action

```yaml
# .github/actions/auths-sign/action.yml
name: 'Auths Sign'
description: 'Sign artifacts with Auths identity'

inputs:
  mode:
    description: 'ephemeral (per-job) or persistent (from secret)'
    required: false
    default: 'ephemeral'
  identity-secret:
    description: 'Base64-encoded Auths identity (for persistent mode)'
    required: false
  capabilities:
    description: 'Comma-separated capabilities for ephemeral identity'
    required: false
    default: 'sign_commit,sign_release'
  parent-identity:
    description: 'DID of the parent identity that authorizes this CI identity'
    required: false
  attestation-ttl:
    description: 'TTL for ephemeral attestation (e.g., "1h", "30m")'
    required: false
    default: '1h'

outputs:
  identity-did:
    description: 'DID of the signing identity'
  attestation-json:
    description: 'JSON attestation linking CI identity to parent'

runs:
  using: 'composite'
  steps:
    - name: Install Auths CLI
      shell: bash
      run: |
        curl -fsSL https://get.auths.dev | sh
        echo "$HOME/.auths/bin" >> $GITHUB_PATH

    - name: Setup Identity
      shell: bash
      run: |
        if [ "${{ inputs.mode }}" = "ephemeral" ]; then
          auths setup --profile ci --non-interactive
          echo "identity-did=$(auths status --json | jq -r .did)" >> $GITHUB_OUTPUT
        else
          echo "${{ inputs.identity-secret }}" | base64 -d > /tmp/auths-identity.json
          auths key import --from /tmp/auths-identity.json --alias ci-signer
          rm /tmp/auths-identity.json
        fi

    - name: Configure Git Signing
      shell: bash
      run: auths git install-hooks --global
```

#### 5.2 — `auths ci sign` subcommand

```rust
// crates/auths-cli/src/commands/ci.rs

use anyhow::Result;
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct CiCommand {
    #[command(subcommand)]
    command: CiSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum CiSubcommand {
    /// Sign the current commit or artifact in CI context.
    Sign(CiSignArgs),
    /// Verify a CI-signed artifact.
    Verify(CiVerifyArgs),
    /// Generate environment export for downstream jobs.
    Export(CiExportArgs),
}

#[derive(Args, Debug)]
pub struct CiSignArgs {
    /// Path to artifact to sign (or "commit" for current HEAD).
    #[clap(default_value = "commit")]
    target: String,

    /// Attach provenance metadata (SLSA-compatible).
    #[clap(long)]
    provenance: bool,

    /// Output format for the signature.
    #[clap(long, value_enum, default_value = "json")]
    format: SignatureFormat,
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum SignatureFormat {
    Json,
    Sigstore,
    InToto,
}

pub fn handle_ci(cmd: CiCommand) -> Result<()> {
    match cmd.command {
        CiSubcommand::Sign(args) => handle_ci_sign(args),
        CiSubcommand::Verify(args) => handle_ci_verify(args),
        CiSubcommand::Export(args) => handle_ci_export(args),
    }
}
```

#### 5.3 — GitLab CI Component and generic CI template

Provide equivalent for `.gitlab-ci.yml` and a generic shell script for other CI systems (Jenkins, CircleCI, Buildkite).

---

## Epic 6: Structured Error Reporting & Diagnostics

**Priority:** High | **Area:** UX / Developer Experience | **Effort:** S

### Problem

Errors like `CommitmentMismatch`, `KelError`, and `RegistryError::NotFound` are technically correct but opaque to non-cryptographers. When a developer's commit is rejected, they need to know *what to do*, not what went wrong in the Merkle tree.

### Subtasks

#### 6.1 — User-facing error wrapper with remediation hints

```rust
// crates/auths-cli/src/diagnostics.rs

use auths_core::error::AgentError;
use auths_id::keri::rotation::RotationError;

/// A user-facing diagnostic that wraps internal errors with
/// actionable remediation steps.
pub struct Diagnostic {
    pub code: &'static str,
    pub headline: String,
    pub explanation: String,
    pub remediation: Vec<String>,
    pub docs_url: Option<String>,
}

impl Diagnostic {
    pub fn render(&self) -> String {
        let mut out = format!("error[{}]: {}\n", self.code, self.headline);
        out.push_str(&format!("\n  {}\n", self.explanation));
        if !self.remediation.is_empty() {
            out.push_str("\n  How to fix:\n");
            for (i, step) in self.remediation.iter().enumerate() {
                out.push_str(&format!("    {}. {}\n", i + 1, step));
            }
        }
        if let Some(url) = &self.docs_url {
            out.push_str(&format!("\n  Docs: {}\n", url));
        }
        out
    }
}

pub fn diagnose_rotation_error(err: &RotationError) -> Diagnostic {
    match err {
        RotationError::CommitmentMismatch => Diagnostic {
            code: "E0010",
            headline: "Key rotation failed: wrong recovery key".into(),
            explanation: "The key you provided doesn't match the one you \
                committed to during your last rotation. This is a security \
                feature that prevents unauthorized key changes."
                .into(),
            remediation: vec![
                "Locate your recovery key backup (created during setup or last rotation)".into(),
                "Run `auths key list` to see available keys".into(),
                "Use `auths key rotate --recovery-key <alias>` with the correct key".into(),
            ],
            docs_url: Some("https://docs.auths.dev/guides/key-rotation".into()),
        },
        RotationError::IdentityAbandoned => Diagnostic {
            code: "E0011",
            headline: "Identity has been permanently deactivated".into(),
            explanation: "This identity was abandoned (final rotation with empty commitment). \
                It can no longer be rotated or used for new signatures."
                .into(),
            remediation: vec![
                "Create a new identity with `auths setup`".into(),
                "If this was unintentional, contact your organization admin".into(),
            ],
            docs_url: Some("https://docs.auths.dev/concepts/abandonment".into()),
        },
        _ => Diagnostic {
            code: "E0099",
            headline: format!("Key rotation failed: {}", err),
            explanation: "An unexpected error occurred during key rotation.".into(),
            remediation: vec![
                "Run `auths doctor` to check your setup".into(),
                "If the problem persists, file an issue with the output of `auths doctor --json`"
                    .into(),
            ],
            docs_url: None,
        },
    }
}
```

#### 6.2 — Apply diagnostics to all CLI error paths

Wrap every `handle_*` function's error return through a diagnostics layer. The `main.rs` match already centralizes command dispatch—add a single `map_err` pipeline.

#### 6.3 — JSON error output for tooling

Ensure `--output json` produces structured error objects with `code`, `message`, and `remediation` fields for IDE plugins and CI parsers.

---

## Epic 7: Automated Key Rotation & Recovery UX

**Priority:** High | **Area:** Security / UX | **Effort:** M

### Problem

Pre-rotation is Auths' killer security feature, but it's also the biggest UX footgun. Users must manually manage PKCS8-encoded recovery keys. If they lose the pre-committed next key, the identity is permanently locked (not abandoned—just stuck). There's no recovery ceremony, no social recovery, and no guided rotation flow.

### Theoretical Backing

KERI's pre-rotation provides *post-quantum* key compromise recovery: even if an attacker steals the current private key, they cannot rotate without the pre-committed next key. But this security guarantee is only as strong as the user's ability to manage the next key. The UX must abstract this into a "recovery kit" model—analogous to a hardware wallet seed phrase, but for identity.

### Subtasks

#### 7.1 — Recovery kit generation and encrypted export

```rust
// crates/auths-core/src/recovery.rs

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// An encrypted bundle containing the pre-rotation key material.
///
/// Designed to be printed, stored on a USB drive, or kept in a
/// password manager. The bundle is encrypted with a user-chosen
/// passphrase via AES-256-GCM with Argon2id key derivation.
#[derive(Debug, Serialize, Deserialize)]
pub struct RecoveryKit {
    pub version: u32,
    pub identity_did: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub kdf: KdfParams,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: String,
    pub salt: Vec<u8>,
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl RecoveryKit {
    /// Create a new recovery kit from the next-key PKCS8 material.
    pub fn create(
        identity_did: &str,
        next_keypair_pkcs8: &[u8],
        passphrase: &str,
    ) -> Result<Self, RecoveryError> {
        let rng = SystemRandom::new();

        let mut salt = vec![0u8; 32];
        rng.fill(&mut salt).map_err(|_| RecoveryError::RngFailed)?;

        let derived_key = derive_key(passphrase, &salt)?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, &derived_key)
            .map_err(|_| RecoveryError::EncryptionFailed)?;
        let key = LessSafeKey::new(unbound_key);

        let mut nonce_bytes = vec![0u8; 12];
        rng.fill(&mut nonce_bytes).map_err(|_| RecoveryError::RngFailed)?;
        let nonce = Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| RecoveryError::EncryptionFailed)?;

        let mut ciphertext = next_keypair_pkcs8.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut ciphertext)
            .map_err(|_| RecoveryError::EncryptionFailed)?;

        Ok(Self {
            version: 1,
            identity_did: identity_did.to_string(),
            created_at: chrono::Utc::now(),
            kdf: KdfParams {
                algorithm: "argon2id".to_string(),
                salt,
                m_cost: 65536,
                t_cost: 3,
                p_cost: 4,
            },
            ciphertext,
            nonce: nonce_bytes,
        })
    }

    /// Decrypt the recovery kit and return the next-key PKCS8 material.
    pub fn decrypt(&self, passphrase: &str) -> Result<Zeroizing<Vec<u8>>, RecoveryError> {
        let derived_key = derive_key(passphrase, &self.kdf.salt)?;

        let unbound_key = UnboundKey::new(&AES_256_GCM, &derived_key)
            .map_err(|_| RecoveryError::DecryptionFailed)?;
        let key = LessSafeKey::new(unbound_key);

        let nonce = Nonce::try_assume_unique_for_key(&self.nonce)
            .map_err(|_| RecoveryError::DecryptionFailed)?;

        let mut plaintext = self.ciphertext.clone();
        key.open_in_place(nonce, Aad::empty(), &mut plaintext)
            .map_err(|_| RecoveryError::WrongPassphrase)?;

        // Remove the GCM tag
        plaintext.truncate(plaintext.len() - AES_256_GCM.tag_len());

        Ok(Zeroizing::new(plaintext))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("RNG initialization failed")]
    RngFailed,
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("key derivation failed: {0}")]
    KdfFailed(String),
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Vec<u8>, RecoveryError> {
    use argon2::{Argon2, Algorithm, Params, Version};

    let params = Params::new(65536, 3, 4, Some(32))
        .map_err(|e| RecoveryError::KdfFailed(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| RecoveryError::KdfFailed(e.to_string()))?;

    Ok(key)
}
```

#### 7.2 — `auths key rotate` with guided flow

```rust
// Extend crates/auths-cli/src/commands/key.rs

/// Interactive key rotation with recovery kit management.
fn handle_key_rotate(args: KeyRotateArgs, passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>) -> Result<()> {
    println!("🔄 Key Rotation\n");

    // Step 1: Load current identity
    let identity = load_current_identity(&args)?;
    println!("  Identity: {}", short_did(&identity.controller_did));

    // Step 2: Locate recovery key
    println!("\n  To rotate your key, you need your recovery key.");
    println!("  This was saved during setup or your last rotation.\n");

    let recovery_source = Select::new()
        .with_prompt("Where is your recovery key?")
        .items(&["Recovery kit file (.auths-recovery)", "Keychain (stored locally)", "Manual entry (PKCS8)"])
        .default(0)
        .interact()?;

    let next_keypair_pkcs8 = match recovery_source {
        0 => load_from_recovery_kit(&passphrase_provider)?,
        1 => load_from_keychain(&args, &passphrase_provider)?,
        2 => load_from_manual_entry()?,
        _ => unreachable!(),
    };

    // Step 3: Perform rotation
    println!("\n  Rotating key...");
    let result = rotate_keys_with_recovery(&identity, &next_keypair_pkcs8)?;

    // Step 4: Generate new recovery kit
    println!("  Generating new recovery kit...");
    let kit_passphrase = prompt_recovery_passphrase(&passphrase_provider)?;
    let kit = RecoveryKit::create(
        &identity.controller_did,
        &result.new_next_keypair_pkcs8,
        &kit_passphrase,
    )?;
    save_recovery_kit(&kit, &args)?;

    println!("\n✅ Key rotated successfully.");
    println!("   New recovery kit saved. Store it safely—you'll need it for the next rotation.");

    Ok(())
}
```

#### 7.3 — Scheduled rotation reminders

Add a `rotation_policy` field to identity metadata that configures rotation reminders (e.g., every 90 days). `auths status` surfaces upcoming rotation deadlines.

---

## Epic 8: Revocation Event Propagation

**Priority:** High | **Area:** Security / Product | **Effort:** M

### Problem

Revocation currently appends an event to the KEL, but there's no push mechanism. A revoked agent key passes verification until the verifier happens to pull the latest KEL. For the "global kill switch" value prop (from the analysis doc's §5.2), revocation must propagate in near-real-time.

### Subtasks

#### 8.1 — Revocation event webhook system

```rust
// crates/auths-core/src/revocation/webhook.rs

use serde::{Deserialize, Serialize};

/// Configuration for revocation event propagation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationWebhookConfig {
    pub endpoints: Vec<WebhookEndpoint>,
    pub retry_policy: RetryPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    pub url: String,
    pub secret: Option<String>,
    pub events: Vec<RevocationEventType>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationEventType {
    DeviceRevoked,
    KeyRotated,
    IdentityAbandoned,
    MemberRemoved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

/// Payload sent to webhook endpoints on revocation events.
#[derive(Debug, Serialize, Deserialize)]
pub struct RevocationPayload {
    pub event_type: RevocationEventType,
    pub identity_did: String,
    pub subject_did: Option<String>,
    pub sequence: u64,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub signature: String,
}
```

#### 8.2 — CRL (Certificate Revocation List) endpoint

Provide an HTTP endpoint that serves a compact revocation list in a Sigstore-compatible format, enabling integration with existing supply chain verification tooling.

#### 8.3 — `auths revoke` with confirmation and propagation

Extend the existing revoke flow to: (1) confirm the action with the user, (2) append the KEL event, (3) fire webhooks, (4) push to witnesses, (5) report propagation status.

---

## Epic 9: MCP Server for LLM-Native Identity

**Priority:** Medium | **Area:** Product / Agentic | **Effort:** M

### Problem

The analysis doc (§9 Phase 2) calls out MCP integration as a strategic move. Today, an LLM agent wanting to sign a tool output must shell out to the CLI. A Model Context Protocol server would let agents query identities, sign outputs, and verify attestations as native tool calls—making "provenance by default" seamless for the agent framework ecosystem.

### Subtasks

#### 9.1 — MCP server with identity tools

```rust
// crates/auths-mcp/src/server.rs

use serde::{Deserialize, Serialize};

/// MCP tool definitions exposed by the Auths server.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "auths_whoami".into(),
            description: "Get the current Auths identity and capabilities".into(),
            parameters: serde_json::json!({}),
        },
        ToolDefinition {
            name: "auths_sign".into(),
            description: "Sign arbitrary content with the agent's Auths identity".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "content": { "type": "string", "description": "Content to sign" },
                    "content_type": {
                        "type": "string",
                        "enum": ["text", "json", "commit"],
                        "description": "Type of content being signed"
                    }
                },
                "required": ["content"]
            }),
        },
        ToolDefinition {
            name: "auths_verify".into(),
            description: "Verify a signed attestation or artifact".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "attestation_json": { "type": "string" },
                    "expected_signer": { "type": "string", "description": "Expected signer DID (optional)" }
                },
                "required": ["attestation_json"]
            }),
        },
        ToolDefinition {
            name: "auths_check_capability".into(),
            description: "Check if the current identity has a specific capability".into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "capability": { "type": "string", "description": "Capability to check (e.g., sign_commit)" }
                },
                "required": ["capability"]
            }),
        },
    ]
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}
```

#### 9.2 — LangChain / CrewAI middleware

```python
# packages/auths-langchain/auths_langchain/signer.py

"""LangChain tool wrapper for Auths identity operations."""

from typing import Optional
from langchain_core.tools import BaseTool
from pydantic import BaseModel, Field
import subprocess
import json


class AuthsSignInput(BaseModel):
    content: str = Field(description="Content to sign")
    content_type: str = Field(
        default="text",
        description="Type: text, json, or commit",
    )


class AuthsSignTool(BaseTool):
    """Sign content with the agent's Auths identity.

    Wraps the Auths CLI to provide cryptographic signing
    as a LangChain tool. The agent's identity and capabilities
    are determined by the environment configuration.
    """

    name: str = "auths_sign"
    description: str = (
        "Sign content with your cryptographic identity. "
        "Use this to create verifiable provenance for any "
        "output you produce."
    )
    args_schema: type[BaseModel] = AuthsSignInput

    def _run(self, content: str, content_type: str = "text") -> str:
        result = subprocess.run(
            ["auths", "ci", "sign", "--format", "json", "--stdin"],
            input=content.encode(),
            capture_output=True,
        )
        if result.returncode != 0:
            return json.dumps({"error": result.stderr.decode()})
        return result.stdout.decode()

    async def _arun(self, content: str, content_type: str = "text") -> str:
        import asyncio
        return await asyncio.to_thread(self._run, content, content_type)


class AuthsVerifyTool(BaseTool):
    """Verify a signed attestation from another agent or identity."""

    name: str = "auths_verify"
    description: str = (
        "Verify that content was signed by a specific identity. "
        "Returns verification status and signer details."
    )

    def _run(self, attestation_json: str, expected_signer: Optional[str] = None) -> str:
        cmd = ["auths", "verify", "--json", "--stdin"]
        if expected_signer:
            cmd.extend(["--expected-signer", expected_signer])

        result = subprocess.run(
            cmd,
            input=attestation_json.encode(),
            capture_output=True,
        )
        return result.stdout.decode()
```

#### 9.3 — Signed tool-use attestation format

Define a standard JSON schema for "this agent called this tool with these parameters and produced this output, signed by DID X." This becomes the audit trail for agentic workflows.

---

## Epic 10: Registry Performance Layer (auths-index)

**Priority:** Medium | **Area:** Product / Scalability | **Effort:** M

### Problem

The `auths-index` crate exists but is minimal. The `PackedRegistryBackend` uses Git tree operations for every read, which means O(n) Git object traversals for lookups. At scale (10k+ identities, high-frequency agent updates), Git ref-locking causes contention and reads become unacceptably slow.

### Subtasks

#### 10.1 — SQLite read-through index

```rust
// crates/auths-index/src/sqlite_index.rs

use rusqlite::{Connection, params};
use std::path::Path;
use std::sync::Mutex;

/// SQLite-backed read index for the Auths registry.
///
/// Serves as a read-through cache that materializes Git tree
/// contents into queryable tables. Writes always go through
/// Git (source of truth); the index rebuilds from Git state
/// on cache miss or explicit rebuild.
pub struct SqliteIndex {
    conn: Mutex<Connection>,
}

impl SqliteIndex {
    pub fn open(path: &Path) -> Result<Self, IndexError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn lookup_identity(&self, prefix: &str) -> Result<Option<IndexedIdentity>, IndexError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT prefix, controller_did, current_key_hex, sequence, \
             is_abandoned, last_updated \
             FROM identities WHERE prefix = ?1",
        )?;

        let result = stmt.query_row(params![prefix], |row| {
            Ok(IndexedIdentity {
                prefix: row.get(0)?,
                controller_did: row.get(1)?,
                current_key_hex: row.get(2)?,
                sequence: row.get(3)?,
                is_abandoned: row.get(4)?,
                last_updated: row.get(5)?,
            })
        });

        match result {
            Ok(identity) => Ok(Some(identity)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn lookup_device(&self, device_did: &str) -> Result<Option<IndexedDevice>, IndexError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT device_did, identity_did, capabilities, role, \
             revoked, expires_at, last_updated \
             FROM devices WHERE device_did = ?1",
        )?;

        let result = stmt.query_row(params![device_did], |row| {
            Ok(IndexedDevice {
                device_did: row.get(0)?,
                identity_did: row.get(1)?,
                capabilities: row.get(2)?,
                role: row.get(3)?,
                revoked: row.get(4)?,
                expires_at: row.get(5)?,
                last_updated: row.get(6)?,
            })
        });

        match result {
            Ok(device) => Ok(Some(device)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Full-text search across identities and devices.
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<SearchResult>, IndexError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT 'identity' as type, prefix as id, controller_did as label \
             FROM identities WHERE controller_did LIKE ?1 \
             UNION ALL \
             SELECT 'device', device_did, identity_did \
             FROM devices WHERE device_did LIKE ?1 \
             LIMIT ?2",
        )?;

        let pattern = format!("%{}%", query);
        let results = stmt.query_map(params![pattern, limit as i64], |row| {
            Ok(SearchResult {
                result_type: row.get(0)?,
                id: row.get(1)?,
                label: row.get(2)?,
            })
        })?;

        results.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Rebuild the entire index from Git registry state.
    pub fn rebuild_from_registry(
        &self,
        registry: &dyn crate::RegistryReader,
    ) -> Result<RebuildStats, IndexError> {
        let conn = self.conn.lock().unwrap();
        let tx = conn.unchecked_transaction()?;

        tx.execute("DELETE FROM identities", [])?;
        tx.execute("DELETE FROM devices", [])?;

        let mut identity_count = 0u64;
        let mut device_count = 0u64;

        registry.visit_all_identities(|prefix, state| {
            tx.execute(
                "INSERT INTO identities (prefix, controller_did, current_key_hex, \
                 sequence, is_abandoned, last_updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    prefix,
                    format!("did:keri:{}", prefix),
                    hex::encode(state.current_key_bytes()),
                    state.sequence,
                    state.is_abandoned,
                    chrono::Utc::now().to_rfc3339(),
                ],
            )?;
            identity_count += 1;
            Ok(())
        })?;

        registry.visit_all_devices(|did, attestation| {
            tx.execute(
                "INSERT INTO devices (device_did, identity_did, capabilities, \
                 role, revoked, expires_at, last_updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    did.to_string(),
                    attestation.issuer,
                    serde_json::to_string(&attestation.capabilities).unwrap_or_default(),
                    attestation.role,
                    attestation.revoked,
                    attestation.expires_at.map(|t| t.to_rfc3339()),
                    chrono::Utc::now().to_rfc3339(),
                ],
            )?;
            device_count += 1;
            Ok(())
        })?;

        tx.commit()?;

        Ok(RebuildStats {
            identities: identity_count,
            devices: device_count,
        })
    }
}

const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS identities (
        prefix TEXT PRIMARY KEY,
        controller_did TEXT NOT NULL,
        current_key_hex TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        is_abandoned INTEGER NOT NULL DEFAULT 0,
        last_updated TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS devices (
        device_did TEXT PRIMARY KEY,
        identity_did TEXT NOT NULL,
        capabilities TEXT,
        role TEXT,
        revoked INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT,
        last_updated TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_devices_identity ON devices(identity_did);
";

#[derive(Debug)]
pub struct IndexedIdentity {
    pub prefix: String,
    pub controller_did: String,
    pub current_key_hex: String,
    pub sequence: u64,
    pub is_abandoned: bool,
    pub last_updated: String,
}

#[derive(Debug)]
pub struct IndexedDevice {
    pub device_did: String,
    pub identity_did: String,
    pub capabilities: String,
    pub role: Option<String>,
    pub revoked: bool,
    pub expires_at: Option<String>,
    pub last_updated: String,
}

#[derive(Debug)]
pub struct SearchResult {
    pub result_type: String,
    pub id: String,
    pub label: String,
}

#[derive(Debug)]
pub struct RebuildStats {
    pub identities: u64,
    pub devices: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum IndexError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("registry error: {0}")]
    Registry(String),
}
```

#### 10.2 — Write-through invalidation via Git hooks

Register a post-commit hook on the registry ref that invalidates affected index entries. The hook calls `auths index update --incremental` which reads only the changed tree entries.

#### 10.3 — `auths index` CLI enhancements

Extend the existing `index` command with: `auths index rebuild` (full), `auths index stats` (count/size), `auths index search <query>` (full-text lookup).

---

## Summary Matrix

| # | Epic | Priority | Area | Risk Mitigated |
|---|------|----------|------|----------------|
| 1 | Typed Capabilities | Critical | Security | Capability injection, typo-squatting |
| 2 | Witness Network | Critical | Security | Split-view attacks, registry poisoning |
| 3 | `auths setup` | Critical | UX | Adoption friction, onboarding drop-off |
| 4 | Offline Verification | High | Security/Product | TOCTOU on revoked keys |
| 5 | CI/CD Action | High | Distribution | Ecosystem penetration |
| 6 | Error Diagnostics | High | UX | Support burden, developer frustration |
| 7 | Key Rotation UX | High | Security/UX | Lost recovery keys, locked identities |
| 8 | Revocation Propagation | High | Security/Product | Stale revocation state |
| 9 | MCP Server | Medium | Product/Agentic | Agent framework integration |
| 10 | Registry Index | Medium | Scalability | Git contention at scale |
