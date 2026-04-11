use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_verifier::Capability;
use auths_verifier::types::DeviceDID;
use std::path::PathBuf;

use crate::domains::ci::types::{CiEnvironment, CiIdentityConfig};

/// Policy for handling an existing identity during developer setup.
///
/// Replaces interactive CLI prompts with a typed enum that headless consumers
/// can set programmatically.
///
/// Usage:
/// ```ignore
/// let config = CreateDeveloperIdentityConfig::builder("my-key")
///     .with_conflict_policy(IdentityConflictPolicy::ReuseExisting)
///     .build();
/// ```
#[derive(Debug, Clone, Default)]
pub enum IdentityConflictPolicy {
    /// Return an error if an identity already exists (default).
    #[default]
    Error,
    /// Reuse the existing identity silently.
    ReuseExisting,
    /// Overwrite the existing identity with a new one.
    ForceNew,
}

/// Configuration for provisioning a new developer identity.
///
/// Use [`CreateDeveloperIdentityConfigBuilder`] to construct this with optional fields.
/// The registry backend is injected via [`crate::context::AuthsContext`] — this
/// struct carries only serializable configuration values.
///
/// Args:
/// * `key_alias`: Human-readable name for the key (e.g. "work-laptop").
///
/// Usage:
/// ```ignore
/// let config = CreateDeveloperIdentityConfig::builder("work-laptop")
///     .with_platform(crate::types::PlatformVerification::GitHub { access_token: "ghp_abc".into() })
///     .with_git_signing_scope(crate::types::GitSigningScope::Global)
///     .build();
/// ```
#[derive(Debug)]
pub struct CreateDeveloperIdentityConfig {
    /// Human-readable name for the key (e.g. "work-laptop").
    pub key_alias: KeyAlias,
    /// Optional platform verification configuration.
    pub platform: Option<crate::types::PlatformVerification>,
    /// How to configure git commit signing.
    pub git_signing_scope: crate::types::GitSigningScope,
    /// Whether to register the identity on a remote registry.
    pub register_on_registry: bool,
    /// Remote registry URL, if registration is enabled.
    pub registry_url: Option<String>,
    /// What to do if an identity already exists.
    pub conflict_policy: IdentityConflictPolicy,
    /// Optional KERI witness configuration for the inception event.
    pub witness_config: Option<auths_id::witness_config::WitnessConfig>,
    /// Optional JSON metadata to attach to the identity.
    pub metadata: Option<serde_json::Value>,
    /// Path to the `auths-sign` binary, required when git signing is configured.
    /// The CLI resolves this via `which::which("auths-sign")`.
    pub sign_binary_path: Option<PathBuf>,
    /// Override the default curve for key generation. Defaults to `CurveType::default()` (P-256).
    pub curve: auths_crypto::CurveType,
}

impl CreateDeveloperIdentityConfig {
    /// Creates a builder with the required key alias.
    ///
    /// Args:
    /// * `key_alias`: Human-readable name for the key.
    ///
    /// Usage:
    /// ```ignore
    /// let builder = CreateDeveloperIdentityConfig::builder("my-key");
    /// ```
    pub fn builder(key_alias: KeyAlias) -> CreateDeveloperIdentityConfigBuilder {
        CreateDeveloperIdentityConfigBuilder {
            key_alias,
            platform: None,
            git_signing_scope: crate::types::GitSigningScope::Global,
            register_on_registry: false,
            registry_url: None,
            conflict_policy: IdentityConflictPolicy::Error,
            witness_config: None,
            metadata: None,
            sign_binary_path: None,
            curve: auths_crypto::CurveType::default(),
        }
    }
}

/// Builder for [`CreateDeveloperIdentityConfig`].
#[derive(Debug)]
pub struct CreateDeveloperIdentityConfigBuilder {
    key_alias: KeyAlias,
    platform: Option<crate::types::PlatformVerification>,
    git_signing_scope: crate::types::GitSigningScope,
    register_on_registry: bool,
    registry_url: Option<String>,
    conflict_policy: IdentityConflictPolicy,
    witness_config: Option<auths_id::witness_config::WitnessConfig>,
    metadata: Option<serde_json::Value>,
    sign_binary_path: Option<PathBuf>,
    curve: auths_crypto::CurveType,
}

impl CreateDeveloperIdentityConfigBuilder {
    /// Configures platform identity verification for the new identity.
    ///
    /// The SDK never opens a browser or runs OAuth flows. The caller must
    /// obtain the access token beforehand and pass it here.
    ///
    /// Args:
    /// * `platform`: The platform and access token to verify against.
    ///
    /// Usage:
    /// ```ignore
    /// let config = CreateDeveloperIdentityConfig::builder("my-key")
    ///     .with_platform(crate::types::PlatformVerification::GitHub {
    ///         access_token: "ghp_abc123".into(),
    ///     })
    ///     .build();
    /// ```
    pub fn with_platform(mut self, platform: crate::types::PlatformVerification) -> Self {
        self.platform = Some(platform);
        self
    }

    /// Sets the Git signing scope (local, global, or skip).
    ///
    /// Args:
    /// * `scope`: How to configure `git config` for commit signing.
    ///
    /// Usage:
    /// ```ignore
    /// let config = CreateDeveloperIdentityConfig::builder("my-key")
    ///     .with_git_signing_scope(crate::types::GitSigningScope::Local {
    ///         repo_path: PathBuf::from("/path/to/repo"),
    ///     })
    ///     .build();
    /// ```
    pub fn with_git_signing_scope(mut self, scope: crate::types::GitSigningScope) -> Self {
        self.git_signing_scope = scope;
        self
    }

    /// Enables registration on a remote auths registry after identity creation.
    ///
    /// Args:
    /// * `url`: The registry URL to register with.
    ///
    /// Usage:
    /// ```ignore
    /// let config = CreateDeveloperIdentityConfig::builder("my-key")
    ///     .with_registration("https://registry.auths.dev")
    ///     .build();
    /// ```
    pub fn with_registration(mut self, url: impl Into<String>) -> Self {
        self.register_on_registry = true;
        self.registry_url = Some(url.into());
        self
    }

    /// Sets the policy for handling an existing identity at the registry path.
    ///
    /// Args:
    /// * `policy`: What to do if an identity already exists.
    ///
    /// Usage:
    /// ```ignore
    /// let config = CreateDeveloperIdentityConfig::builder("my-key")
    ///     .with_conflict_policy(IdentityConflictPolicy::ReuseExisting)
    ///     .build();
    /// ```
    pub fn with_conflict_policy(mut self, policy: IdentityConflictPolicy) -> Self {
        self.conflict_policy = policy;
        self
    }

    /// Sets the witness configuration for the KERI inception event.
    ///
    /// Args:
    /// * `config`: Witness endpoints and thresholds.
    ///
    /// Usage:
    /// ```ignore
    /// let config = CreateDeveloperIdentityConfig::builder("my-key")
    ///     .with_witness_config(witness_cfg)
    ///     .build();
    /// ```
    pub fn with_witness_config(mut self, config: auths_id::witness_config::WitnessConfig) -> Self {
        self.witness_config = Some(config);
        self
    }

    /// Attaches custom metadata to the identity (e.g. `created_at`, `setup_profile`).
    ///
    /// Args:
    /// * `metadata`: Arbitrary JSON metadata.
    ///
    /// Usage:
    /// ```ignore
    /// let config = CreateDeveloperIdentityConfig::builder("my-key")
    ///     .with_metadata(serde_json::json!({"team": "platform"}))
    ///     .build();
    /// ```
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Sets the path to the `auths-sign` binary used for git signing configuration.
    ///
    /// Required when `git_signing_scope` is not `Skip`. The CLI resolves this via
    /// `which::which("auths-sign")`.
    ///
    /// Args:
    /// * `path`: Absolute path to the `auths-sign` binary.
    ///
    /// Usage:
    /// ```ignore
    /// let config = CreateDeveloperIdentityConfig::builder("my-key")
    ///     .with_sign_binary_path(PathBuf::from("/usr/local/bin/auths-sign"))
    ///     .build();
    /// ```
    pub fn with_sign_binary_path(mut self, path: PathBuf) -> Self {
        self.sign_binary_path = Some(path);
        self
    }

    /// Override the curve for key generation (default: P-256).
    pub fn with_curve(mut self, curve: auths_crypto::CurveType) -> Self {
        self.curve = curve;
        self
    }

    /// Builds the final [`CreateDeveloperIdentityConfig`].
    ///
    /// Usage:
    /// ```ignore
    /// let config = CreateDeveloperIdentityConfig::builder("my-key").build();
    /// ```
    pub fn build(self) -> CreateDeveloperIdentityConfig {
        CreateDeveloperIdentityConfig {
            key_alias: self.key_alias,
            platform: self.platform,
            git_signing_scope: self.git_signing_scope,
            register_on_registry: self.register_on_registry,
            registry_url: self.registry_url,
            conflict_policy: self.conflict_policy,
            witness_config: self.witness_config,
            metadata: self.metadata,
            sign_binary_path: self.sign_binary_path,
            curve: self.curve,
        }
    }
}

/// Selects which identity persona to provision via [`crate::setup::initialize`].
///
/// Usage:
/// ```ignore
/// // Developer preset (platform keychain, git signing):
/// let config = IdentityConfig::developer(KeyAlias::new_unchecked("work-laptop"));
///
/// // CI preset (memory keychain, ephemeral):
/// let config = IdentityConfig::ci(PathBuf::from("/tmp/.auths-ci"));
///
/// // Agent preset (minimal capabilities, long-lived):
/// let config = IdentityConfig::agent(KeyAlias::new_unchecked("deploy-bot"), registry_path);
///
/// // Custom configuration:
/// let config = IdentityConfig::Developer(
///     CreateDeveloperIdentityConfig::builder(alias)
///         .with_platform(crate::types::PlatformVerification::GitHub { access_token: token })
///         .build()
/// );
/// ```
#[derive(Debug)]
pub enum IdentityConfig {
    /// Full local developer setup: platform keychain, git signing, passphrase.
    Developer(CreateDeveloperIdentityConfig),
    /// Ephemeral CI setup: memory keychain, no git signing.
    Ci(CiIdentityConfig),
    /// Agent setup: file keychain, scoped capabilities, long-lived.
    Agent(CreateAgentIdentityConfig),
}

impl IdentityConfig {
    /// Create a developer identity config with sensible defaults.
    ///
    /// Args:
    /// * `alias`: Human-readable key alias (e.g. `"work-laptop"`).
    ///
    /// Usage:
    /// ```ignore
    /// let config = IdentityConfig::developer(KeyAlias::new_unchecked("work-laptop"));
    /// ```
    pub fn developer(alias: KeyAlias) -> Self {
        Self::Developer(CreateDeveloperIdentityConfig::builder(alias).build())
    }

    /// Create a CI/ephemeral identity config.
    ///
    /// Args:
    /// * `registry_path`: Path to the ephemeral auths registry directory.
    ///
    /// Usage:
    /// ```ignore
    /// let config = IdentityConfig::ci(PathBuf::from("/tmp/.auths-ci"));
    /// ```
    pub fn ci(registry_path: impl Into<PathBuf>) -> Self {
        Self::Ci(CiIdentityConfig {
            ci_environment: CiEnvironment::Unknown,
            registry_path: registry_path.into(),
        })
    }

    /// Create an agent identity config with sensible defaults.
    ///
    /// Args:
    /// * `alias`: Human-readable agent name.
    /// * `registry_path`: Path to the auths registry directory.
    ///
    /// Usage:
    /// ```ignore
    /// let config = IdentityConfig::agent(KeyAlias::new_unchecked("deploy-bot"), registry_path);
    /// ```
    pub fn agent(alias: KeyAlias, registry_path: impl Into<PathBuf>) -> Self {
        Self::Agent(CreateAgentIdentityConfig::builder(alias, registry_path).build())
    }
}

/// Configuration for agent identity.
///
/// Use [`CreateAgentIdentityConfigBuilder`] to construct this with optional fields.
///
/// Args:
/// * `alias`: Human-readable name for the agent.
/// * `parent_identity_did`: The DID of the identity that owns this agent.
/// * `registry_path`: Path to the auths registry.
///
/// Usage:
/// ```ignore
/// let config = CreateAgentIdentityConfig::builder("deploy-bot", "did:keri:abc123", path)
///     .with_capabilities(vec!["sign-commit".into()])
///     .build();
/// ```
#[derive(Debug)]
pub struct CreateAgentIdentityConfig {
    /// Human-readable name for the agent.
    pub alias: KeyAlias,
    /// Capabilities granted to the agent.
    pub capabilities: Vec<Capability>,
    /// DID of the parent identity that delegates authority.
    pub parent_identity_did: Option<String>,
    /// Path to the auths registry directory.
    pub registry_path: PathBuf,
    /// Duration in seconds until expiration (per RFC 6749).
    pub expires_in: Option<u64>,
    /// If true, construct state without persisting.
    pub dry_run: bool,
}

impl CreateAgentIdentityConfig {
    /// Creates a builder with alias and registry path.
    ///
    /// Args:
    /// * `alias`: Human-readable name for the agent.
    /// * `registry_path`: Path to the auths registry directory.
    ///
    /// Usage:
    /// ```ignore
    /// let builder = CreateAgentIdentityConfig::builder("deploy-bot", path);
    /// ```
    pub fn builder(
        alias: KeyAlias,
        registry_path: impl Into<PathBuf>,
    ) -> CreateAgentIdentityConfigBuilder {
        CreateAgentIdentityConfigBuilder {
            alias,
            capabilities: Vec::new(),
            parent_identity_did: None,
            registry_path: registry_path.into(),
            expires_in: None,
            dry_run: false,
        }
    }
}

/// Builder for [`CreateAgentIdentityConfig`].
#[derive(Debug)]
pub struct CreateAgentIdentityConfigBuilder {
    alias: KeyAlias,
    capabilities: Vec<Capability>,
    parent_identity_did: Option<String>,
    registry_path: PathBuf,
    expires_in: Option<u64>,
    dry_run: bool,
}

impl CreateAgentIdentityConfigBuilder {
    /// Sets the parent identity DID that delegates authority to this agent.
    ///
    /// Args:
    /// * `did`: The DID of the owning identity.
    ///
    /// Usage:
    /// ```ignore
    /// let config = CreateAgentIdentityConfig::builder("bot", path)
    ///     .with_parent_did("did:keri:abc123")
    ///     .build();
    /// ```
    pub fn with_parent_did(mut self, did: impl Into<String>) -> Self {
        self.parent_identity_did = Some(did.into());
        self
    }

    /// Sets the capabilities granted to the agent.
    ///
    /// Args:
    /// * `capabilities`: List of capabilities.
    ///
    /// Usage:
    /// ```ignore
    /// let config = CreateAgentIdentityConfig::builder("bot", path)
    ///     .with_capabilities(vec![Capability::sign_commit()])
    ///     .build();
    /// ```
    pub fn with_capabilities(mut self, capabilities: Vec<Capability>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Sets the agent key expiration time in seconds.
    ///
    /// Args:
    /// * `secs`: Seconds until the agent identity expires.
    ///
    /// Usage:
    /// ```ignore
    /// let config = CreateAgentIdentityConfig::builder("bot", path)
    ///     .with_expiry(86400) // 24 hours
    ///     .build();
    /// ```
    pub fn with_expiry(mut self, secs: u64) -> Self {
        self.expires_in = Some(secs);
        self
    }

    /// Enables dry-run mode (constructs state without persisting).
    ///
    /// Usage:
    /// ```ignore
    /// let config = CreateAgentIdentityConfig::builder("bot", path)
    ///     .dry_run(true)
    ///     .build();
    /// ```
    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Builds the final [`CreateAgentIdentityConfig`].
    ///
    /// Usage:
    /// ```ignore
    /// let config = CreateAgentIdentityConfig::builder("bot", path).build();
    /// ```
    pub fn build(self) -> CreateAgentIdentityConfig {
        CreateAgentIdentityConfig {
            alias: self.alias,
            capabilities: self.capabilities,
            parent_identity_did: self.parent_identity_did,
            registry_path: self.registry_path,
            expires_in: self.expires_in,
            dry_run: self.dry_run,
        }
    }
}

/// Configuration for rotating an identity's signing keys.
///
/// Args:
/// * `repo_path`: Path to the auths registry (typically `~/.auths`).
/// * `identity_key_alias`: Keychain alias of the current signing key.
///   If `None`, the first non-next alias for the identity is used.
/// * `next_key_alias`: Keychain alias to store the new key under.
///   Defaults to `<identity_key_alias>-rotated-<timestamp>`.
///
/// Usage:
/// ```ignore
/// let config = IdentityRotationConfig {
///     repo_path: PathBuf::from("/home/user/.auths"),
///     identity_key_alias: Some("main".into()),
///     next_key_alias: None,
/// };
/// ```
#[derive(Debug)]
pub struct IdentityRotationConfig {
    /// Path to the auths registry (typically `~/.auths`).
    pub repo_path: PathBuf,
    /// Keychain alias of the current signing key (auto-detected if `None`).
    pub identity_key_alias: Option<KeyAlias>,
    /// Keychain alias for the new rotated key (auto-generated if `None`).
    pub next_key_alias: Option<KeyAlias>,
}

// Result types for identity operations

/// Outcome of a successful developer identity setup.
///
/// Usage:
/// ```ignore
/// let result = initialize(IdentityConfig::developer(alias), &ctx, keychain, &signer, &provider, git_cfg)?;
/// if let InitializeResult::Developer(r) = result {
///     println!("Created identity: {}", r.identity_did);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct DeveloperIdentityResult {
    /// The controller DID of the created identity.
    pub identity_did: IdentityDID,
    /// The device DID bound to this identity.
    pub device_did: DeviceDID,
    /// The keychain alias used for the signing key.
    pub key_alias: KeyAlias,
    /// Result of platform verification, if performed.
    pub platform_claim: Option<crate::result::PlatformClaimResult>,
    /// Whether git commit signing was configured.
    pub git_signing_configured: bool,
    /// Result of registry registration, if performed.
    pub registered: Option<RegistrationOutcome>,
}

/// Outcome of a successful CI/ephemeral identity setup.
///
/// Usage:
/// ```ignore
/// let result = initialize(IdentityConfig::ci(registry_path), &ctx, keychain, &signer, &provider, None)?;
/// if let InitializeResult::Ci(r) = result {
///     for line in &r.env_block { println!("{line}"); }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CiIdentityResult {
    /// The controller DID of the CI identity.
    pub identity_did: IdentityDID,
    /// The device DID bound to this CI identity.
    pub device_did: DeviceDID,
    /// Shell `export` lines for configuring CI environment variables.
    pub env_block: Vec<String>,
}

/// Outcome of a successful agent identity setup.
///
/// Usage:
/// ```ignore
/// let result = initialize(IdentityConfig::agent(alias, path), &ctx, keychain, &signer, &provider, None)?;
/// if let InitializeResult::Agent(r) = result {
///     println!("Agent {:?} delegated by {:?}", r.agent_did, r.parent_did);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct AgentIdentityResult {
    /// The DID of the newly created agent identity (None for dry-run proposals).
    pub agent_did: Option<IdentityDID>,
    /// The DID of the parent identity that delegated authority (None if no parent).
    pub parent_did: Option<IdentityDID>,
    /// The capabilities granted to the agent.
    pub capabilities: Vec<Capability>,
}

/// Outcome of [`crate::setup::initialize`] — one variant per identity persona.
///
/// Usage:
/// ```ignore
/// match initialize(config, &ctx, keychain, &signer, &provider, git_cfg)? {
///     InitializeResult::Developer(r) => display_developer_result(r),
///     InitializeResult::Ci(r) => display_ci_result(r),
///     InitializeResult::Agent(r) => display_agent_result(r),
/// }
/// ```
#[derive(Debug, Clone)]
pub enum InitializeResult {
    /// Developer identity result.
    Developer(DeveloperIdentityResult),
    /// CI/ephemeral identity result.
    Ci(CiIdentityResult),
    /// Agent identity result.
    Agent(AgentIdentityResult),
}

/// Outcome of a successful identity rotation.
///
/// Usage:
/// ```ignore
/// let result: IdentityRotationResult = rotate_identity(config, provider)?;
/// println!("Rotated DID: {}", result.controller_did);
/// println!("New key:  {}...", result.new_key_fingerprint);
/// println!("Old key:  {}...", result.previous_key_fingerprint);
/// ```
#[derive(Debug, Clone)]
pub struct IdentityRotationResult {
    /// The controller DID of the rotated identity.
    pub controller_did: IdentityDID,
    /// Hex-encoded fingerprint of the new signing key.
    pub new_key_fingerprint: String,
    /// Hex-encoded fingerprint of the previous signing key.
    pub previous_key_fingerprint: String,
    /// KERI sequence number after this rotation event.
    pub sequence: u64,
}

/// Outcome of a successful registry registration.
///
/// Usage:
/// ```ignore
/// if let Some(reg) = result.registered {
///     println!("Registered {} at {}", reg.did, reg.registry);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct RegistrationOutcome {
    /// The DID returned by the registry (e.g. `did:keri:EABC...`).
    pub did: IdentityDID,
    /// The registry URL where the identity was registered.
    pub registry: String,
    /// Number of platform claims indexed by the registry.
    pub platform_claims_indexed: usize,
}
