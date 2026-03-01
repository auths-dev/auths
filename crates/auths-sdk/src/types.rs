use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use std::path::PathBuf;

/// Policy for handling an existing identity during developer setup.
///
/// Replaces interactive CLI prompts with a typed enum that headless consumers
/// can set programmatically.
///
/// Usage:
/// ```ignore
/// let config = DeveloperSetupConfig::builder("my-key")
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

/// How to verify a platform identity.
///
/// The CLI obtains tokens interactively (OAuth device flow, browser open).
/// The SDK accepts the resulting token — it never opens a browser.
///
/// Usage:
/// ```ignore
/// let platform = PlatformVerification::GitHub {
///     access_token: "ghp_abc123".into(),
/// };
/// ```
#[derive(Debug, Clone)]
pub enum PlatformVerification {
    /// Verify via GitHub using a personal access token.
    GitHub {
        /// The GitHub personal access token.
        access_token: String,
    },
    /// Verify via GitLab using a personal access token.
    GitLab {
        /// The GitLab personal access token.
        access_token: String,
    },
    /// Skip platform verification.
    Skip,
}

/// Whether and how to configure Git commit signing.
///
/// Usage:
/// ```ignore
/// let scope = GitSigningScope::Global;
/// ```
#[derive(Debug, Clone, Default)]
pub enum GitSigningScope {
    /// Configure signing for a specific repository only.
    Local {
        /// Path to the repository to configure.
        repo_path: PathBuf,
    },
    /// Configure signing globally for all repositories (default).
    #[default]
    Global,
    /// Do not configure git signing.
    Skip,
}

/// CI platform environment.
///
/// Usage:
/// ```ignore
/// let env = CiEnvironment::GitHubActions;
/// ```
#[derive(Debug, Clone)]
pub enum CiEnvironment {
    /// GitHub Actions CI environment.
    GitHubActions,
    /// GitLab CI/CD environment.
    GitLabCi,
    /// A custom CI platform with a user-provided name.
    Custom {
        /// The name of the custom CI platform.
        name: String,
    },
    /// The CI platform could not be detected.
    Unknown,
}

/// Configuration for provisioning a new developer identity.
///
/// Use [`DeveloperSetupConfigBuilder`] to construct this with optional fields.
/// The registry backend is injected via [`crate::context::AuthsContext`] — this
/// struct carries only serializable configuration values.
///
/// Args:
/// * `key_alias`: Human-readable name for the key (e.g. "work-laptop").
///
/// Usage:
/// ```ignore
/// let config = DeveloperSetupConfig::builder("work-laptop")
///     .with_platform(PlatformVerification::GitHub { access_token: "ghp_abc".into() })
///     .with_git_signing_scope(GitSigningScope::Global)
///     .build();
/// ```
#[derive(Debug)]
pub struct DeveloperSetupConfig {
    /// Human-readable name for the key (e.g. "work-laptop").
    pub key_alias: KeyAlias,
    /// Optional platform verification configuration.
    pub platform: Option<PlatformVerification>,
    /// How to configure git commit signing.
    pub git_signing_scope: GitSigningScope,
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
}

impl DeveloperSetupConfig {
    /// Creates a builder with the required key alias.
    ///
    /// Args:
    /// * `key_alias`: Human-readable name for the key.
    ///
    /// Usage:
    /// ```ignore
    /// let builder = DeveloperSetupConfig::builder("my-key");
    /// ```
    pub fn builder(key_alias: KeyAlias) -> DeveloperSetupConfigBuilder {
        DeveloperSetupConfigBuilder {
            key_alias,
            platform: None,
            git_signing_scope: GitSigningScope::Global,
            register_on_registry: false,
            registry_url: None,
            conflict_policy: IdentityConflictPolicy::Error,
            witness_config: None,
            metadata: None,
            sign_binary_path: None,
        }
    }
}

/// Builder for [`DeveloperSetupConfig`].
#[derive(Debug)]
pub struct DeveloperSetupConfigBuilder {
    key_alias: KeyAlias,
    platform: Option<PlatformVerification>,
    git_signing_scope: GitSigningScope,
    register_on_registry: bool,
    registry_url: Option<String>,
    conflict_policy: IdentityConflictPolicy,
    witness_config: Option<auths_id::witness_config::WitnessConfig>,
    metadata: Option<serde_json::Value>,
    sign_binary_path: Option<PathBuf>,
}

impl DeveloperSetupConfigBuilder {
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
    /// let config = DeveloperSetupConfig::builder("my-key")
    ///     .with_platform(PlatformVerification::GitHub {
    ///         access_token: "ghp_abc123".into(),
    ///     })
    ///     .build();
    /// ```
    pub fn with_platform(mut self, platform: PlatformVerification) -> Self {
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
    /// let config = DeveloperSetupConfig::builder("my-key")
    ///     .with_git_signing_scope(GitSigningScope::Local {
    ///         repo_path: PathBuf::from("/path/to/repo"),
    ///     })
    ///     .build();
    /// ```
    pub fn with_git_signing_scope(mut self, scope: GitSigningScope) -> Self {
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
    /// let config = DeveloperSetupConfig::builder("my-key")
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
    /// let config = DeveloperSetupConfig::builder("my-key")
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
    /// let config = DeveloperSetupConfig::builder("my-key")
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
    /// let config = DeveloperSetupConfig::builder("my-key")
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
    /// let config = DeveloperSetupConfig::builder("my-key")
    ///     .with_sign_binary_path(PathBuf::from("/usr/local/bin/auths-sign"))
    ///     .build();
    /// ```
    pub fn with_sign_binary_path(mut self, path: PathBuf) -> Self {
        self.sign_binary_path = Some(path);
        self
    }

    /// Builds the final [`DeveloperSetupConfig`].
    ///
    /// Usage:
    /// ```ignore
    /// let config = DeveloperSetupConfig::builder("my-key").build();
    /// ```
    pub fn build(self) -> DeveloperSetupConfig {
        DeveloperSetupConfig {
            key_alias: self.key_alias,
            platform: self.platform,
            git_signing_scope: self.git_signing_scope,
            register_on_registry: self.register_on_registry,
            registry_url: self.registry_url,
            conflict_policy: self.conflict_policy,
            witness_config: self.witness_config,
            metadata: self.metadata,
            sign_binary_path: self.sign_binary_path,
        }
    }
}

/// Configuration for CI/ephemeral identity.
///
/// Args:
/// * `ci_environment`: The detected or specified CI platform.
/// * `passphrase`: Passphrase for key encryption (typically from env var).
/// * `registry_path`: Path to the ephemeral auths registry.
/// * `keychain`: The key storage backend (use `MemoryKeyStorage` for CI).
///
/// Usage:
/// ```ignore
/// let config = CiSetupConfig {
///     ci_environment: CiEnvironment::GitHubActions,
///     passphrase: std::env::var("AUTHS_PASSPHRASE").unwrap(),
///     registry_path: PathBuf::from("/tmp/.auths"),
///     keychain: Box::new(memory_keychain),
/// };
/// ```
pub struct CiSetupConfig {
    /// The detected or specified CI platform.
    pub ci_environment: CiEnvironment,
    /// Passphrase for key encryption (typically from an environment variable).
    pub passphrase: String,
    /// Path to the ephemeral auths registry directory.
    pub registry_path: PathBuf,
    /// Key storage backend (typically `MemoryKeyStorage` for CI).
    pub keychain: Box<dyn KeyStorage + Send + Sync>,
}

impl std::fmt::Debug for CiSetupConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CiSetupConfig")
            .field("ci_environment", &self.ci_environment)
            .field("registry_path", &self.registry_path)
            .field("passphrase", &"[REDACTED]")
            .finish()
    }
}

/// Configuration for agent identity.
///
/// Use [`AgentSetupConfigBuilder`] to construct this with optional fields.
///
/// Args:
/// * `alias`: Human-readable name for the agent.
/// * `parent_identity_did`: The DID of the identity that owns this agent.
/// * `registry_path`: Path to the auths registry.
///
/// Usage:
/// ```ignore
/// let config = AgentSetupConfig::builder("deploy-bot", "did:keri:abc123", path)
///     .with_capabilities(vec!["sign-commit".into()])
///     .build();
/// ```
#[derive(Debug)]
pub struct AgentSetupConfig {
    /// Human-readable name for the agent.
    pub alias: KeyAlias,
    /// Capability strings granted to the agent.
    pub capabilities: Vec<String>,
    /// DID of the parent identity that delegates authority.
    pub parent_identity_did: Option<String>,
    /// Path to the auths registry directory.
    pub registry_path: PathBuf,
    /// Optional agent key expiration time in seconds.
    pub expires_in_secs: Option<u64>,
    /// If true, construct state without persisting.
    pub dry_run: bool,
}

impl AgentSetupConfig {
    /// Creates a builder with alias and registry path.
    ///
    /// Args:
    /// * `alias`: Human-readable name for the agent.
    /// * `registry_path`: Path to the auths registry directory.
    ///
    /// Usage:
    /// ```ignore
    /// let builder = AgentSetupConfig::builder("deploy-bot", path);
    /// ```
    pub fn builder(alias: KeyAlias, registry_path: impl Into<PathBuf>) -> AgentSetupConfigBuilder {
        AgentSetupConfigBuilder {
            alias,
            capabilities: Vec::new(),
            parent_identity_did: None,
            registry_path: registry_path.into(),
            expires_in_secs: None,
            dry_run: false,
        }
    }
}

/// Builder for [`AgentSetupConfig`].
#[derive(Debug)]
pub struct AgentSetupConfigBuilder {
    alias: KeyAlias,
    capabilities: Vec<String>,
    parent_identity_did: Option<String>,
    registry_path: PathBuf,
    expires_in_secs: Option<u64>,
    dry_run: bool,
}

impl AgentSetupConfigBuilder {
    /// Sets the parent identity DID that delegates authority to this agent.
    ///
    /// Args:
    /// * `did`: The DID of the owning identity.
    ///
    /// Usage:
    /// ```ignore
    /// let config = AgentSetupConfig::builder("bot", path)
    ///     .with_parent_did("did:keri:abc123")
    ///     .build();
    /// ```
    pub fn with_parent_did(mut self, did: impl Into<String>) -> Self {
        self.parent_identity_did = Some(did.into());
        self
    }

    /// Sets the capabilities granted to the agent (e.g. "sign-commit").
    ///
    /// Args:
    /// * `capabilities`: List of capability strings.
    ///
    /// Usage:
    /// ```ignore
    /// let config = AgentSetupConfig::builder("bot", path)
    ///     .with_capabilities(vec!["sign-commit".into(), "sign-tag".into()])
    ///     .build();
    /// ```
    pub fn with_capabilities(mut self, capabilities: Vec<String>) -> Self {
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
    /// let config = AgentSetupConfig::builder("bot", path)
    ///     .with_expiry(86400) // 24 hours
    ///     .build();
    /// ```
    pub fn with_expiry(mut self, secs: u64) -> Self {
        self.expires_in_secs = Some(secs);
        self
    }

    /// Enables dry-run mode (constructs state without persisting).
    ///
    /// Usage:
    /// ```ignore
    /// let config = AgentSetupConfig::builder("bot", path)
    ///     .dry_run(true)
    ///     .build();
    /// ```
    pub fn dry_run(mut self, enabled: bool) -> Self {
        self.dry_run = enabled;
        self
    }

    /// Builds the final [`AgentSetupConfig`].
    ///
    /// Usage:
    /// ```ignore
    /// let config = AgentSetupConfig::builder("bot", path).build();
    /// ```
    pub fn build(self) -> AgentSetupConfig {
        AgentSetupConfig {
            alias: self.alias,
            capabilities: self.capabilities,
            parent_identity_did: self.parent_identity_did,
            registry_path: self.registry_path,
            expires_in_secs: self.expires_in_secs,
            dry_run: self.dry_run,
        }
    }
}

/// Configuration for extending a device authorization's expiration.
///
/// Args:
/// * `repo_path`: Path to the auths registry.
/// * `device_did`: The DID of the device whose authorization to extend.
/// * `days`: Number of days from now for the new expiration.
/// * `identity_key_alias`: Keychain alias for the identity key (for re-signing).
/// * `device_key_alias`: Keychain alias for the device key (for re-signing).
///
/// Usage:
/// ```ignore
/// let config = DeviceExtensionConfig {
///     repo_path: PathBuf::from("/home/user/.auths"),
///     device_did: "did:key:z6Mk...".into(),
///     days: 365,
///     identity_key_alias: "my-identity".into(),
///     device_key_alias: "my-device".into(),
/// };
/// ```
#[derive(Debug)]
pub struct DeviceExtensionConfig {
    /// Path to the auths registry.
    pub repo_path: PathBuf,
    /// DID of the device whose authorization to extend.
    pub device_did: String,
    /// Number of days from now for the new expiration.
    pub days: u32,
    /// Keychain alias for the identity signing key.
    pub identity_key_alias: KeyAlias,
    /// Keychain alias for the device signing key.
    pub device_key_alias: KeyAlias,
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
/// let config = RotationConfig {
///     repo_path: PathBuf::from("/home/user/.auths"),
///     identity_key_alias: Some("main".into()),
///     next_key_alias: None,
/// };
/// ```
#[derive(Debug)]
pub struct RotationConfig {
    /// Path to the auths registry (typically `~/.auths`).
    pub repo_path: PathBuf,
    /// Keychain alias of the current signing key (auto-detected if `None`).
    pub identity_key_alias: Option<KeyAlias>,
    /// Keychain alias for the new rotated key (auto-generated if `None`).
    pub next_key_alias: Option<KeyAlias>,
}

/// Configuration for linking a device to an existing identity.
///
/// Args:
/// * `identity_key_alias`: Alias of the identity key in the keychain.
///
/// Usage:
/// ```ignore
/// let config = DeviceLinkConfig {
///     identity_key_alias: "my-identity".into(),
///     device_key_alias: Some("macbook-pro".into()),
///     device_did: None,
///     capabilities: vec!["sign-commit".into()],
///     expires_in_days: Some(365),
///     note: Some("Work laptop".into()),
///     payload: None,
/// };
/// ```
#[derive(Debug)]
pub struct DeviceLinkConfig {
    /// Alias of the identity key in the keychain.
    pub identity_key_alias: KeyAlias,
    /// Optional alias for the device key (defaults to identity alias).
    pub device_key_alias: Option<KeyAlias>,
    /// Optional pre-existing device DID (not yet supported).
    pub device_did: Option<String>,
    /// Capability strings to grant to the linked device.
    pub capabilities: Vec<String>,
    /// Optional expiration period in days.
    pub expires_in_days: Option<u32>,
    /// Optional human-readable note for the attestation.
    pub note: Option<String>,
    /// Optional JSON payload to embed in the attestation.
    pub payload: Option<serde_json::Value>,
}
