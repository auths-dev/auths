use std::convert::TryInto;
use std::path::Path;

use auths_core::signing::{PassphraseProvider, SecureSigner, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use auths_id::attestation::create::create_signed_attestation;
use auths_id::identity::initialize::initialize_registry_identity;
use auths_id::storage::git_refs::AttestationMetadata;
use auths_id::storage::registry::install_linearity_hook;
use auths_verifier::types::DeviceDID;
use chrono::{DateTime, Utc};

use crate::context::AuthsContext;
use crate::error::{SdkStorageError, SetupError};
use crate::ports::git_config::GitConfigProvider;
use crate::result::{
    AgentSetupResult, CiSetupResult, PlatformClaimResult, RegistrationOutcome, SetupResult,
};
use crate::types::{
    AgentSetupConfig, CiEnvironment, CiSetupConfig, DeveloperSetupConfig, GitSigningScope,
    IdentityConflictPolicy, PlatformVerification,
};

/// Provisions a new developer identity with device linking, optional platform
/// verification, git signing, and registry publication.
///
/// This function is a pure orchestrator — it delegates every step to a small,
/// named helper and never performs I/O itself.
///
/// Args:
/// * `config`: All setup parameters (key alias, platform, etc.).
/// * `ctx`: Injected infrastructure adapters (registry, identity storage, attestation sink, clock).
/// * `keychain`: Platform keychain for key storage and retrieval.
/// * `signer`: Secure signer for creating attestation signatures.
/// * `passphrase_provider`: Provides passphrases for key encryption/decryption.
///
/// Usage:
/// ```ignore
/// let result = setup_developer(config, &ctx, keychain.as_ref(), &signer, &provider, git_cfg)?;
/// ```
pub fn setup_developer(
    config: DeveloperSetupConfig,
    ctx: &AuthsContext,
    keychain: &(dyn KeyStorage + Send + Sync),
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    git_config: Option<&dyn GitConfigProvider>,
) -> Result<SetupResult, SetupError> {
    let now = ctx.clock.now();
    let (controller_did, key_alias, reused) =
        resolve_or_create_identity(&config, ctx, keychain, passphrase_provider, now)?;
    let device_did = if reused {
        derive_device_did(&key_alias, keychain, passphrase_provider)?
    } else {
        bind_device(&key_alias, ctx, keychain, signer, passphrase_provider, now)?
    };
    let platform_claim = bind_platform_claim(&config.platform);
    let git_configured = configure_git_signing(
        &config.git_signing_scope,
        &key_alias,
        git_config,
        config.sign_binary_path.as_deref(),
    )?;
    let registered = submit_registration(&config);

    Ok(SetupResult {
        identity_did: controller_did,
        device_did: device_did.to_string(),
        key_alias,
        platform_claim,
        git_signing_configured: git_configured,
        registered,
    })
}

/// One-shot convenience wrapper that creates a developer identity with sensible
/// defaults: global git signing, no platform verification, no registry.
///
/// Args:
/// * `alias`: Human-readable name for the key (e.g. "main").
/// * `ctx`: Injected infrastructure adapters.
/// * `keychain`: Platform keychain backend.
/// * `signer`: Secure signer for attestation creation.
/// * `passphrase_provider`: Provides the passphrase for key encryption.
///
/// Usage:
/// ```ignore
/// let result = quick_setup("main", &ctx, keychain.as_ref(), &signer, &provider)?;
/// ```
pub fn quick_setup(
    alias: &KeyAlias,
    ctx: &AuthsContext,
    keychain: &(dyn KeyStorage + Send + Sync),
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
) -> Result<SetupResult, SetupError> {
    let config = DeveloperSetupConfig::builder(alias.clone()).build();
    setup_developer(config, ctx, keychain, signer, passphrase_provider, None)
}

/// Returns (controller_did, key_alias, reused).
fn resolve_or_create_identity(
    config: &DeveloperSetupConfig,
    ctx: &AuthsContext,
    keychain: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &dyn PassphraseProvider,
    now: DateTime<Utc>,
) -> Result<(String, KeyAlias, bool), SetupError> {
    if let Ok(existing) = ctx.identity_storage.load_identity() {
        match config.conflict_policy {
            IdentityConflictPolicy::Error => {
                return Err(SetupError::IdentityAlreadyExists {
                    did: existing.controller_did.into_inner(),
                });
            }
            IdentityConflictPolicy::ReuseExisting => {
                return Ok((
                    existing.controller_did.into_inner(),
                    config.key_alias.clone(),
                    true,
                ));
            }
            IdentityConflictPolicy::ForceNew => {}
        }
    }

    let (did, alias) = derive_keys(config, ctx, keychain, passphrase_provider, now)?;
    Ok((did, alias, false))
}

fn derive_keys(
    config: &DeveloperSetupConfig,
    ctx: &AuthsContext,
    keychain: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &dyn PassphraseProvider,
    _now: DateTime<Utc>,
) -> Result<(String, KeyAlias), SetupError> {
    let (controller_did, _key_event) = initialize_registry_identity(
        std::sync::Arc::clone(&ctx.registry),
        &config.key_alias,
        passphrase_provider,
        keychain,
        config.witness_config.as_ref(),
    )
    .map_err(|e| {
        SetupError::StorageError(SdkStorageError::OperationFailed(format!(
            "failed to initialize identity: {e}"
        )))
    })?;

    let did_str = controller_did.into_inner();
    ctx.identity_storage
        .create_identity(&did_str, None)
        .map_err(|e| {
            SetupError::StorageError(SdkStorageError::OperationFailed(format!(
                "failed to persist identity: {e}"
            )))
        })?;

    Ok((did_str, config.key_alias.clone()))
}

fn derive_device_did(
    key_alias: &KeyAlias,
    keychain: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &dyn PassphraseProvider,
) -> Result<DeviceDID, SetupError> {
    let pk_bytes = auths_core::storage::keychain::extract_public_key_bytes(
        keychain,
        key_alias,
        passphrase_provider,
    )?;

    let device_did = DeviceDID::from_ed25519(pk_bytes.as_slice().try_into().map_err(|_| {
        SetupError::CryptoError(auths_core::AgentError::InvalidInput(
            "public key is not 32 bytes".into(),
        ))
    })?);

    Ok(device_did)
}

fn bind_device(
    key_alias: &KeyAlias,
    ctx: &AuthsContext,
    keychain: &(dyn KeyStorage + Send + Sync),
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    now: DateTime<Utc>,
) -> Result<DeviceDID, SetupError> {
    let managed = ctx.identity_storage.load_identity().map_err(|e| {
        SetupError::StorageError(SdkStorageError::OperationFailed(format!(
            "failed to load identity for device linking: {e}"
        )))
    })?;

    let pk_bytes = auths_core::storage::keychain::extract_public_key_bytes(
        keychain,
        key_alias,
        passphrase_provider,
    )?;

    let device_did = DeviceDID::from_ed25519(pk_bytes.as_slice().try_into().map_err(|_| {
        SetupError::CryptoError(auths_core::AgentError::InvalidInput(
            "public key is not 32 bytes".into(),
        ))
    })?);

    let meta = AttestationMetadata {
        timestamp: Some(now),
        expires_at: None,
        note: Some("Linked by auths-sdk setup".to_string()),
    };

    let attestation = create_signed_attestation(
        now,
        &managed.storage_id,
        &managed.controller_did,
        &device_did,
        &pk_bytes,
        None,
        &meta,
        signer,
        passphrase_provider,
        Some(key_alias),
        Some(key_alias),
        vec![],
        None,
        None,
    )
    .map_err(|e| {
        SetupError::StorageError(SdkStorageError::OperationFailed(format!(
            "attestation creation failed: {e}"
        )))
    })?;

    ctx.attestation_sink
        .export(&auths_verifier::VerifiedAttestation::dangerous_from_unchecked(attestation))
        .map_err(|e| {
            SetupError::StorageError(SdkStorageError::OperationFailed(format!(
                "failed to save device attestation: {e}"
            )))
        })?;

    Ok(device_did)
}

fn bind_platform_claim(platform: &Option<PlatformVerification>) -> Option<PlatformClaimResult> {
    match platform {
        Some(PlatformVerification::GitHub { .. }) => None,
        Some(PlatformVerification::GitLab { .. }) => None,
        Some(PlatformVerification::Skip) | None => None,
    }
}

fn configure_git_signing(
    scope: &GitSigningScope,
    key_alias: &KeyAlias,
    git_config: Option<&dyn GitConfigProvider>,
    sign_binary_path: Option<&Path>,
) -> Result<bool, SetupError> {
    if matches!(scope, GitSigningScope::Skip) {
        return Ok(false);
    }
    let git_config = git_config.ok_or_else(|| {
        SetupError::GitConfigError("GitConfigProvider required for non-Skip scope".into())
    })?;
    let sign_binary_path = sign_binary_path.ok_or_else(|| {
        SetupError::GitConfigError("sign_binary_path required for non-Skip scope".into())
    })?;
    set_git_signing_config(key_alias, git_config, sign_binary_path)?;
    Ok(true)
}

fn set_git_signing_config(
    key_alias: &KeyAlias,
    git_config: &dyn GitConfigProvider,
    sign_binary_path: &Path,
) -> Result<(), SetupError> {
    let auths_sign_str = sign_binary_path
        .to_str()
        .ok_or_else(|| SetupError::GitConfigError("auths-sign path is not valid UTF-8".into()))?;
    let signing_key = format!("auths:{}", key_alias);
    let configs: &[(&str, &str)] = &[
        ("gpg.format", "ssh"),
        ("gpg.ssh.program", auths_sign_str),
        ("user.signingkey", &signing_key),
        ("commit.gpgsign", "true"),
        ("tag.gpgsign", "true"),
    ];
    for (key, val) in configs {
        git_config
            .set(key, val)
            .map_err(|e| SetupError::GitConfigError(e.to_string()))?;
    }
    Ok(())
}

fn submit_registration(config: &DeveloperSetupConfig) -> Option<RegistrationOutcome> {
    if !config.register_on_registry {
        return None;
    }
    None
}

// ── CI setup ────────────────────────────────────────────────────────────

/// Provisions an ephemeral CI identity for use in automated pipelines.
///
/// Unlike `setup_developer`, this function takes the keychain from
/// `CiSetupConfig` so callers can inject a memory keychain without mutating
/// environment variables.
///
/// Args:
/// * `config`: CI setup parameters including keychain, passphrase, and CI environment.
/// * `ctx`: Injected infrastructure adapters (registry, identity storage, attestation sink, clock).
///
/// Usage:
/// ```ignore
/// let result = setup_ci(config, &ctx)?;
/// ```
pub fn setup_ci(config: CiSetupConfig, ctx: &AuthsContext) -> Result<CiSetupResult, SetupError> {
    let now = ctx.clock.now();
    let provider = auths_core::PrefilledPassphraseProvider::new(&config.passphrase);
    let keychain = config.keychain;
    let (controller_did, key_alias) = create_ci_identity(ctx, keychain.as_ref(), &provider, now)?;
    let signer = StorageSigner::new(keychain);
    let device_did = bind_device(&key_alias, ctx, signer.inner(), &signer, &provider, now)?;
    let env_block =
        generate_ci_env_block(&key_alias, &config.registry_path, &config.ci_environment);

    Ok(CiSetupResult {
        identity_did: controller_did,
        device_did: device_did.to_string(),
        env_block,
    })
}

fn create_ci_identity(
    ctx: &AuthsContext,
    keychain: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &dyn PassphraseProvider,
    _now: DateTime<Utc>,
) -> Result<(String, KeyAlias), SetupError> {
    let key_alias = KeyAlias::new_unchecked("ci-key");

    let (controller_did, _) = initialize_registry_identity(
        std::sync::Arc::clone(&ctx.registry),
        &key_alias,
        passphrase_provider,
        keychain,
        None,
    )
    .map_err(|e| {
        SetupError::StorageError(SdkStorageError::OperationFailed(format!(
            "failed to initialize CI identity: {e}"
        )))
    })?;

    Ok((controller_did.into_inner(), key_alias))
}

fn generate_ci_env_block(
    key_alias: &KeyAlias,
    repo_path: &Path,
    environment: &CiEnvironment,
) -> Vec<String> {
    match environment {
        CiEnvironment::GitHubActions => generate_github_env_block(key_alias, repo_path),
        CiEnvironment::GitLabCi => generate_gitlab_env_block(key_alias, repo_path),
        CiEnvironment::Custom { name } => generate_generic_env_block(key_alias, repo_path, name),
        CiEnvironment::Unknown => generate_generic_env_block(key_alias, repo_path, "ci"),
    }
}

fn generate_github_env_block(key_alias: &KeyAlias, repo_path: &Path) -> Vec<String> {
    let mut lines = base_env_lines(key_alias, repo_path);
    lines.push(String::new());
    lines.push("# GitHub Actions: add these as repository secrets".to_string());
    lines.push("# then reference them in your workflow env: block".to_string());
    lines
}

fn generate_gitlab_env_block(key_alias: &KeyAlias, repo_path: &Path) -> Vec<String> {
    let mut lines = base_env_lines(key_alias, repo_path);
    lines.push(String::new());
    lines.push("# GitLab CI: add these as CI/CD variables".to_string());
    lines.push("# in Settings > CI/CD > Variables".to_string());
    lines
}

fn generate_generic_env_block(
    key_alias: &KeyAlias,
    repo_path: &Path,
    platform: &str,
) -> Vec<String> {
    let mut lines = base_env_lines(key_alias, repo_path);
    lines.push(String::new());
    lines.push(format!("# {platform}: add these as environment variables"));
    lines
}

fn base_env_lines(key_alias: &KeyAlias, repo_path: &Path) -> Vec<String> {
    vec![
        format!("export AUTHS_KEYCHAIN_BACKEND=\"memory\""),
        format!("export AUTHS_REPO=\"{}\"", repo_path.display()),
        format!("export AUTHS_KEY_ALIAS=\"{key_alias}\""),
        String::new(),
        format!("export GIT_CONFIG_COUNT=4"),
        format!("export GIT_CONFIG_KEY_0=\"gpg.format\""),
        format!("export GIT_CONFIG_VALUE_0=\"ssh\""),
        format!("export GIT_CONFIG_KEY_1=\"gpg.ssh.program\""),
        format!("export GIT_CONFIG_VALUE_1=\"auths-sign\""),
        format!("export GIT_CONFIG_KEY_2=\"user.signingKey\""),
        format!("export GIT_CONFIG_VALUE_2=\"auths:{key_alias}\""),
        format!("export GIT_CONFIG_KEY_3=\"commit.gpgSign\""),
        format!("export GIT_CONFIG_VALUE_3=\"true\""),
    ]
}

// ── Agent setup ─────────────────────────────────────────────────────────

/// Provisions an agent identity delegated from a parent identity.
///
/// Constructs all proposed state first, then persists only if `dry_run` is false.
///
/// Args:
/// * `config`: Agent setup parameters (alias, parent DID, capabilities, etc.).
/// * `ctx`: Injected infrastructure adapters (registry, clock).
/// * `keychain`: Platform keychain for key storage.
/// * `passphrase_provider`: Provides passphrases for key operations.
///
/// Usage:
/// ```ignore
/// let result = setup_agent(config, &ctx, keychain, &provider)?;
/// ```
pub fn setup_agent(
    config: AgentSetupConfig,
    ctx: &AuthsContext,
    keychain: Box<dyn KeyStorage + Send + Sync>,
    passphrase_provider: &dyn PassphraseProvider,
) -> Result<AgentSetupResult, SetupError> {
    use auths_id::agent_identity::{AgentProvisioningConfig, AgentStorageMode};

    let provisioning_config = AgentProvisioningConfig {
        agent_name: config.alias.to_string(),
        capabilities: config.capabilities.clone(),
        expires_in_secs: config.expires_in_secs,
        delegated_by: config
            .parent_identity_did
            .clone()
            .map(auths_core::storage::keychain::IdentityDID::new),
        storage_mode: AgentStorageMode::Persistent {
            repo_path: Some(config.registry_path.clone()),
        },
    };

    let proposed = build_agent_proposal(&provisioning_config, &config)?;

    if !config.dry_run {
        let bundle = auths_id::agent_identity::provision_agent_identity(
            ctx.clock.now(),
            std::sync::Arc::clone(&ctx.registry),
            provisioning_config,
            passphrase_provider,
            keychain,
        )
        .map_err(|e| {
            SetupError::StorageError(SdkStorageError::OperationFailed(format!(
                "agent provisioning failed: {e}"
            )))
        })?;

        return Ok(AgentSetupResult {
            agent_did: bundle.agent_did,
            parent_did: config.parent_identity_did.unwrap_or_default(),
            capabilities: config.capabilities,
        });
    }

    Ok(proposed)
}

fn build_agent_proposal(
    _provisioning_config: &auths_id::agent_identity::AgentProvisioningConfig,
    config: &AgentSetupConfig,
) -> Result<AgentSetupResult, SetupError> {
    Ok(AgentSetupResult {
        agent_did: format!("did:keri:E<pending:{}>", config.alias),
        parent_did: config.parent_identity_did.clone().unwrap_or_default(),
        capabilities: config.capabilities.clone(),
    })
}

/// Install the linearity hook in a registry directory.
///
/// This is called by the CLI after initializing the git repository to prevent
/// non-linear KEL history.
///
/// Args:
/// * `registry_path`: Path to the initialized git repository.
///
/// Usage:
/// ```ignore
/// auths_sdk::setup::install_registry_hook(&registry_path);
/// ```
pub fn install_registry_hook(registry_path: &Path) {
    let _ = install_linearity_hook(registry_path);
}
