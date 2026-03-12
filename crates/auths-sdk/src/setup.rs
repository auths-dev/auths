use std::convert::TryInto;
use std::path::Path;
use std::sync::Arc;

use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};
use auths_id::attestation::create::create_signed_attestation;
use auths_id::identity::initialize::initialize_registry_identity;
use auths_id::storage::git_refs::AttestationMetadata;
use auths_id::storage::registry::install_linearity_hook;
use auths_verifier::types::DeviceDID;
use chrono::{DateTime, Utc};

use crate::context::AuthsContext;
use crate::error::SetupError;
use crate::ports::git_config::GitConfigProvider;
use crate::result::{
    AgentIdentityResult, CiIdentityResult, DeveloperIdentityResult, InitializeResult,
    PlatformClaimResult, RegistrationOutcome,
};
use crate::types::{
    CiEnvironment, CiIdentityConfig, CreateAgentIdentityConfig, CreateDeveloperIdentityConfig,
    GitSigningScope, IdentityConfig, IdentityConflictPolicy, PlatformVerification,
};

/// Provisions a new identity for the requested persona.
///
/// Dispatches to the appropriate setup path based on the `config` variant.
/// No deprecated shims — callers migrate directly to this function.
///
/// Args:
/// * `config`: Identity persona and all setup parameters.
/// * `ctx`: Injected infrastructure adapters (registry, identity storage, attestation sink, clock).
/// * `keychain`: Platform keychain for key storage and retrieval.
/// * `signer`: Secure signer for creating attestation signatures.
/// * `passphrase_provider`: Provides passphrases for key encryption/decryption.
/// * `git_config`: Git configuration provider; required when git signing is configured.
///
/// Usage:
/// ```ignore
/// let keychain: Arc<dyn KeyStorage + Send + Sync> = Arc::new(platform_keychain);
/// let result = initialize(IdentityConfig::developer(alias), &ctx, keychain, &signer, &provider, git_cfg)?;
/// match result {
///     InitializeResult::Developer(r) => println!("Identity: {}", r.identity_did),
///     InitializeResult::Ci(r) => println!("CI env block: {} lines", r.env_block.len()),
///     InitializeResult::Agent(r) => println!("Agent: {}", r.agent_did),
/// }
/// ```
pub fn initialize(
    config: IdentityConfig,
    ctx: &AuthsContext,
    keychain: Arc<dyn KeyStorage + Send + Sync>,
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    git_config: Option<&dyn GitConfigProvider>,
) -> Result<InitializeResult, SetupError> {
    match config {
        IdentityConfig::Developer(dev_config) => initialize_developer(
            dev_config,
            ctx,
            keychain.as_ref(),
            signer,
            passphrase_provider,
            git_config,
        )
        .map(InitializeResult::Developer),
        IdentityConfig::Ci(ci_config) => initialize_ci(
            ci_config,
            ctx,
            keychain.as_ref(),
            signer,
            passphrase_provider,
        )
        .map(InitializeResult::Ci),
        IdentityConfig::Agent(agent_config) => {
            initialize_agent(agent_config, ctx, Box::new(keychain), passphrase_provider)
                .map(InitializeResult::Agent)
        }
    }
}

fn initialize_developer(
    config: CreateDeveloperIdentityConfig,
    ctx: &AuthsContext,
    keychain: &(dyn KeyStorage + Send + Sync),
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    git_config: Option<&dyn GitConfigProvider>,
) -> Result<DeveloperIdentityResult, SetupError> {
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

    Ok(DeveloperIdentityResult {
        identity_did: IdentityDID::new_unchecked(controller_did),
        device_did,
        key_alias,
        platform_claim,
        git_signing_configured: git_configured,
        registered,
    })
}

fn initialize_ci(
    config: CiIdentityConfig,
    ctx: &AuthsContext,
    keychain: &(dyn KeyStorage + Send + Sync),
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
) -> Result<CiIdentityResult, SetupError> {
    let now = ctx.clock.now();
    let (controller_did, key_alias) = initialize_ci_keys(ctx, keychain, passphrase_provider, now)?;
    let device_did = bind_device(&key_alias, ctx, keychain, signer, passphrase_provider, now)?;
    let env_block =
        generate_ci_env_block(&key_alias, &config.registry_path, &config.ci_environment);

    Ok(CiIdentityResult {
        identity_did: IdentityDID::new_unchecked(controller_did),
        device_did,
        env_block,
    })
}

fn initialize_agent(
    config: CreateAgentIdentityConfig,
    ctx: &AuthsContext,
    keychain: Box<dyn KeyStorage + Send + Sync>,
    passphrase_provider: &dyn PassphraseProvider,
) -> Result<AgentIdentityResult, SetupError> {
    use auths_id::agent_identity::{AgentProvisioningConfig, AgentStorageMode};

    let cap_strings: Vec<String> = config.capabilities.iter().map(|c| c.to_string()).collect();
    let provisioning_config = AgentProvisioningConfig {
        agent_name: config.alias.to_string(),
        capabilities: cap_strings,
        expires_in_secs: config.expires_in_secs,
        delegated_by: config
            .parent_identity_did
            .clone()
            .map(IdentityDID::new_unchecked),
        storage_mode: AgentStorageMode::Persistent {
            repo_path: Some(config.registry_path.clone()),
        },
    };

    let proposed = build_agent_identity_proposal(&provisioning_config, &config)?;

    if !config.dry_run {
        let bundle = auths_id::agent_identity::provision_agent_identity(
            ctx.clock.now(),
            std::sync::Arc::clone(&ctx.registry),
            provisioning_config,
            passphrase_provider,
            keychain,
        )
        .map_err(|e| SetupError::StorageError(e.into()))?;

        return Ok(AgentIdentityResult {
            agent_did: bundle.agent_did,
            parent_did: IdentityDID::new_unchecked(config.parent_identity_did.unwrap_or_default()),
            capabilities: config.capabilities,
        });
    }

    Ok(proposed)
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

// ── Private helpers ──────────────────────────────────────────────────────

/// Returns (controller_did, key_alias, reused).
fn resolve_or_create_identity(
    config: &CreateDeveloperIdentityConfig,
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
    config: &CreateDeveloperIdentityConfig,
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
    .map_err(|e| SetupError::StorageError(e.into()))?;

    let did_str = controller_did.into_inner();
    ctx.identity_storage
        .create_identity(&did_str, None)
        .map_err(|e| SetupError::StorageError(e.into()))?;

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
    let managed = ctx
        .identity_storage
        .load_identity()
        .map_err(|e| SetupError::StorageError(e.into()))?;

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
    .map_err(|e| SetupError::StorageError(e.into()))?;

    ctx.attestation_sink
        .export(&auths_verifier::VerifiedAttestation::dangerous_from_unchecked(attestation))
        .map_err(|e| SetupError::StorageError(e.into()))?;

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
        SetupError::InvalidSetupConfig("GitConfigProvider required for non-Skip scope".into())
    })?;
    let sign_binary_path = sign_binary_path.ok_or_else(|| {
        SetupError::InvalidSetupConfig("sign_binary_path required for non-Skip scope".into())
    })?;
    set_git_signing_config(key_alias, git_config, sign_binary_path)?;
    Ok(true)
}

fn set_git_signing_config(
    key_alias: &KeyAlias,
    git_config: &dyn GitConfigProvider,
    sign_binary_path: &Path,
) -> Result<(), SetupError> {
    let auths_sign_str = sign_binary_path.to_str().ok_or_else(|| {
        SetupError::InvalidSetupConfig("auths-sign path is not valid UTF-8".into())
    })?;
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
            .map_err(SetupError::GitConfigError)?;
    }
    Ok(())
}

fn submit_registration(config: &CreateDeveloperIdentityConfig) -> Option<RegistrationOutcome> {
    if !config.register_on_registry {
        return None;
    }
    None
}

fn initialize_ci_keys(
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
    .map_err(|e| SetupError::StorageError(e.into()))?;

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

fn build_agent_identity_proposal(
    _provisioning_config: &auths_id::agent_identity::AgentProvisioningConfig,
    config: &CreateAgentIdentityConfig,
) -> Result<AgentIdentityResult, SetupError> {
    Ok(AgentIdentityResult {
        agent_did: IdentityDID::new_unchecked(format!("did:keri:E<pending:{}>", config.alias)),
        parent_did: IdentityDID::new_unchecked(
            config.parent_identity_did.clone().unwrap_or_default(),
        ),
        capabilities: config.capabilities.clone(),
    })
}
