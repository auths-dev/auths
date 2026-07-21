use std::path::Path;
use std::sync::Arc;

use auths_core::signing::{PassphraseProvider, SecureSigner};
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};
use auths_id::attestation::create::create_signed_attestation;
use auths_id::identity::initialize::initialize_registry_identity;
use auths_id::storage::git_refs::AttestationMetadata;
use auths_id::storage::registry::install_linearity_hook;
use auths_verifier::types::CanonicalDid;
use chrono::{DateTime, Utc};

use crate::context::AuthsContext;
use crate::domains::ci::types::{CiEnvironment, CiIdentityConfig};
use crate::domains::identity::error::SetupError;
use crate::domains::identity::types::{
    AgentIdentityResult, CiIdentityResult, CreateAgentIdentityConfig,
    CreateDeveloperIdentityConfig, DeveloperIdentityResult, IdentityConfig, IdentityConflictPolicy,
    InitializeResult, RegistrationOutcome,
};
use crate::domains::signing::types::PlatformClaimResult;
use crate::domains::signing::types::{GitSigningScope, PlatformVerification};
use crate::ports::git_config::GitConfigProvider;

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
            initialize_agent(agent_config, ctx, keychain, passphrase_provider)
                .map(InitializeResult::Agent)
        }
    }
}

fn initialize_developer(
    config: CreateDeveloperIdentityConfig,
    ctx: &AuthsContext,
    keychain: &(dyn KeyStorage + Send + Sync),
    _signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    git_config: Option<&dyn GitConfigProvider>,
) -> Result<DeveloperIdentityResult, SetupError> {
    let now = ctx.clock.now();
    let (controller_did, key_alias, reused) =
        resolve_or_create_identity(&config, ctx, keychain, passphrase_provider, now)?;
    // Delegate device #0 so the primary device has its own AID, distinct from the root
    // identity (fixes identity_did == device_did; makes the device independently revocable).
    // A re-run over an existing identity keeps the existing device DID.
    // `git_signing_alias` is the key git signs commits with. For a fresh identity that is
    // delegated device #0's key, so the SSH signature matches the `Auths-Device` trailer;
    // a re-run over an existing identity keeps signing with the root's key.
    let (device_did, git_signing_alias) = if reused {
        (
            derive_device_did(&key_alias, keychain, passphrase_provider)?,
            key_alias.clone(),
        )
    } else {
        delegate_primary_device(
            &controller_did,
            &key_alias,
            ctx,
            keychain,
            passphrase_provider,
        )?
    };
    let platform_claim = bind_platform_claim(&config.platform);
    let git_configured = configure_git_signing(
        &config.git_signing_scope,
        &git_signing_alias,
        git_config,
        config.sign_binary_path.as_deref(),
    )?;
    let registered = submit_registration(&config);

    Ok(DeveloperIdentityResult {
        identity_did: controller_did,
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
    // Commit-time trailers for CI: the hook reads `$AUTHS_REPO/commit-trailers`
    // (AUTHS_REPO is in the env block), so commits made in CI carry the
    // Auths-Id/Auths-Device trailers without an `auths sign HEAD` step. The CI
    // identity is a root identity signing directly, so Auths-Device is the root
    // `did:keri:` itself (a replayable KEL), matching `resolve_local_signer`.
    // Best-effort: a hook-install failure must not fail CI identity creation —
    // the explicit `auths sign <ref>` path still works without it.
    let hooks_dir = crate::workflows::commit_hooks::install_commit_hooks(
        &config.registry_path,
        controller_did.as_str(),
        controller_did.as_str(),
    )
    .ok();
    // Stamp the current KEL position into the trailer file (best-effort).
    let _ = crate::workflows::commit_hooks::refresh_commit_trailers(ctx, &config.registry_path);
    let env_block = generate_ci_env_block(
        &key_alias,
        &config.registry_path,
        &config.keychain_file,
        &config.passphrase,
        &config.ci_environment,
        hooks_dir.as_deref(),
    );

    Ok(CiIdentityResult {
        identity_did: controller_did,
        device_did,
        env_block,
    })
}

fn initialize_agent(
    config: CreateAgentIdentityConfig,
    _ctx: &AuthsContext,
    _keychain: Arc<dyn KeyStorage + Send + Sync>,
    _passphrase_provider: &dyn PassphraseProvider,
) -> Result<AgentIdentityResult, SetupError> {
    use auths_id::agent_identity::{AgentProvisioningConfig, AgentStorageMode};

    let delegated_by = config
        .parent_identity_did
        .clone()
        .map(IdentityDID::try_from)
        .transpose()
        .map_err(|e| SetupError::InvalidSetupConfig(format!("invalid parent identity did: {e}")))?;

    let provisioning_config = AgentProvisioningConfig {
        agent_name: config.alias.to_string(),
        capabilities: config.capabilities.clone(),
        expires_in: config.expires_in,
        delegated_by,
        storage_mode: AgentStorageMode::Persistent {
            repo_path: Some(config.registry_path.clone()),
        },
    };

    // Dry run previews the delegated agent. Standalone-`icp` agent provisioning was
    // retired in Epic E: an agent is a KERI delegated identifier, created against an
    // existing root via `auths id agent add` (SDK `agents::add`), not initialized
    // standalone.
    let proposed = build_agent_identity_proposal(&provisioning_config, &config)?;
    if !config.dry_run {
        return Err(SetupError::InvalidSetupConfig(
            "standalone agent initialization is retired — an agent is a KERI delegated \
             identifier. Run `auths init` for your root identity, then \
             `auths id agent add --label <name>` to delegate an agent."
                .to_string(),
        ));
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
) -> Result<(IdentityDID, KeyAlias, bool), SetupError> {
    if let Ok(existing) = ctx.identity_storage.load_identity() {
        match config.conflict_policy {
            IdentityConflictPolicy::Error => {
                return Err(SetupError::IdentityAlreadyExists {
                    did: existing.controller_did.into_inner(),
                });
            }
            IdentityConflictPolicy::ReuseExisting => {
                return Ok((existing.controller_did, config.key_alias.clone(), true));
            }
            IdentityConflictPolicy::ForceNew => {}
        }
    }

    let (did, alias) = derive_keys(config, ctx, keychain, passphrase_provider, now)?;
    Ok((did, alias, false))
}

/// Map an identity-initialization failure to a `SetupError`, preserving the
/// weak-passphrase case as its own typed variant (E5008) instead of flattening
/// it into a generic storage error — the message names the input to fix.
fn map_init_error(e: auths_id::error::InitError) -> SetupError {
    match e {
        auths_id::error::InitError::Key(auths_core::AgentError::WeakPassphrase(reason)) => {
            SetupError::WeakPassphrase {
                source_name: passphrase_source_name(),
                reason,
            }
        }
        other => SetupError::StorageError(other.into()),
    }
}

/// Which input supplied the passphrase. Env-sourced passphrases (the CI and
/// scripted paths) are named explicitly so a `--non-interactive` failure tells
/// the user exactly what to change.
fn passphrase_source_name() -> String {
    if std::env::var_os("AUTHS_PASSPHRASE").is_some() {
        "the AUTHS_PASSPHRASE environment variable".to_string()
    } else {
        "the entered passphrase".to_string()
    }
}

fn derive_keys(
    config: &CreateDeveloperIdentityConfig,
    ctx: &AuthsContext,
    keychain: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &dyn PassphraseProvider,
    now: DateTime<Utc>,
) -> Result<(IdentityDID, KeyAlias), SetupError> {
    let witness = match (config.witness_config.as_ref(), ctx.repo_path.as_deref()) {
        (Some(cfg), Some(path)) => auths_id::witness_config::WitnessParams::Enabled {
            config: cfg,
            repo_path: path,
        },
        _ => auths_id::witness_config::WitnessParams::Disabled,
    };
    let (controller_did, _key_event) = initialize_registry_identity(
        std::sync::Arc::clone(&ctx.registry),
        &config.key_alias,
        passphrase_provider,
        keychain,
        witness,
        config.curve,
        now,
    )
    .map_err(map_init_error)?;

    ctx.identity_storage
        .create_identity(controller_did.as_str(), None)
        .map_err(|e| SetupError::StorageError(e.into()))?;

    Ok((controller_did, config.key_alias.clone()))
}

fn derive_device_did(
    key_alias: &KeyAlias,
    keychain: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &dyn PassphraseProvider,
) -> Result<CanonicalDid, SetupError> {
    let (pk_bytes, curve) = auths_core::storage::keychain::extract_public_key_bytes(
        keychain,
        key_alias,
        passphrase_provider,
    )?;

    let device_did = CanonicalDid::from_public_key_did_key(&pk_bytes, curve);

    Ok(device_did)
}

fn bind_device(
    key_alias: &KeyAlias,
    ctx: &AuthsContext,
    keychain: &(dyn KeyStorage + Send + Sync),
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    now: DateTime<Utc>,
) -> Result<CanonicalDid, SetupError> {
    let managed = ctx
        .identity_storage
        .load_identity()
        .map_err(|e| SetupError::StorageError(e.into()))?;

    let (pk_bytes, curve) = auths_core::storage::keychain::extract_public_key_bytes(
        keychain,
        key_alias,
        passphrase_provider,
    )?;

    let device_did = CanonicalDid::from_public_key_did_key(&pk_bytes, curve);

    let meta = AttestationMetadata {
        timestamp: Some(now),
        expires_at: None,
        note: Some("Linked by auths-sdk setup".to_string()),
    };

    let issuer_canonical = CanonicalDid::from(managed.controller_did.clone());
    let attestation = create_signed_attestation(
        now,
        auths_id::attestation::create::AttestationInput {
            rid: &managed.storage_id,
            issuer: &issuer_canonical,
            subject: &device_did,
            device_public_key: &pk_bytes,
            device_curve: curve,
            payload: None,
            meta: &meta,
            identity_alias: Some(key_alias),
            device_alias: Some(key_alias),
            delegated_by: None,
            commit_sha: None,
            signer_type: None,
            oidc_binding: None,
        },
        signer,
        passphrase_provider,
    )
    .map_err(|e| SetupError::StorageError(e.into()))?;

    let mut batch = auths_id::storage::registry::backend::AtomicWriteBatch::new();
    batch.stage_attestation(attestation.clone());

    if let Ok(prefix) = auths_id::keri::parse_did_keri(managed.controller_did.as_str()) {
        match auths_id::keri::try_stage_anchor(
            ctx.registry.as_ref(),
            signer,
            key_alias,
            passphrase_provider,
            &prefix,
            &attestation,
            &mut batch,
        ) {
            Ok(_) => {}
            Err(auths_id::keri::AnchorError::IxnForbidden(_)) => {
                // Non-transferable identity — anchoring not possible, continue without
            }
            Err(e) => {
                return Err(SetupError::StorageError(
                    auths_id::error::StorageError::InvalidData(e.to_string()).into(),
                ));
            }
        }
    }

    ctx.registry.commit_batch(&batch).map_err(|e| {
        SetupError::StorageError(auths_id::error::StorageError::InvalidData(e.to_string()).into())
    })?;

    Ok(device_did)
}

/// Delegate device #0 at init so the primary device gets its OWN delegated AID,
/// distinct from the root identity. The root incepts (`icp`); this then mints a
/// delegated `dip` for the device (its own freshly-generated key) and anchors it in
/// the root KEL, so `identity_did != device_did` and the device is independently
/// revocable (delegator-side, via the root's revocation seal). Returns the device's
/// delegated `did:keri` and its keychain alias (the alias git signs commits with, so the
/// SSH signature is device #0's — matching the `Auths-Device` trailer).
///
/// Args:
/// * `controller_did`: the root identity's `did:keri` (the delegator).
/// * `root_alias`: keychain alias of the root's signing key (signs the anchoring `ixn`).
/// * `ctx`: SDK context (registry holds the root + new device KELs).
/// * `keychain`: key storage (the device's new key is stored under a `-device` alias).
/// * `passphrase_provider`: passphrase source for the key operations.
fn delegate_primary_device(
    controller_did: &IdentityDID,
    root_alias: &KeyAlias,
    ctx: &AuthsContext,
    keychain: &(dyn KeyStorage + Send + Sync),
    passphrase_provider: &dyn PassphraseProvider,
) -> Result<(CanonicalDid, KeyAlias), SetupError> {
    let root_prefix = auths_id::keri::parse_did_keri(controller_did.as_str()).map_err(|e| {
        SetupError::StorageError(auths_id::error::StorageError::InvalidData(e.to_string()).into())
    })?;
    let (_pk, curve) = auths_core::storage::keychain::extract_public_key_bytes(
        keychain,
        root_alias,
        passphrase_provider,
    )?;
    let device_alias = KeyAlias::new_unchecked(format!("{}-device", root_alias.as_str()));
    let dev = auths_id::keri::delegation::incept_delegated_device(
        std::sync::Arc::clone(&ctx.registry),
        &root_prefix,
        root_alias,
        curve,
        &device_alias,
        curve,
        passphrase_provider,
        keychain,
    )
    .map_err(|e| {
        SetupError::StorageError(auths_id::error::StorageError::InvalidData(e.to_string()).into())
    })?;
    Ok((CanonicalDid::from(dev.device_did), device_alias))
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
    now: DateTime<Utc>,
) -> Result<(IdentityDID, KeyAlias), SetupError> {
    let key_alias = KeyAlias::new_unchecked("ci-key");

    let (controller_did, _) = initialize_registry_identity(
        std::sync::Arc::clone(&ctx.registry),
        &key_alias,
        passphrase_provider,
        keychain,
        ctx.witness_params(),
        auths_crypto::CurveType::default(),
        now,
    )
    .map_err(map_init_error)?;

    Ok((controller_did, key_alias))
}

fn generate_ci_env_block(
    key_alias: &KeyAlias,
    repo_path: &Path,
    keychain_file: &Path,
    passphrase: &str,
    environment: &CiEnvironment,
    hooks_dir: Option<&Path>,
) -> Vec<String> {
    let mut lines = base_env_lines(key_alias, repo_path, keychain_file, passphrase, hooks_dir);
    lines.push(String::new());
    match environment {
        CiEnvironment::GitHubActions => {
            lines.push("# GitHub Actions: add these as repository secrets".to_string());
            lines.push("# then reference them in your workflow env: block".to_string());
        }
        CiEnvironment::GitLabCi => {
            lines.push("# GitLab CI: add these as CI/CD variables".to_string());
            lines.push("# in Settings > CI/CD > Variables".to_string());
        }
        CiEnvironment::Custom { name } => {
            lines.push(format!("# {name}: add these as environment variables"));
        }
        CiEnvironment::Unknown => {
            lines.push("# ci: add these as environment variables".to_string());
        }
    }
    lines
}

fn base_env_lines(
    key_alias: &KeyAlias,
    repo_path: &Path,
    keychain_file: &Path,
    passphrase: &str,
    hooks_dir: Option<&Path>,
) -> Vec<String> {
    let mut lines = vec![
        "# CI signing secrets — store these securely and rotate per environment".to_string(),
        format!("export AUTHS_KEYCHAIN_BACKEND=\"file\""),
        format!("export AUTHS_KEYCHAIN_FILE=\"{}\"", keychain_file.display()),
        format!("export AUTHS_PASSPHRASE=\"{passphrase}\""),
        format!("export AUTHS_REPO=\"{}\"", repo_path.display()),
        format!("export AUTHS_KEY_ALIAS=\"{key_alias}\""),
        String::new(),
    ];
    let git_configs: Vec<(String, String)> = [
        ("gpg.format".to_string(), "ssh".to_string()),
        ("gpg.ssh.program".to_string(), "auths-sign".to_string()),
        ("user.signingKey".to_string(), format!("auths:{key_alias}")),
        ("commit.gpgSign".to_string(), "true".to_string()),
    ]
    .into_iter()
    .chain(hooks_dir.map(|dir| ("core.hooksPath".to_string(), dir.display().to_string())))
    .collect();
    lines.push(format!("export GIT_CONFIG_COUNT={}", git_configs.len()));
    for (i, (key, value)) in git_configs.iter().enumerate() {
        lines.push(format!("export GIT_CONFIG_KEY_{i}=\"{key}\""));
        lines.push(format!("export GIT_CONFIG_VALUE_{i}=\"{value}\""));
    }
    lines
}

fn build_agent_identity_proposal(
    _provisioning_config: &auths_id::agent_identity::AgentProvisioningConfig,
    config: &CreateAgentIdentityConfig,
) -> Result<AgentIdentityResult, SetupError> {
    Ok(AgentIdentityResult {
        agent_did: None,
        parent_did: config
            .parent_identity_did
            .as_deref()
            .and_then(|s| IdentityDID::parse(s).ok()),
        capabilities: config.capabilities.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use auths_core::PrefilledPassphraseProvider;
    use auths_core::ports::clock::SystemClock;
    use auths_core::storage::memory::MemoryKeychainHandle;
    use auths_id::attestation::export::AttestationSink;
    use auths_id::ports::registry::RegistryBackend;
    use auths_id::storage::attestation::AttestationSource;
    use auths_id::storage::identity::IdentityStorage;
    use auths_id::testing::fakes::{
        FakeAttestationSink, FakeAttestationSource, FakeIdentityStorage, FakeRegistryBackend,
    };

    use crate::domains::identity::types::CreateAgentIdentityConfig;

    fn ctx() -> AuthsContext {
        AuthsContext::builder()
            .registry(Arc::new(FakeRegistryBackend::new()) as Arc<dyn RegistryBackend + Send + Sync>)
            .key_storage(Arc::new(MemoryKeychainHandle))
            .clock(Arc::new(SystemClock))
            .identity_storage(
                Arc::new(FakeIdentityStorage::new()) as Arc<dyn IdentityStorage + Send + Sync>
            )
            .attestation_sink(
                Arc::new(FakeAttestationSink::new()) as Arc<dyn AttestationSink + Send + Sync>
            )
            .attestation_source(
                Arc::new(FakeAttestationSource::new()) as Arc<dyn AttestationSource + Send + Sync>
            )
            .passphrase_provider(
                Arc::new(PrefilledPassphraseProvider::new(""))
                    as Arc<dyn PassphraseProvider + Send + Sync>,
            )
            .build()
    }

    #[test]
    fn initialize_agent_rejects_malformed_parent_did() {
        let config = CreateAgentIdentityConfig::builder(KeyAlias::new_unchecked("bot"), ".")
            .with_parent_did("not-a-keri-did")
            .build();
        let ctx = ctx();
        let result = initialize_agent(
            config,
            &ctx,
            Arc::new(MemoryKeychainHandle),
            &PrefilledPassphraseProvider::new(""),
        );
        assert!(matches!(result, Err(SetupError::InvalidSetupConfig(_))));
    }
}
