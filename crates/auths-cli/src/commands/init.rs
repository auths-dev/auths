//! One-command guided setup wizard for Auths.
//!
//! Applies Gather → Execute → Display for each profile, delegating all
//! business logic to `auths-sdk`.

use anyhow::{Context, Result, anyhow};
use clap::{Args, ValueEnum};
use dialoguer::{Confirm, Input, Select};
use std::io::IsTerminal;
use std::path::Path;
use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::{PassphraseProvider, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, KeyStorage, get_platform_keychain};
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_infra_http::HttpRegistryClient;
use auths_sdk::ports::git_config::GitConfigProvider;
use auths_sdk::registration::DEFAULT_REGISTRY_URL;
use auths_sdk::result::InitializeResult;
use auths_sdk::setup::initialize;
use auths_sdk::types::{
    CiEnvironment, CiIdentityConfig, CreateDeveloperIdentityConfig, GitSigningScope,
    IdentityConfig, IdentityConflictPolicy,
};
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};

use crate::adapters::git_config::SystemGitConfigProvider;
use crate::factories::storage::build_auths_context;

use super::init_helpers::{
    check_git_version, detect_ci_environment, get_auths_repo_path, offer_shell_completions,
    select_agent_capabilities, write_allowed_signers,
};
use crate::config::CliConfig;
use crate::ux::format::Output;

const DEFAULT_KEY_ALIAS: &str = "main";

/// Setup profile for identity initialization.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum InitProfile {
    /// Full local development setup with keychain, identity, device linking, and git signing
    Developer,
    /// Ephemeral identity for CI/CD pipelines
    Ci,
    /// Scoped identity for AI agents with capability restrictions
    Agent,
}

impl std::fmt::Display for InitProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitProfile::Developer => write!(f, "developer"),
            InitProfile::Ci => write!(f, "ci"),
            InitProfile::Agent => write!(f, "agent"),
        }
    }
}

/// Initializes Auths identity with a guided setup wizard.
///
/// Supports three profiles (developer, ci, agent) covering the most common
/// deployment scenarios. Interactive by default; pass `--non-interactive` for
/// scripted or CI use.
///
/// Usage:
/// ```ignore
/// // auths init
/// // auths init --profile developer --non-interactive
/// // auths init --profile ci --non-interactive
/// ```
#[derive(Args, Debug, Clone)]
#[command(
    name = "init",
    about = "Set up your cryptographic identity and Git signing"
)]
pub struct InitCommand {
    /// Skip interactive prompts and use sensible defaults
    #[clap(long)]
    pub non_interactive: bool,

    /// Preset profile: developer, ci, or agent
    #[clap(long, value_enum)]
    pub profile: Option<InitProfile>,

    /// Key alias for the identity key (default: main)
    #[clap(long, default_value = DEFAULT_KEY_ALIAS)]
    pub key_alias: String,

    /// Force overwrite if identity already exists
    #[clap(long)]
    pub force: bool,

    /// Preview agent configuration without creating files or identities
    #[clap(long)]
    pub dry_run: bool,

    /// Registry URL for automatic identity registration
    #[clap(long, default_value = DEFAULT_REGISTRY_URL)]
    pub registry: String,

    /// Skip automatic registry registration during setup
    #[clap(long)]
    pub skip_registration: bool,
}

// ── Main Dispatcher ──────────────────────────────────────────────────────

/// Handle the `init` command with Gather → Execute → Display pattern.
///
/// Args:
/// * `cmd`: Parsed [`InitCommand`] from the CLI.
/// * `ctx`: CLI configuration with passphrase provider and repo path.
///
/// Usage:
/// ```ignore
/// handle_init(cmd, &ctx)?;
/// ```
pub fn handle_init(cmd: InitCommand, ctx: &CliConfig) -> Result<()> {
    let out = Output::new();
    let interactive = !cmd.non_interactive && std::io::stdin().is_terminal();

    let profile = match cmd.profile {
        Some(p) => p,
        None if !interactive => {
            out.println("No profile specified in non-interactive mode, defaulting to developer.");
            InitProfile::Developer
        }
        None => prompt_profile(&out)?,
    };

    out.print_heading(&format!("Auths Setup ({})", profile));
    out.println("=".repeat(40).as_str());
    out.newline();

    match profile {
        InitProfile::Developer => {
            // GATHER
            let (keychain, mut config) = gather_developer_config(interactive, &out, &cmd)?;
            let registry_path = get_auths_repo_path()?;

            // Bootstrap: ensure registry dir and git repo exist (CLI responsibility)
            ensure_registry_dir(&registry_path)?;

            // Resolve auths-sign path and git config provider at presentation boundary
            let sign_binary_path = which::which("auths-sign").ok();
            if let Some(ref path) = sign_binary_path {
                config.sign_binary_path = Some(path.clone());
            }
            let git_config_provider: Option<Box<dyn GitConfigProvider>> =
                match &config.git_signing_scope {
                    GitSigningScope::Skip => None,
                    GitSigningScope::Global => Some(Box::new(SystemGitConfigProvider::global())),
                    GitSigningScope::Local { repo_path } => {
                        Some(Box::new(SystemGitConfigProvider::local(repo_path.clone())))
                    }
                };

            // Build SDK context with injected backends
            let sdk_ctx = build_auths_context(&registry_path, &ctx.env_config, None)?;

            // EXECUTE
            let keychain_arc: Arc<dyn KeyStorage + Send + Sync> = Arc::from(keychain);
            let signer = StorageSigner::new(Arc::clone(&keychain_arc));
            let result = initialize(
                IdentityConfig::Developer(config),
                &sdk_ctx,
                keychain_arc,
                &signer,
                ctx.passphrase_provider.as_ref(),
                git_config_provider.as_deref(),
            )?;
            let result = match result {
                InitializeResult::Developer(r) => r,
                _ => unreachable!(),
            };

            out.print_success(&format!("Identity ready: {}", &result.identity_did));
            out.print_success(&format!("Device linked: {}", result.device_did.as_str()));
            out.newline();

            // Post-execute: platform verification (interactive CLI concern)
            let proof_url = if interactive && !cmd.skip_registration {
                out.print_info("Claim your Developer Passport");
                out.newline();
                match prompt_platform_verification(
                    &out,
                    Arc::clone(&ctx.passphrase_provider),
                    &ctx.env_config,
                )? {
                    Some((url, _username)) => {
                        out.print_success(&format!("Proof anchored: {}", url));
                        Some(url)
                    }
                    None => {
                        out.println("  Continuing as anonymous identity");
                        None
                    }
                }
            } else {
                None
            };
            out.newline();

            offer_shell_completions(interactive, &out)?;
            write_allowed_signers(&result.key_alias, &out)?;

            // Post-execute: registration (best-effort, via SDK)
            let registered = submit_registration(
                &get_auths_repo_path()?,
                &cmd.registry,
                proof_url,
                cmd.skip_registration,
                &out,
            );

            // DISPLAY
            display_developer_result(&out, &result, registered.as_deref());
        }
        InitProfile::Ci => {
            // GATHER
            let (ci_env, config, keychain, passphrase_str) = gather_ci_config(&out)?;
            let registry_path = config.registry_path.clone();

            // Bootstrap: ensure registry dir and git repo exist (CLI responsibility)
            ensure_registry_dir(&registry_path)?;

            // Build SDK context with injected backends
            let sdk_ctx = build_auths_context(&registry_path, &ctx.env_config, None)?;

            // EXECUTE
            let keychain_arc: Arc<dyn KeyStorage + Send + Sync> = Arc::from(keychain);
            let signer = StorageSigner::new(Arc::clone(&keychain_arc));
            let provider = PrefilledPassphraseProvider::new(&passphrase_str);
            let result = initialize(
                IdentityConfig::Ci(config),
                &sdk_ctx,
                keychain_arc,
                &signer,
                &provider,
                None,
            )?;
            let result = match result {
                InitializeResult::Ci(r) => r,
                _ => unreachable!(),
            };

            // DISPLAY
            display_ci_result(&out, &result, ci_env.as_deref());
        }
        InitProfile::Agent => {
            // GATHER
            let (keychain, config) = gather_agent_config(interactive, &out, &cmd)?;
            let registry_path = config.registry_path.clone();

            if config.dry_run {
                display_agent_dry_run(&out, &config);
            } else {
                // Bootstrap: ensure registry dir and git repo exist (CLI responsibility)
                ensure_registry_dir(&registry_path)?;

                // Build SDK context with injected backends
                let sdk_ctx = build_auths_context(&registry_path, &ctx.env_config, None)?;

                // EXECUTE
                let keychain_arc: Arc<dyn KeyStorage + Send + Sync> = Arc::from(keychain);
                let signer = StorageSigner::new(Arc::clone(&keychain_arc));
                let result = initialize(
                    IdentityConfig::Agent(config),
                    &sdk_ctx,
                    keychain_arc,
                    &signer,
                    ctx.passphrase_provider.as_ref(),
                    None,
                )?;
                let result = match result {
                    InitializeResult::Agent(r) => r,
                    _ => unreachable!(),
                };

                // DISPLAY
                display_agent_result(&out, &result);
            }
        }
    }

    Ok(())
}

// ── Gather Functions ─────────────────────────────────────────────────────

fn gather_developer_config(
    interactive: bool,
    out: &Output,
    cmd: &InitCommand,
) -> Result<(
    Box<dyn KeyStorage + Send + Sync>,
    CreateDeveloperIdentityConfig,
)> {
    out.print_info("Checking prerequisites...");
    let keychain = check_keychain_access(out)?;
    check_git_version(out)?;
    out.print_success("Prerequisites OK");
    out.newline();

    let registry_path = get_auths_repo_path()?;
    let alias = prompt_for_alias(interactive, cmd)?;
    let conflict_policy = prompt_for_conflict_policy(interactive, cmd, &registry_path, out)?;
    let git_scope = prompt_for_git_scope(interactive)?;

    let mut builder = CreateDeveloperIdentityConfig::builder(KeyAlias::new_unchecked(&alias))
        .with_conflict_policy(conflict_policy)
        .with_git_signing_scope(git_scope);

    if !cmd.skip_registration {
        builder = builder.with_registration(&cmd.registry);
    }

    Ok((keychain, builder.build()))
}

#[allow(clippy::type_complexity)]
fn gather_ci_config(
    out: &Output,
) -> Result<(
    Option<String>,
    CiIdentityConfig,
    Box<dyn KeyStorage + Send + Sync>,
    String,
)> {
    out.print_info("Detecting CI environment...");
    let ci_env = detect_ci_environment();
    if let Some(ref vendor) = ci_env {
        out.print_success(&format!("Detected: {}", vendor));
    } else {
        out.print_warn("No CI environment detected, proceeding anyway");
    }
    out.newline();

    let registry_path = std::env::current_dir()?.join(".auths-ci");
    let passphrase =
        std::env::var("AUTHS_PASSPHRASE").unwrap_or_else(|_| "Ci-ephemeral-pass1!".to_string());

    // SAFETY: Single-threaded CLI context; env var read immediately by get_platform_keychain.
    unsafe {
        std::env::set_var("AUTHS_KEYCHAIN_BACKEND", "memory");
    }
    let keychain =
        get_platform_keychain().map_err(|e| anyhow!("Failed to get memory keychain: {}", e))?;

    out.println(&format!("  Using keychain: {}", keychain.backend_name()));

    let config = CiIdentityConfig {
        ci_environment: map_ci_environment(&ci_env),
        registry_path,
    };

    Ok((ci_env, config, keychain, passphrase))
}

fn gather_agent_config(
    interactive: bool,
    out: &Output,
    cmd: &InitCommand,
) -> Result<(
    Box<dyn KeyStorage + Send + Sync>,
    auths_sdk::types::CreateAgentIdentityConfig,
)> {
    out.print_info("Setting capability scope...");
    let capabilities = select_agent_capabilities(interactive, out)?;
    let cap_names: Vec<String> = capabilities.iter().map(|c| c.name.clone()).collect();
    out.print_success(&format!("Capabilities: {}", cap_names.join(", ")));
    out.newline();

    let parsed_caps: Vec<auths_verifier::Capability> = cap_names
        .into_iter()
        .filter_map(|s| auths_verifier::Capability::parse(&s).ok())
        .collect();

    let keychain = check_keychain_access(out)?;
    let registry_path = get_auths_repo_path()?;

    let config = auths_sdk::types::CreateAgentIdentityConfig::builder(
        KeyAlias::new_unchecked("agent"),
        &registry_path,
    )
    .with_capabilities(parsed_caps)
    .with_expiry(365 * 24 * 3600)
    .dry_run(cmd.dry_run)
    .build();

    Ok((keychain, config))
}

// ── Prompt Functions ─────────────────────────────────────────────────────

fn prompt_profile(out: &Output) -> Result<InitProfile> {
    out.print_heading("Select Setup Profile");
    out.newline();

    let items = [
        "Developer - Full local setup with keychain and git signing",
        "CI - Ephemeral identity for CI/CD pipelines",
        "Agent - Scoped identity for AI agents",
    ];

    let selection = Select::new()
        .with_prompt("Choose your setup profile")
        .items(items)
        .default(0)
        .interact()?;

    Ok(match selection {
        0 => InitProfile::Developer,
        1 => InitProfile::Ci,
        _ => InitProfile::Agent,
    })
}

fn prompt_for_alias(interactive: bool, cmd: &InitCommand) -> Result<String> {
    if interactive {
        Ok(Input::new()
            .with_prompt("Key alias")
            .default(cmd.key_alias.clone())
            .interact_text()?)
    } else {
        Ok(cmd.key_alias.clone())
    }
}

fn prompt_for_conflict_policy(
    interactive: bool,
    cmd: &InitCommand,
    registry_path: &Path,
    out: &Output,
) -> Result<IdentityConflictPolicy> {
    if cmd.force {
        return Ok(IdentityConflictPolicy::ForceNew);
    }

    let identity_storage = RegistryIdentityStorage::new(registry_path.to_path_buf());
    if let Ok(existing) = identity_storage.load_identity() {
        out.println(&format!(
            "  Found existing identity: {}",
            out.info(existing.controller_did.as_str())
        ));

        if !interactive {
            return Ok(IdentityConflictPolicy::ReuseExisting);
        }

        let use_existing = Confirm::new()
            .with_prompt("Use existing identity?")
            .default(true)
            .interact()?;
        if use_existing {
            return Ok(IdentityConflictPolicy::ReuseExisting);
        }

        let overwrite = Confirm::new()
            .with_prompt("Create new identity? This will NOT delete the old one.")
            .default(false)
            .interact()?;
        if !overwrite {
            return Err(anyhow!("Setup cancelled by user"));
        }
    }

    Ok(IdentityConflictPolicy::ForceNew)
}

fn prompt_for_git_scope(interactive: bool) -> Result<GitSigningScope> {
    if !interactive {
        return Ok(GitSigningScope::Global);
    }

    let choice = Select::new()
        .with_prompt("Configure git signing for")
        .items([
            "This repository only (--local)",
            "All repositories (--global)",
        ])
        .default(1)
        .interact()?;

    if choice == 0 {
        let repo_path = std::env::current_dir()?;
        Ok(GitSigningScope::Local { repo_path })
    } else {
        Ok(GitSigningScope::Global)
    }
}

fn prompt_platform_verification(
    out: &Output,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &auths_core::config::EnvironmentConfig,
) -> Result<Option<(String, String)>> {
    let items = [
        "GitHub — link your GitHub identity (recommended)",
        "GitLab — coming soon",
        "Anonymous — skip platform verification",
    ];

    let selection = Select::new()
        .with_prompt("Claim your Developer Passport")
        .items(items)
        .default(0)
        .interact()?;

    match selection {
        0 => {
            use std::time::Duration;

            use auths_core::ports::platform::OAuthDeviceFlowProvider;
            use auths_core::ports::platform::PlatformProofPublisher;
            use auths_infra_http::{HttpGistPublisher, HttpGitHubOAuthProvider};
            use auths_sdk::workflows::platform::create_signed_platform_claim;

            const GITHUB_CLIENT_ID: &str = "Ov23lio2CiTHBjM2uIL4";
            let client_id = std::env::var("AUTHS_GITHUB_CLIENT_ID")
                .unwrap_or_else(|_| GITHUB_CLIENT_ID.to_string());

            let auths_dir = get_auths_repo_path()?;
            let ctx = build_auths_context(&auths_dir, env_config, Some(passphrase_provider))?;

            let oauth = HttpGitHubOAuthProvider::new();
            let publisher = HttpGistPublisher::new();

            let rt = tokio::runtime::Runtime::new().context("failed to create async runtime")?;

            let device_code = rt
                .block_on(oauth.request_device_code(&client_id, "read:user gist"))
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            out.println(&format!(
                "  Enter this code: {}",
                out.bold(&device_code.user_code)
            ));
            out.println(&format!(
                "  At: {}",
                out.info(&device_code.verification_uri)
            ));
            if let Err(e) = open::that(&device_code.verification_uri) {
                out.print_warn(&format!("Could not open browser automatically: {e}"));
                out.println("  Please open the URL above manually.");
            } else {
                out.println("  Browser opened — waiting for authorization...");
            }

            let expires_in = Duration::from_secs(device_code.expires_in);
            let interval = Duration::from_secs(device_code.interval);

            let access_token = rt
                .block_on(oauth.poll_for_token(
                    &client_id,
                    &device_code.device_code,
                    interval,
                    expires_in,
                ))
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            let profile = rt
                .block_on(oauth.fetch_user_profile(&access_token))
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            out.print_success(&format!("Authenticated as @{}", profile.login));

            let controller_did =
                auths_sdk::pairing::load_controller_did(ctx.identity_storage.as_ref())
                    .map_err(|e| anyhow::anyhow!("{e}"))?;

            let identity_did =
                auths_core::storage::keychain::IdentityDID::new_unchecked(controller_did.clone());
            let aliases = ctx
                .key_storage
                .list_aliases_for_identity(&identity_did)
                .context("failed to list key aliases")?;
            let key_alias = aliases
                .into_iter()
                .find(|a| !a.contains("--next-"))
                .ok_or_else(|| anyhow::anyhow!("no signing key found for {controller_did}"))?;

            let claim_json = create_signed_platform_claim(
                "github",
                &profile.login,
                &controller_did,
                &key_alias,
                &ctx,
                chrono::Utc::now(),
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;

            let proof_url = rt
                .block_on(publisher.publish_proof(&access_token, &claim_json))
                .map_err(|e| anyhow::anyhow!("{e}"))?;

            out.print_success(&format!("Published proof Gist: {}", out.info(&proof_url)));

            Ok(Some((proof_url, profile.login)))
        }
        1 => {
            out.print_warn("GitLab integration is coming soon. Continuing as anonymous.");
            Ok(None)
        }
        _ => Ok(None),
    }
}

// ── Display Functions ────────────────────────────────────────────────────

fn display_developer_result(
    out: &Output,
    result: &auths_sdk::result::DeveloperIdentityResult,
    registered: Option<&str>,
) {
    out.newline();
    out.print_heading("You are on the Web of Trust!");
    out.newline();
    out.println(&format!("  Identity: {}", out.info(&result.identity_did)));
    out.println(&format!("  Key alias: {}", out.info(&result.key_alias)));
    if let Some(registry) = registered {
        out.println(&format!("  Registry: {}", out.info(registry)));
    }
    let did_prefix = result
        .identity_did
        .strip_prefix("did:keri:")
        .unwrap_or(&result.identity_did);
    out.println(&format!(
        "  Profile: {}",
        out.info(&format!("https://auths.dev/registry/identity/{did_prefix}"))
    ));
    out.newline();
    out.print_success("Your next commit will be signed with Auths!");
    out.println("  Run `auths status` to check your identity");
}

fn display_ci_result(
    out: &Output,
    result: &auths_sdk::result::CiIdentityResult,
    ci_vendor: Option<&str>,
) {
    out.print_success(&format!("CI identity: {}", &result.identity_did));
    out.newline();

    out.print_heading("Add these to your CI secrets:");
    out.println("─".repeat(50).as_str());
    for line in &result.env_block {
        println!("{}", line);
    }
    out.println("─".repeat(50).as_str());
    out.newline();

    if let Some(vendor) = ci_vendor {
        write_ci_vendor_hints(out, vendor);
    }

    out.print_success("CI setup complete!");
    out.println("  Add the environment variables to your CI secrets");
    out.println("  Commits made in CI will be signed with the ephemeral identity");
}

fn display_agent_result(out: &Output, result: &auths_sdk::result::AgentIdentityResult) {
    out.print_heading("Agent Setup Complete!");
    out.newline();
    out.println(&format!("  Identity: {}", out.info(&result.agent_did)));
    let cap_display: Vec<String> = result.capabilities.iter().map(|c| c.to_string()).collect();
    out.println(&format!("  Capabilities: {}", cap_display.join(", ")));
    out.newline();
    out.print_success("Agent is ready to sign commits!");
    out.println("  Start the agent: auths agent start");
    out.println("  Check status: auths agent status");
}

fn display_agent_dry_run(out: &Output, config: &auths_sdk::types::CreateAgentIdentityConfig) {
    out.print_heading("Dry Run — no files or identities will be created");
    out.newline();
    out.println(&format!("  Storage: {}", config.registry_path.display()));
    out.println(&format!("  Capabilities: {:?}", config.capabilities));
    if let Some(secs) = config.expires_in_secs {
        out.println(&format!("  Expires in: {}s", secs));
    }
    out.newline();
    out.print_info("TOML config that would be generated:");
    let provisioning_config = auths_id::agent_identity::AgentProvisioningConfig {
        agent_name: config.alias.to_string(),
        capabilities: config.capabilities.iter().map(|c| c.to_string()).collect(),
        expires_in_secs: config.expires_in_secs,
        delegated_by: None,
        storage_mode: auths_id::agent_identity::AgentStorageMode::Persistent { repo_path: None },
    };
    out.println(&auths_id::agent_identity::format_agent_toml(
        "did:keri:E<pending>",
        "agent-key",
        &provisioning_config,
    ));
}

// ── Post-Execute Helpers ─────────────────────────────────────────────────

fn submit_registration(
    repo_path: &Path,
    registry_url: &str,
    proof_url: Option<String>,
    skip: bool,
    out: &Output,
) -> Option<String> {
    if skip {
        out.print_info("Registration skipped (--skip-registration)");
        return None;
    }

    out.print_info("Publishing identity to Auths Registry...");
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            out.print_warn(&format!("Could not create async runtime: {e}"));
            return None;
        }
    };

    let backend = Arc::new(GitRegistryBackend::from_config_unchecked(
        RegistryConfig::single_tenant(repo_path),
    ));
    let identity_storage: Arc<dyn IdentityStorage + Send + Sync> =
        Arc::new(RegistryIdentityStorage::new(repo_path.to_path_buf()));
    let attestation_store = Arc::new(RegistryAttestationStorage::new(repo_path));
    let attestation_source: Arc<dyn AttestationSource + Send + Sync> = attestation_store;

    let registry_client = HttpRegistryClient::new();

    match rt.block_on(auths_sdk::registration::register_identity(
        identity_storage,
        backend,
        attestation_source,
        registry_url,
        proof_url,
        &registry_client,
    )) {
        Ok(outcome) => {
            out.print_success(&format!("Identity registered at {}", outcome.registry));
            Some(outcome.registry)
        }
        Err(auths_sdk::error::RegistrationError::AlreadyRegistered) => {
            out.print_success("Already registered on this registry");
            Some(registry_url.to_string())
        }
        Err(auths_sdk::error::RegistrationError::QuotaExceeded) => {
            out.print_warn("Registration quota exceeded. Run `auths id register` to retry later.");
            None
        }
        Err(auths_sdk::error::RegistrationError::NetworkError(_)) => {
            out.print_warn(
                "Could not reach the registry (offline?). Your local setup is complete.",
            );
            out.println("  Run `auths id register` when you're back online.");
            None
        }
        Err(auths_sdk::error::RegistrationError::LocalDataError(e)) => {
            out.print_warn(&format!("Could not prepare registration payload: {e}"));
            out.println("  Run `auths id register` to retry.");
            None
        }
        Err(e) => {
            out.print_warn(&format!("Registration failed: {e}"));
            None
        }
    }
}

fn ensure_registry_dir(registry_path: &Path) -> Result<()> {
    if !registry_path.exists() {
        std::fs::create_dir_all(registry_path).with_context(|| {
            format!(
                "Failed to create registry directory: {}",
                registry_path.display()
            )
        })?;
    }
    if git2::Repository::open(registry_path).is_err() {
        git2::Repository::init(registry_path).with_context(|| {
            format!(
                "Failed to initialize git repository: {}",
                registry_path.display()
            )
        })?;
    }
    auths_sdk::setup::install_registry_hook(registry_path);
    Ok(())
}

fn check_keychain_access(out: &Output) -> Result<Box<dyn KeyStorage + Send + Sync>> {
    match get_platform_keychain() {
        Ok(keychain) => {
            out.println(&format!(
                "  Keychain: {} (accessible)",
                out.success(keychain.backend_name())
            ));
            Ok(keychain)
        }
        Err(e) => Err(anyhow!("Keychain not accessible: {}", e)),
    }
}

fn map_ci_environment(detected: &Option<String>) -> CiEnvironment {
    match detected.as_deref() {
        Some("GitHub Actions") => CiEnvironment::GitHubActions,
        Some("GitLab CI") => CiEnvironment::GitLabCi,
        Some(name) => CiEnvironment::Custom {
            name: name.to_string(),
        },
        None => CiEnvironment::Unknown,
    }
}

fn write_ci_vendor_hints(out: &Output, vendor: &str) {
    out.newline();
    out.print_heading(&format!("Hints for {}", vendor));

    match vendor {
        "GitHub Actions" => {
            out.println("Add to your workflow (.github/workflows/*.yml):");
            out.newline();
            out.println("  env:");
            out.println("    AUTHS_KEYCHAIN_BACKEND: memory");
            out.newline();
            out.println("  steps:");
            out.println("    - uses: actions/checkout@v4");
            out.println("    - run: auths init --profile ci --non-interactive");
        }
        "GitLab CI" => {
            out.println("Add to .gitlab-ci.yml:");
            out.newline();
            out.println("  variables:");
            out.println("    AUTHS_KEYCHAIN_BACKEND: memory");
            out.newline();
            out.println("  before_script:");
            out.println("    - auths init --profile ci --non-interactive");
        }
        _ => {
            out.println("Set these environment variables in your CI:");
            out.println("  AUTHS_KEYCHAIN_BACKEND=memory");
        }
    }
    out.newline();
}

// ── ExecutableCommand ────────────────────────────────────────────────────

impl crate::commands::executable::ExecutableCommand for InitCommand {
    fn execute(&self, ctx: &CliConfig) -> anyhow::Result<()> {
        handle_init(self.clone(), ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_profile_display() {
        assert_eq!(InitProfile::Developer.to_string(), "developer");
        assert_eq!(InitProfile::Ci.to_string(), "ci");
        assert_eq!(InitProfile::Agent.to_string(), "agent");
    }

    #[test]
    fn test_setup_command_defaults() {
        let cmd = InitCommand {
            non_interactive: false,
            profile: None,
            key_alias: DEFAULT_KEY_ALIAS.to_string(),
            force: false,
            dry_run: false,
            registry: DEFAULT_REGISTRY_URL.to_string(),
            skip_registration: false,
        };
        assert!(!cmd.non_interactive);
        assert!(cmd.profile.is_none());
        assert_eq!(cmd.key_alias, "main");
        assert!(!cmd.force);
        assert!(!cmd.dry_run);
        assert_eq!(cmd.registry, "https://auths-registry.fly.dev");
        assert!(!cmd.skip_registration);
    }

    #[test]
    fn test_setup_command_with_profile() {
        let cmd = InitCommand {
            non_interactive: true,
            profile: Some(InitProfile::Ci),
            key_alias: "ci-key".to_string(),
            force: true,
            dry_run: false,
            registry: DEFAULT_REGISTRY_URL.to_string(),
            skip_registration: false,
        };
        assert!(cmd.non_interactive);
        assert!(matches!(cmd.profile, Some(InitProfile::Ci)));
        assert_eq!(cmd.key_alias, "ci-key");
        assert!(cmd.force);
    }

    #[test]
    fn test_map_ci_environment() {
        assert!(matches!(
            map_ci_environment(&Some("GitHub Actions".into())),
            CiEnvironment::GitHubActions
        ));
        assert!(matches!(
            map_ci_environment(&Some("GitLab CI".into())),
            CiEnvironment::GitLabCi
        ));
        assert!(matches!(map_ci_environment(&None), CiEnvironment::Unknown));
    }
}
