//! One-command guided setup wizard for Auths.
//!
//! Applies Gather → Execute → Display for each profile, delegating all
//! business logic to `auths-sdk`.

mod display;
mod gather;
mod guided;
mod helpers;
mod prompts;

use anyhow::{Result, anyhow};
use clap::{Args, ValueEnum};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use auths_sdk::domains::identity::registration::DEFAULT_REGISTRY_URL;
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::IdentityConfig;
use auths_sdk::domains::identity::types::InitializeResult;
use auths_sdk::domains::signing::types::GitSigningScope;
use auths_sdk::keychain::KeyStorage;
use auths_sdk::ports::git_config::GitConfigProvider;
use auths_sdk::signing::PrefilledPassphraseProvider;
use auths_sdk::signing::StorageSigner;

use crate::adapters::git_config::SystemGitConfigProvider;
use crate::config::CliConfig;
use crate::factories::storage::build_auths_context;
use crate::ux::format::Output;

use display::{
    display_agent_dry_run, display_agent_result, display_ci_result, display_developer_result,
};
use gather::{
    ensure_registry_dir, gather_agent_config, gather_ci_config, gather_developer_config,
    submit_registration,
};
use guided::GuidedSetup;
use helpers::{get_auths_repo_path, offer_shell_completions};
use prompts::{prompt_platform_verification, prompt_profile};

const DEFAULT_KEY_ALIAS: &str = "main";

/// Setup profile for identity initialization.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum InitProfile {
    /// Full local development setup with keychain, identity, device linking, and git signing
    Developer,
    /// Temporary signing identity for CI/CD pipelines
    Ci,
    /// Restricted signing identity for AI agents
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
/// deployment scenarios. Interactive by default on TTY; pass `--non-interactive`
/// for scripted or CI use, or `--interactive` to force prompts.
///
/// Usage:
/// ```ignore
/// // auths init
/// // auths init --profile developer --non-interactive
/// // auths init --interactive --profile developer
/// ```
#[derive(Args, Debug, Clone)]
#[command(
    name = "init",
    about = "Create your signing identity and configure Git",
    after_help = "Examples:
  auths init                              # Interactive setup wizard
  auths init --profile developer          # Developer profile with prompts
  auths init --profile ci --non-interactive # Automated CI setup

Profiles:
  developer — Local setup: keychain, Git signing, platform identity
  ci        — Temporary signing identity for CI/CD runners
  agent     — Restricted signing identity for AI agents

Related:
  auths status  — Check setup completion
  auths doctor  — Run health checks"
)]
pub struct InitCommand {
    /// Force interactive prompts (errors if not a TTY)
    #[clap(long, conflicts_with = "non_interactive")]
    pub interactive: bool,

    /// Skip interactive prompts and use sensible defaults
    #[clap(long, conflicts_with = "interactive")]
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

    /// Registry URL for identity registration
    #[clap(long, env = "AUTHS_REGISTRY_URL", default_value = DEFAULT_REGISTRY_URL)]
    pub registry: String,

    /// Register identity with the Auths Registry after creation
    #[clap(long)]
    pub register: bool,

    /// Scaffold a GitHub Actions workflow using the auths attest-action
    #[clap(long)]
    pub github_action: bool,

    /// Number of device slots for a multi-key KEL (default 1).
    ///
    /// Values > 1 require `--signing-threshold` and `--rotation-threshold`.
    /// Multi-device init today runs a single-device inception and points the
    /// operator at `auths id expand` for the device-expansion rotation; the
    /// full atomic multi-device inception path is wired through later.
    #[clap(long, default_value_t = 1)]
    pub device_count: u8,

    /// Signing threshold: scalar integer (e.g. `"2"`) or fraction list
    /// (e.g. `"1/2,1/2,1/2"`). Required when `--device-count > 1`.
    #[clap(long)]
    pub signing_threshold: Option<String>,

    /// Rotation (next) threshold, same format as `--signing-threshold`.
    #[clap(long)]
    pub rotation_threshold: Option<String>,
}

/// Parse a threshold argument from the CLI.
///
/// Accepts either a plain integer (`"2"`, `"a"` hex) for `Threshold::Simple`
/// or a comma-separated fraction list (`"1/2,1/2,1/2"`) for
/// `Threshold::Weighted`. Rejects mixed shapes (`"2,3"` with no `/`) with
/// a clear error.
pub fn parse_threshold_cli(
    s: &str,
    key_count: usize,
) -> Result<auths_keri::Threshold, anyhow::Error> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("threshold value is empty"));
    }

    if trimmed.contains(',') || trimmed.contains('/') {
        // Fraction list path.
        let fractions: Result<Vec<auths_keri::Fraction>, _> = trimmed
            .split(',')
            .map(|part| part.trim().parse::<auths_keri::Fraction>())
            .collect();
        let fractions = fractions.map_err(|e| {
            anyhow!(
                "invalid fraction in threshold {:?}: {e}. Provide either an integer count (e.g. \"2\") or a comma-separated fraction list (e.g. \"1/2,1/2,1/2\").",
                trimmed
            )
        })?;
        if fractions.len() != key_count {
            return Err(anyhow!(
                "threshold fraction list has {} entries for device_count {}",
                fractions.len(),
                key_count
            ));
        }
        Ok(auths_keri::Threshold::Weighted(vec![fractions]))
    } else {
        let n = u64::from_str_radix(trimmed, 16).map_err(|_| {
            anyhow!(
                "invalid scalar threshold {:?}: expected hex integer (e.g. \"2\") or fraction list (e.g. \"1/2,1/2,1/2\")",
                trimmed
            )
        })?;
        if (n as usize) > key_count {
            return Err(anyhow!(
                "threshold {} exceeds device count {}",
                n,
                key_count
            ));
        }
        if n == 0 && key_count > 0 {
            return Err(anyhow!(
                "threshold 0 is unsatisfiable for non-empty device set"
            ));
        }
        Ok(auths_keri::Threshold::Simple(n))
    }
}

fn resolve_interactive(cmd: &InitCommand) -> Result<bool> {
    if cmd.interactive {
        if !std::io::stdin().is_terminal() {
            return Err(anyhow!(
                "--interactive requires a TTY (stdin is not a terminal)"
            ));
        }
        Ok(true)
    } else if cmd.non_interactive {
        Ok(false)
    } else {
        Ok(std::io::stdin().is_terminal())
    }
}

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
pub fn handle_init(
    cmd: InitCommand,
    ctx: &CliConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let out = Output::new();

    if cmd.github_action {
        return helpers::scaffold_github_action(&out);
    }

    // Validate multi-device flag combinations at CLI parse time.
    let device_count = cmd.device_count.max(1) as usize;
    if device_count > 1 {
        let kt_str = cmd
            .signing_threshold
            .as_deref()
            .ok_or_else(|| anyhow!("--signing-threshold is required when --device-count > 1"))?;
        let nt_str = cmd
            .rotation_threshold
            .as_deref()
            .ok_or_else(|| anyhow!("--rotation-threshold is required when --device-count > 1"))?;
        let _kt = parse_threshold_cli(kt_str, device_count)?;
        let _nt = parse_threshold_cli(nt_str, device_count)?;
        return Err(anyhow!(
            "multi-device init (--device-count > 1) is not yet wired through the developer setup flow. \
             Run `auths init` for a single-device identity, then `auths id expand --add-device <CURVE>` \
             (repeatable) with the desired thresholds to convert into a multi-device KEL."
        ));
    }
    if cmd.signing_threshold.is_some() && device_count == 1 {
        let kt = parse_threshold_cli(cmd.signing_threshold.as_deref().unwrap_or("1"), 1)?;
        if !matches!(kt, auths_keri::Threshold::Simple(1)) {
            return Err(anyhow!(
                "single-device init requires --signing-threshold to be 1 or omitted"
            ));
        }
    }

    let interactive = resolve_interactive(&cmd)?;

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

    match profile {
        InitProfile::Developer => run_developer_setup(interactive, &out, &cmd, ctx, now)?,
        InitProfile::Ci => run_ci_setup(&out, ctx)?,
        InitProfile::Agent => run_agent_setup(interactive, &out, &cmd, ctx)?,
    }

    Ok(())
}

fn run_developer_setup(
    interactive: bool,
    out: &Output,
    cmd: &InitCommand,
    ctx: &CliConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let mut guide = GuidedSetup::new(out, guided::developer_steps(), interactive);

    // GATHER
    guide.section("Prerequisites & Configuration");
    let (keychain, mut config) = gather_developer_config(interactive, out, cmd)?;
    let registry_path = get_auths_repo_path()?;
    ensure_registry_dir(&registry_path)?;

    let sign_binary_path = which::which("auths-sign").ok();
    if let Some(ref path) = sign_binary_path {
        config.sign_binary_path = Some(path.clone());
    }
    let git_config_provider: Option<Box<dyn GitConfigProvider>> = match &config.git_signing_scope {
        GitSigningScope::Skip => None,
        GitSigningScope::Global => Some(Box::new(SystemGitConfigProvider::global())),
        GitSigningScope::Local { repo_path } => {
            Some(Box::new(SystemGitConfigProvider::local(repo_path.clone())))
        }
    };

    // EXECUTE
    guide.section("Creating Identity");
    let sdk_ctx = build_auths_context(&registry_path, &ctx.env_config, None)?;
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

    out.print_success(&format!(
        "Identity created: {}",
        crate::ux::product_id(&result.identity_did)
    ));
    out.print_success(&format!(
        "This device authorized: {}",
        result.device_did.as_str()
    ));

    // PLATFORM VERIFICATION
    guide.section("Platform Verification");
    let proof_url = if interactive && cmd.register {
        out.print_info("Link your GitHub account");
        out.newline();
        match prompt_platform_verification(
            out,
            Arc::clone(&ctx.passphrase_provider),
            &ctx.env_config,
            now,
        )? {
            Some((url, _username)) => {
                out.print_success(&format!("GitHub identity linked: {}", url));
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

    // POST-SETUP
    guide.section("Shell & Signing Setup");
    offer_shell_completions(interactive, out)?;

    // Commit-time trailers: install the prepare-commit-msg hook and point
    // core.hooksPath at it, so a plain `git commit` carries the Auths-Id /
    // Auths-Device trailers `auths verify` replays — zero extra commands.
    // Trailer values come from the signer resolver (same source as `auths sign`):
    // on the root machine Auths-Device is the root `did:keri:` itself, on a
    // delegate it is the device's delegated AID — always a replayable KEL.
    if let Some(git_config) = git_config_provider.as_deref() {
        match auths_sdk::domains::identity::local::resolve_local_signer(&sdk_ctx) {
            Ok(signer) => {
                match auths_sdk::workflows::commit_hooks::enable_commit_trailers(
                    &registry_path,
                    &signer.root_did,
                    &signer.signer_did,
                    git_config,
                ) {
                    Ok(()) => {
                        // Refresh stamps the current KEL position (Auths-Anchor-Seq)
                        // into the trailer file the hook reads.
                        let _ = auths_sdk::workflows::commit_hooks::refresh_commit_trailers(
                            &sdk_ctx,
                            &registry_path,
                        );
                        out.println("  Commit trailers enabled (prepare-commit-msg hook)");
                    }
                    Err(e) => out.println(&format!("  Note: could not install commit hook ({e})")),
                }
            }
            Err(e) => out.println(&format!("  Note: could not resolve signer for hook ({e})")),
        }
    }

    // Pin the local identity as a trusted root for KEL-native verification (Epic B):
    // the committed `<repo>/.auths/roots` is the root of trust — no allowed_signers file.
    // The hook seeds the same pin into every repo on first signed commit; this covers
    // the repo the user is standing in right now.
    if let Ok(output) = crate::subprocess::git_command(&["rev-parse", "--show-toplevel"]).output()
        && output.status.success()
    {
        let root = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
        let root_did = result.identity_did.to_string();
        match auths_sdk::workflows::roots::add_pinned_root(
            &crate::adapters::config_store::FileConfigStore,
            &root.join(".auths"),
            &root_did,
        ) {
            Ok(()) => out.println(&format!(
                "  Pinned trusted root: {}",
                crate::ux::product_id(&root_did)
            )),
            Err(e) => out.println(&format!("  Note: could not pin trusted root ({e})")),
        }
    }

    // REGISTRATION & DISPLAY
    guide.section("Registration & Summary");
    let registered = submit_registration(
        &get_auths_repo_path()?,
        &cmd.registry,
        proof_url,
        !cmd.register, // skip unless --register is explicitly passed
        out,
    );
    display_developer_result(out, &result, registered.as_deref());

    Ok(())
}

fn run_ci_setup(out: &Output, ctx: &CliConfig) -> Result<()> {
    let mut guide = GuidedSetup::new(out, guided::ci_steps(), false);

    // GATHER
    guide.section("CI Environment Detection");
    let (ci_env, config, keychain, passphrase_str) =
        gather_ci_config(out, ctx.repo_path.as_deref())?;
    let registry_path = config.registry_path.clone();
    ensure_registry_dir(&registry_path)?;

    // EXECUTE
    guide.section("Creating CI Identity");
    // gather_ci_config set the file-backend env vars; read them fresh so the SDK
    // context's keychain matches the one we just built (ctx.env_config predates them).
    let ci_env_config = auths_sdk::core_config::EnvironmentConfig::from_env();
    let sdk_ctx = build_auths_context(&registry_path, &ci_env_config, None)?;
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
    guide.section("Summary");
    display_ci_result(out, &result, ci_env.as_deref());

    Ok(())
}

fn run_agent_setup(
    interactive: bool,
    out: &Output,
    cmd: &InitCommand,
    ctx: &CliConfig,
) -> Result<()> {
    let mut guide = GuidedSetup::new(out, guided::agent_steps(), interactive);

    // GATHER
    guide.section("Agent Configuration");
    let (keychain, config) = gather_agent_config(interactive, out, cmd)?;
    let registry_path = config.registry_path.clone();

    if config.dry_run {
        display_agent_dry_run(out, &config);
        return Ok(());
    }

    // The user said "I want an agent" — deliver one. An agent is a KERI
    // delegated identifier under an existing root, so when a root identity
    // exists, route straight into the delegation flow (the same machinery as
    // `auths id agent add`), reusing the capabilities just selected.
    if interactive && delegate_agent_interactively(out, cmd, ctx, &config, &registry_path)? {
        return Ok(());
    }

    // EXECUTE — no root identity (or non-interactive): the SDK returns the
    // actionable "delegate via `auths id agent add`" guidance.
    guide.section("Creating Agent Identity");
    ensure_registry_dir(&registry_path)?;
    let sdk_ctx = build_auths_context(&registry_path, &ctx.env_config, None)?;
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
    guide.section("Summary");
    display_agent_result(out, &result);

    Ok(())
}

/// Delegate an agent under the existing root identity, interactively. Returns
/// `Ok(false)` when no root identity exists (the caller falls through to the
/// guidance path).
fn delegate_agent_interactively(
    out: &Output,
    cmd: &InitCommand,
    ctx: &CliConfig,
    config: &auths_sdk::types::CreateAgentIdentityConfig,
    registry_path: &Path,
) -> Result<bool> {
    let sdk_ctx = build_auths_context(
        registry_path,
        &ctx.env_config,
        Some(Arc::clone(&ctx.passphrase_provider)),
    )?;
    if sdk_ctx.identity_storage.load_identity().is_err() {
        out.print_info("No root identity found — an agent is delegated under a root identity.");
        out.println("  Run `auths init` (developer profile) first, then choose Agent again.");
        return Ok(false);
    }

    let label: String = dialoguer::Input::new()
        .with_prompt("Agent label (also the keychain alias for its key)")
        .default("agent".to_string())
        .interact_text()
        .unwrap_or_else(|_| "agent".to_string());

    let root_alias = auths_sdk::keychain::KeyAlias::new_unchecked(&cmd.key_alias);
    let agent_alias = auths_sdk::keychain::KeyAlias::new_unchecked(&label);
    #[allow(clippy::disallowed_methods)] // CLI boundary: clock injected here
    let expires_at = config
        .expires_in
        .map(|secs| chrono::Utc::now().timestamp() + secs as i64);

    let result = auths_sdk::domains::agents::add_scoped(
        &sdk_ctx,
        &root_alias,
        &agent_alias,
        auths_crypto::CurveType::default(),
        &config.capabilities,
        expires_at,
    )
    .map_err(anyhow::Error::new)?;
    let _ = auths_sdk::workflows::commit_hooks::refresh_commit_trailers(&sdk_ctx, registry_path);

    out.newline();
    out.print_success("Agent delegated under your identity:");
    out.println(&format!(
        "  {}",
        out.info(&crate::ux::product_id(&result.agent_did))
    ));
    let cap_display: Vec<String> = config.capabilities.iter().map(|c| c.to_string()).collect();
    if !cap_display.is_empty() {
        out.println(&format!("  Capabilities: {}", cap_display.join(", ")));
    }
    out.newline();
    out.println("  Manage it: auths id agent list / auths id agent revoke");
    Ok(true)
}

impl crate::commands::executable::ExecutableCommand for InitCommand {
    #[allow(clippy::disallowed_methods)]
    fn execute(&self, ctx: &CliConfig) -> anyhow::Result<()> {
        handle_init(self.clone(), ctx, chrono::Utc::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_sdk::types::CiEnvironment;
    use gather::map_ci_environment;

    #[test]
    fn test_setup_profile_display() {
        assert_eq!(InitProfile::Developer.to_string(), "developer");
        assert_eq!(InitProfile::Ci.to_string(), "ci");
        assert_eq!(InitProfile::Agent.to_string(), "agent");
    }

    #[test]
    fn parse_threshold_cli_rejects_unsatisfiable_thresholds() {
        // A threshold larger than the device count can never be met — it would brick recovery,
        // so it is rejected at creation.
        assert!(parse_threshold_cli("3", 2).is_err());
        // Zero is unsatisfiable for a non-empty device set.
        assert!(parse_threshold_cli("0", 2).is_err());
        // A satisfiable threshold parses: 2-of-2.
        assert_eq!(
            parse_threshold_cli("2", 2).unwrap(),
            auths_keri::Threshold::Simple(2)
        );
        // 1-of-N (the any-device default) is satisfiable.
        assert!(parse_threshold_cli("1", 3).is_ok());
    }

    #[test]
    fn test_setup_command_defaults() {
        let cmd = InitCommand {
            interactive: false,
            non_interactive: false,
            profile: None,
            key_alias: DEFAULT_KEY_ALIAS.to_string(),
            force: false,
            dry_run: false,
            registry: DEFAULT_REGISTRY_URL.to_string(),
            register: false,
            github_action: false,
            device_count: 1,
            signing_threshold: None,
            rotation_threshold: None,
        };
        assert!(!cmd.interactive);
        assert!(!cmd.non_interactive);
        assert!(cmd.profile.is_none());
        assert_eq!(cmd.key_alias, "main");
        assert!(!cmd.force);
        assert!(!cmd.dry_run);
        assert_eq!(cmd.registry, "https://registry.auths.dev");
        assert!(!cmd.register);
        assert!(!cmd.github_action);
    }

    #[test]
    fn test_setup_command_with_profile() {
        let cmd = InitCommand {
            interactive: false,
            non_interactive: true,
            profile: Some(InitProfile::Ci),
            key_alias: "ci-key".to_string(),
            force: true,
            dry_run: false,
            registry: DEFAULT_REGISTRY_URL.to_string(),
            register: false,
            github_action: false,
            device_count: 1,
            signing_threshold: None,
            rotation_threshold: None,
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

    #[test]
    fn test_resolve_interactive_non_interactive_flag() {
        let cmd = InitCommand {
            interactive: false,
            non_interactive: true,
            profile: None,
            key_alias: DEFAULT_KEY_ALIAS.to_string(),
            force: false,
            dry_run: false,
            registry: DEFAULT_REGISTRY_URL.to_string(),
            register: false,
            github_action: false,
            device_count: 1,
            signing_threshold: None,
            rotation_threshold: None,
        };
        assert!(!resolve_interactive(&cmd).unwrap());
    }

    #[test]
    fn test_resolve_interactive_auto_detect() {
        let cmd = InitCommand {
            interactive: false,
            non_interactive: false,
            profile: None,
            key_alias: DEFAULT_KEY_ALIAS.to_string(),
            force: false,
            dry_run: false,
            registry: DEFAULT_REGISTRY_URL.to_string(),
            register: false,
            github_action: false,
            device_count: 1,
            signing_threshold: None,
            rotation_threshold: None,
        };
        // Auto-detect returns is_terminal() — result depends on environment
        let result = resolve_interactive(&cmd).unwrap();
        assert_eq!(result, std::io::stdin().is_terminal());
    }
}
