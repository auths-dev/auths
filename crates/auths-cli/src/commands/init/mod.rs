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
use std::path::PathBuf;
use std::sync::Arc;

use auths_core::PrefilledPassphraseProvider;
use auths_core::signing::StorageSigner;
use auths_core::storage::keychain::KeyStorage;
use auths_sdk::domains::identity::registration::DEFAULT_REGISTRY_URL;
use auths_sdk::domains::identity::service::initialize;
use auths_sdk::domains::identity::types::IdentityConfig;
use auths_sdk::domains::identity::types::InitializeResult;
use auths_sdk::domains::signing::types::GitSigningScope;
use auths_sdk::ports::git_config::GitConfigProvider;

use crate::adapters::git_config::SystemGitConfigProvider;
use crate::config::CliConfig;
use crate::factories::storage::build_auths_context;
use crate::ux::format::Output;

use super::signers::{SignersSyncArgs, handle_sync};
use display::{
    display_agent_dry_run, display_agent_result, display_ci_result, display_developer_result,
};
use gather::{
    ensure_registry_dir, gather_agent_config, gather_ci_config, gather_developer_config,
    submit_registration,
};
use guided::GuidedSetup;
use helpers::{get_auths_repo_path, offer_shell_completions, write_allowed_signers};
use prompts::{prompt_platform_verification, prompt_profile};

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
    about = "Set up your cryptographic identity and Git signing",
    after_help = "Examples:
  auths init                              # Interactive setup wizard
  auths init --profile developer          # Developer profile with prompts
  auths init --profile ci --non-interactive # Automated CI setup

Profiles:
  developer — Full development environment: local keys, device linking, Git signing
  ci        — Ephemeral identity for CI/CD pipelines with environment variables
  agent     — Scoped identity for AI agents with capability restrictions

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
    #[clap(long, default_value = DEFAULT_REGISTRY_URL)]
    pub registry: String,

    /// Register identity with the Auths Registry after creation
    #[clap(long)]
    pub register: bool,

    /// Scaffold a GitHub Actions workflow using the auths attest-action
    #[clap(long)]
    pub github_action: bool,
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
    let mut guide = GuidedSetup::new(out, guided::developer_steps());

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

    out.print_success(&format!("Identity ready: {}", &result.identity_did));
    out.print_success(&format!("Device linked: {}", result.device_did.as_str()));

    // PLATFORM VERIFICATION
    guide.section("Platform Verification");
    let proof_url = if interactive && cmd.register {
        out.print_info("Claim your Developer Passport");
        out.newline();
        match prompt_platform_verification(
            out,
            Arc::clone(&ctx.passphrase_provider),
            &ctx.env_config,
            now,
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

    // POST-SETUP
    guide.section("Shell & Signing Setup");
    offer_shell_completions(interactive, out)?;
    write_allowed_signers(&result.key_alias, out)?;

    // Also write repo-local .auths/allowed_signers if we're inside a git repo,
    // so `auths verify` works immediately without extra flags.
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        && output.status.success()
    {
        let root = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
        let repo_signers = root.join(".auths").join("allowed_signers");
        let _ = handle_sync(&SignersSyncArgs {
            repo: "~/.auths".into(),
            output_file: Some(repo_signers),
        });
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
    let mut guide = GuidedSetup::new(out, guided::ci_steps());

    // GATHER
    guide.section("CI Environment Detection");
    let (ci_env, config, keychain, passphrase_str) = gather_ci_config(out)?;
    let registry_path = config.registry_path.clone();
    ensure_registry_dir(&registry_path)?;

    // EXECUTE
    guide.section("Creating CI Identity");
    let sdk_ctx = build_auths_context(&registry_path, &ctx.env_config, None)?;
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
    let mut guide = GuidedSetup::new(out, guided::agent_steps());

    // GATHER
    guide.section("Agent Configuration");
    let (keychain, config) = gather_agent_config(interactive, out, cmd)?;
    let registry_path = config.registry_path.clone();

    if config.dry_run {
        display_agent_dry_run(out, &config);
        return Ok(());
    }

    // EXECUTE
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
        };
        assert!(!cmd.interactive);
        assert!(!cmd.non_interactive);
        assert!(cmd.profile.is_none());
        assert_eq!(cmd.key_alias, "main");
        assert!(!cmd.force);
        assert!(!cmd.dry_run);
        assert_eq!(cmd.registry, "https://auths-registry.fly.dev");
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
        };
        // Auto-detect returns is_terminal() — result depends on environment
        let result = resolve_interactive(&cmd).unwrap();
        assert_eq!(result, std::io::stdin().is_terminal());
    }
}
