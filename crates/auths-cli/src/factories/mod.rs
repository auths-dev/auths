pub mod storage;

use std::io::IsTerminal;
use std::sync::Arc;

use anyhow::Result;

use auths_sdk::core_config::{EnvironmentConfig, load_config};
use auths_sdk::keychain::{get_passphrase_cache, parse_duration_str};
use auths_sdk::paths::auths_home;
use auths_sdk::ports::agent::AgentSigningPort;
use auths_sdk::signing::{KeychainPassphraseProvider, PassphraseProvider};
use auths_telemetry::TelemetryShutdown;
use auths_telemetry::config::{build_sinks_from_config, load_audit_config};
use auths_telemetry::sinks::composite::CompositeSink;

use crate::adapters::config_store::FileConfigStore;
use crate::cli::AuthsCli;
use crate::config::{CliConfig, OutputFormat};
use crate::core::provider::{CliPassphraseProvider, PrefilledPassphraseProvider};

/// Builds the full CLI configuration from parsed arguments.
///
/// Constructs the passphrase provider and output settings.
/// This is the composition root — the only place where concrete adapter
/// types are instantiated.
///
/// Args:
/// * `cli`: The parsed CLI arguments.
///
/// Usage:
/// ```ignore
/// use auths_cli::factories::build_config;
///
/// let cli = AuthsCli::parse();
/// let config = build_config(&cli)?;
/// ```
pub fn build_config(cli: &AuthsCli) -> Result<CliConfig> {
    let output_format = if cli.json {
        OutputFormat::Json
    } else {
        OutputFormat::Text
    };

    let env_config = EnvironmentConfig::from_env();

    let passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync> =
        if let Some(passphrase) = env_config.keychain.passphrase.clone() {
            Arc::new(PrefilledPassphraseProvider::new(zeroize::Zeroizing::new(
                passphrase,
            )))
        } else {
            let config = load_config(&FileConfigStore);
            let cache = get_passphrase_cache(config.passphrase.biometric);
            let ttl_secs = config
                .passphrase
                .duration
                .as_deref()
                .and_then(parse_duration_str);
            let inner = Arc::new(CliPassphraseProvider::new());
            Arc::new(KeychainPassphraseProvider::new(
                inner,
                cache,
                "default".to_string(),
                config.passphrase.cache,
                ttl_secs,
            ))
        };

    let is_interactive = std::io::stdout().is_terminal();

    // One storage root for every subcommand: --repo, then AUTHS_REPO (which a
    // headless CI step exports from `init --profile ci`), then AUTHS_HOME as a
    // deprecated alias — honored with a warning rather than silently ignored, so
    // `verify`/`doctor` never read a different root than `init`/`sign` wrote.
    let repo_path = resolve_repo_root(cli.repo.clone());

    Ok(CliConfig {
        repo_path,
        output_format,
        is_interactive,
        passphrase_provider,
        env_config,
    })
}

/// Resolve the single storage-root override shared by every subcommand.
///
/// Precedence: an explicit `--repo`, then `AUTHS_REPO`, then `AUTHS_HOME` as a
/// deprecated alias (warned, never silently dropped). Returns `None` when none is
/// set, leaving callers on the default `~/.auths`.
///
/// Args:
/// * `repo_flag`: the value of the global `--repo` flag, if the user passed one.
///
/// Usage:
/// ```ignore
/// let repo_path = resolve_repo_root(cli.repo.clone());
/// ```
fn resolve_repo_root(repo_flag: Option<std::path::PathBuf>) -> Option<std::path::PathBuf> {
    #[allow(clippy::disallowed_methods)] // CLI boundary: storage-root env resolution
    let auths_repo = std::env::var("AUTHS_REPO").ok().filter(|s| !s.is_empty());
    #[allow(clippy::disallowed_methods)] // CLI boundary: storage-root env resolution
    let auths_home = std::env::var("AUTHS_HOME").ok().filter(|s| !s.is_empty());

    let (root, via_home_alias) = pick_repo_root(repo_flag, auths_repo, auths_home);
    if via_home_alias {
        eprintln!(
            "warning: AUTHS_HOME is deprecated; prefer AUTHS_REPO to override the storage root"
        );
    }
    root
}

/// Apply the storage-root precedence: `--repo` > `AUTHS_REPO` > `AUTHS_HOME`.
///
/// Returns the resolved root (if any) and whether it came from the deprecated
/// `AUTHS_HOME` alias, so the caller can warn without the env read living inside
/// the tested logic.
///
/// Args:
/// * `repo_flag`: the `--repo` value, if given.
/// * `auths_repo`: a non-empty `AUTHS_REPO`, if set.
/// * `auths_home`: a non-empty `AUTHS_HOME`, if set.
///
/// Usage:
/// ```ignore
/// let (root, via_home) = pick_repo_root(None, None, Some("/x".into()));
/// ```
fn pick_repo_root(
    repo_flag: Option<std::path::PathBuf>,
    auths_repo: Option<String>,
    auths_home: Option<String>,
) -> (Option<std::path::PathBuf>, bool) {
    if let Some(flag) = repo_flag {
        return (Some(flag), false);
    }
    if let Some(repo) = auths_repo {
        return (Some(std::path::PathBuf::from(repo)), false);
    }
    match auths_home {
        Some(home) => (Some(std::path::PathBuf::from(home)), true),
        None => (None, false),
    }
}

/// Loads audit sinks from `~/.auths/audit.toml` and initialises the global
/// telemetry pipeline.
///
/// Returns `None` when no sinks are configured — zero overhead in that case.
///
/// Usage:
/// ```ignore
/// let _telemetry = auths_cli::factories::init_audit_sinks();
/// ```
pub fn init_audit_sinks() -> Option<TelemetryShutdown> {
    let audit_path = match auths_home() {
        Ok(h) => h.join("audit.toml"),
        Err(_) => return None,
    };
    let config = load_audit_config(&audit_path);
    #[allow(clippy::disallowed_methods)] // CLI boundary: audit config reads env vars
    let sinks = build_sinks_from_config(&config, |name| std::env::var(name).ok());
    if sinks.is_empty() {
        return None;
    }
    let composite = Arc::new(CompositeSink::new(sinks));
    Some(auths_telemetry::init_telemetry_with_sink(composite))
}

/// Build the platform-appropriate agent signing provider.
///
/// Returns `CliAgentAdapter` on Unix, `NoopAgentProvider` elsewhere.
///
/// Usage:
/// ```ignore
/// let agent = build_agent_provider();
/// let ctx = CommitSigningContext { agent_signing: agent, .. };
/// ```
pub fn build_agent_provider() -> Arc<dyn AgentSigningPort + Send + Sync> {
    #[cfg(unix)]
    {
        Arc::new(crate::adapters::agent::CliAgentAdapter)
    }
    #[cfg(not(unix))]
    {
        Arc::new(auths_sdk::ports::agent::NoopAgentProvider)
    }
}

#[cfg(test)]
mod tests {
    use super::pick_repo_root;
    use std::path::PathBuf;

    #[test]
    fn repo_flag_wins_over_both_env_vars() {
        let (root, via_home) = pick_repo_root(
            Some(PathBuf::from("/flag")),
            Some("/repo".into()),
            Some("/home".into()),
        );
        assert_eq!(root, Some(PathBuf::from("/flag")));
        assert!(!via_home);
    }

    #[test]
    fn auths_repo_wins_over_auths_home() {
        let (root, via_home) = pick_repo_root(None, Some("/repo".into()), Some("/home".into()));
        assert_eq!(root, Some(PathBuf::from("/repo")));
        assert!(!via_home);
    }

    #[test]
    fn auths_home_populates_repo_path_with_warning() {
        // AUTHS_HOME must feed the shared storage root (with a deprecation warning),
        // not be silently ignored — otherwise verify/doctor read a different root
        // than init/sign wrote.
        let (root, via_home) = pick_repo_root(None, None, Some("/home".into()));
        assert_eq!(root, Some(PathBuf::from("/home")));
        assert!(via_home, "AUTHS_HOME must trigger the deprecation warning");
    }

    #[test]
    fn no_override_leaves_default_root() {
        let (root, via_home) = pick_repo_root(None, None, None);
        assert_eq!(root, None);
        assert!(!via_home);
    }
}
