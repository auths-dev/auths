pub mod network;
pub mod storage;

use std::io::IsTerminal;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use auths_core::config::EnvironmentConfig;
use auths_core::signing::{CachedPassphraseProvider, PassphraseProvider};

use crate::cli::AuthsCli;
use crate::config::{CliConfig, OutputFormat};
use crate::core::provider::{CliPassphraseProvider, PrefilledPassphraseProvider};

/// Builds the full CLI configuration from parsed arguments.
///
/// Constructs the passphrase provider, HTTP client, and output settings.
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
    let is_json = cli.json || matches!(cli.output, OutputFormat::Json);
    let output_format = if is_json {
        OutputFormat::Json
    } else {
        cli.output
    };

    let env_config = EnvironmentConfig::from_env();

    let passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync> =
        if let Some(passphrase) = env_config.keychain.passphrase.clone() {
            Arc::new(PrefilledPassphraseProvider::new(zeroize::Zeroizing::new(
                passphrase,
            )))
        } else {
            let inner = Arc::new(CliPassphraseProvider::new());
            Arc::new(CachedPassphraseProvider::new(
                inner,
                Duration::from_secs(3600),
            ))
        };

    let is_interactive = std::io::stdout().is_terminal();
    let http_client = network::build_http_client()?;

    Ok(CliConfig {
        repo_path: cli.repo.clone(),
        output_format,
        is_interactive,
        passphrase_provider,
        http_client,
        env_config,
    })
}
