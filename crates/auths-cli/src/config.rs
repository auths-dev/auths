use std::path::PathBuf;
use std::sync::Arc;

use auths_core::config::EnvironmentConfig;
use auths_core::signing::PassphraseProvider;
use capsec::SendCap;

#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

/// Granted capability tokens for I/O operations.
///
/// Created once at the CLI boundary via `capsec::root()` and threaded into
/// adapter constructors. Domain crates never see these tokens.
#[derive(Clone)]
pub struct Capabilities {
    pub fs_read: SendCap<capsec::FsRead>,
    pub fs_write: SendCap<capsec::FsWrite>,
    pub net_connect: SendCap<capsec::NetConnect>,
    pub spawn: SendCap<capsec::Spawn>,
}

pub struct CliConfig {
    pub repo_path: Option<PathBuf>,
    pub output_format: OutputFormat,
    pub is_interactive: bool,
    pub passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    pub env_config: EnvironmentConfig,
    pub caps: Capabilities,
}

impl CliConfig {
    pub fn is_json(&self) -> bool {
        matches!(self.output_format, OutputFormat::Json)
    }
}
