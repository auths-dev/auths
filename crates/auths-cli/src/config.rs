use std::path::PathBuf;
use std::sync::Arc;

use auths_core::config::EnvironmentConfig;
use auths_core::signing::PassphraseProvider;

#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

pub struct CliConfig {
    pub repo_path: Option<PathBuf>,
    pub output_format: OutputFormat,
    pub is_interactive: bool,
    pub passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    pub env_config: EnvironmentConfig,
}

impl CliConfig {
    pub fn is_json(&self) -> bool {
        matches!(self.output_format, OutputFormat::Json)
    }
}
