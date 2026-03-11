//! Config file I/O port for reading and writing `config.toml`.

use std::path::PathBuf;

use thiserror::Error;

/// Errors that can occur during config store operations.
#[derive(Debug, Error)]
pub enum ConfigStoreError {
    /// Failed to read the config file.
    #[error("failed to read config from {path}")]
    Read {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// Failed to write the config file.
    #[error("failed to write config to {path}")]
    Write {
        /// The path that could not be written.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl auths_crypto::AuthsErrorInfo for ConfigStoreError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Read { .. } => "AUTHS-E3951",
            Self::Write { .. } => "AUTHS-E3952",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::Read { .. } => Some("Check that ~/.auths/config.toml exists and is readable"),
            Self::Write { .. } => Some("Check file permissions for ~/.auths/config.toml"),
        }
    }
}

/// Abstracts filesystem access for config file operations.
///
/// Args:
/// * `path` - The path to the config file.
///
/// Usage:
/// ```ignore
/// let content = store.read(Path::new("~/.auths/config.toml"))?;
/// store.write(Path::new("~/.auths/config.toml"), "content")?;
/// ```
pub trait ConfigStore: Send + Sync {
    /// Read the config file content.
    /// Returns `None` if the file does not exist.
    fn read(&self, path: &std::path::Path) -> Result<Option<String>, ConfigStoreError>;

    /// Write content to the config file, creating parent dirs as needed.
    fn write(&self, path: &std::path::Path, content: &str) -> Result<(), ConfigStoreError>;
}
