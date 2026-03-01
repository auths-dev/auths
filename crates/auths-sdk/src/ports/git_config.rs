/// Error type for git configuration operations.
#[derive(Debug, thiserror::Error)]
pub enum GitConfigError {
    /// The git config command failed with the given message.
    #[error("git config command failed: {0}")]
    CommandFailed(String),
}

/// Configures git settings for cryptographic signing.
///
/// Args:
/// * `key` - The git config key (e.g., "gpg.format")
/// * `value` - The value to set
///
/// Usage:
/// ```ignore
/// git_config.set("gpg.format", "ssh")?;
/// ```
pub trait GitConfigProvider: Send + Sync {
    /// Set a global git config key to the given value.
    fn set(&self, key: &str, value: &str) -> Result<(), GitConfigError>;
}
