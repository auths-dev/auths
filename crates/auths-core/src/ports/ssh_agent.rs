//! Port trait for system SSH agent key registration.

use std::path::Path;

/// Domain error for system SSH agent operations.
///
/// Args:
/// * `CommandFailed` — The ssh-add command ran but returned a non-zero exit code.
/// * `NotAvailable` — The SSH agent is not running or cannot be reached.
/// * `IoError` — A filesystem or process I/O error occurred.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::ssh_agent::SshAgentError;
///
/// fn handle(err: SshAgentError) {
///     match err {
///         SshAgentError::CommandFailed(msg) => eprintln!("ssh-add failed: {msg}"),
///         SshAgentError::NotAvailable(msg) => eprintln!("agent unavailable: {msg}"),
///         SshAgentError::IoError(msg) => eprintln!("I/O error: {msg}"),
///     }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SshAgentError {
    /// The ssh-add command ran but returned a failure status.
    #[error("ssh-add command failed: {0}")]
    CommandFailed(String),

    /// The system SSH agent is not available.
    #[error("SSH agent not available: {0}")]
    NotAvailable(String),

    /// A filesystem or process I/O error.
    #[error("I/O error: {0}")]
    IoError(String),
}

impl auths_crypto::AuthsErrorInfo for SshAgentError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::CommandFailed(_) => "AUTHS-E3901",
            Self::NotAvailable(_) => "AUTHS-E3902",
            Self::IoError(_) => "AUTHS-E3903",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::NotAvailable(_) => Some("Start the SSH agent: eval $(ssh-agent -s)"),
            Self::CommandFailed(_) => {
                Some("Check that the key file exists and has correct permissions")
            }
            Self::IoError(_) => Some("Check file permissions"),
        }
    }
}

/// Registers key files with the system SSH agent.
///
/// Implementations wrap platform-specific mechanisms (e.g., `ssh-add` on
/// macOS/Linux). Domain code calls this trait without knowing the transport.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::ssh_agent::SshAgentPort;
///
/// fn register(agent: &dyn SshAgentPort, key_path: &Path) {
///     agent.register_key(key_path).unwrap();
/// }
/// ```
pub trait SshAgentPort: Send + Sync {
    /// Registers a PEM key file with the system SSH agent.
    ///
    /// Args:
    /// * `key_path`: Path to a temporary PEM file to add via ssh-add.
    ///
    /// Usage:
    /// ```ignore
    /// agent.register_key(Path::new("/tmp/auths-key-abc.pem"))?;
    /// ```
    fn register_key(&self, key_path: &Path) -> Result<(), SshAgentError>;
}
