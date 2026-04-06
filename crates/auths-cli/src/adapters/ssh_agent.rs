//! CLI adapter for system SSH agent key registration via `ssh-add`.

use auths_sdk::ports::{SshAgentError, SshAgentPort};
use std::path::Path;
use std::process::Command;

/// Registers keys with the macOS system SSH agent using `ssh-add`.
///
/// Usage:
/// ```ignore
/// let adapter = MacOsSshAgentAdapter;
/// adapter.register_key(Path::new("/tmp/auths-key-abc.pem"))?;
/// ```
pub struct MacOsSshAgentAdapter;

impl SshAgentPort for MacOsSshAgentAdapter {
    fn register_key(&self, key_path: &Path) -> Result<(), SshAgentError> {
        let output = Command::new("ssh-add")
            .arg(key_path)
            .output()
            .map_err(|e| SshAgentError::IoError(e.to_string()))?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
        if stderr.contains("could not open a connection")
            || stderr.contains("connection refused")
            || stderr.contains("communication with agent failed")
        {
            Err(SshAgentError::NotAvailable(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ))
        } else {
            Err(SshAgentError::CommandFailed(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ))
        }
    }
}
