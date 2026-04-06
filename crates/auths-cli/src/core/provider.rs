use anyhow::Context;
use auths_sdk::error::AgentError;
use auths_sdk::signing::PassphraseProvider;
use zeroize::Zeroizing;

/// A PassphraseProvider implementation that prompts the user on the command line.
#[derive(Debug, Clone, Default)]
pub struct CliPassphraseProvider;

impl CliPassphraseProvider {
    /// Creates a new instance.
    pub fn new() -> Self {
        Self
    }
}

impl PassphraseProvider for CliPassphraseProvider {
    /// Securely obtains a passphrase by prompting the user on the terminal.
    fn get_passphrase(&self, prompt_message: &str) -> Result<Zeroizing<String>, AgentError> {
        // Print the contextual prompt provided by the caller to stderr
        eprintln!("{}", prompt_message);

        // Use rpassword to prompt securely
        let password = rpassword::prompt_password("Enter passphrase: ")
            .context("Failed to read passphrase from terminal") // Add context using anyhow
            .map_err(|e| {
                // Map the anyhow::Error (wrapping std::io::Error) to AgentError
                // Consider adding a specific AgentError variant like UserInputCancelled or IOFailed
                eprintln!("Error reading passphrase: {:?}", e); // Log the specific error
                // For now, map generic IO errors. A more specific mapping could be done.
                if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                    // Example: Check for specific kinds like Interrupted if needed
                    // if io_err.kind() == std::io::ErrorKind::Interrupted {
                    //     return AgentError::UserInputCancelled;
                    // }
                    AgentError::IO(std::io::Error::new(io_err.kind(), format!("{}", e))) // Create a new IO error to own the message
                } else {
                    AgentError::SecurityError(format!("Failed to get passphrase: {}", e)) // Fallback
                }
            })?;

        Ok(Zeroizing::new(password))
    }
}

/// A PassphraseProvider that returns a pre-collected passphrase.
///
/// Use this when the passphrase must be collected before starting a
/// background task (e.g., a terminal spinner) that would interfere
/// with stdin.
pub struct PrefilledPassphraseProvider {
    passphrase: Zeroizing<String>,
}

impl PrefilledPassphraseProvider {
    pub fn new(passphrase: Zeroizing<String>) -> Self {
        Self { passphrase }
    }
}

impl PassphraseProvider for PrefilledPassphraseProvider {
    fn get_passphrase(&self, _prompt_message: &str) -> Result<Zeroizing<String>, AgentError> {
        Ok(self.passphrase.clone())
    }
}
