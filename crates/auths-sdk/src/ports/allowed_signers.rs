//! Allowed signers file I/O port for reading and writing SSH allowed_signers files.

use std::path::Path;

use crate::workflows::allowed_signers::AllowedSignersError;

/// Abstracts filesystem access for allowed_signers file operations.
///
/// Args:
/// * `path` - The path to the allowed_signers file.
///
/// Usage:
/// ```ignore
/// let content = store.read(Path::new("~/.ssh/allowed_signers"))?;
/// store.write(Path::new("~/.ssh/allowed_signers"), "content")?;
/// ```
pub trait AllowedSignersStore: Send + Sync {
    /// Read the allowed_signers file content.
    /// Returns `None` if the file does not exist.
    fn read(&self, path: &Path) -> Result<Option<String>, AllowedSignersError>;

    /// Write content to the allowed_signers file, creating parent dirs as needed.
    /// Should use atomic writes where possible.
    fn write(&self, path: &Path, content: &str) -> Result<(), AllowedSignersError>;
}
