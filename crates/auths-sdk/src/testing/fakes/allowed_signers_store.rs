use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::ports::allowed_signers::{AllowedSignersError, AllowedSignersStore};

/// In-memory fake for [`AllowedSignersStore`].
///
/// Stores file contents in a `HashMap<PathBuf, String>` and records calls
/// for test assertions.
///
/// Usage:
/// ```ignore
/// let store = FakeAllowedSignersStore::new();
/// let store = FakeAllowedSignersStore::new().with_file(path, "content");
/// ```
pub struct FakeAllowedSignersStore {
    files: Mutex<HashMap<PathBuf, String>>,
    write_calls: Mutex<Vec<(PathBuf, String)>>,
    fail_on_write: Mutex<Option<String>>,
}

impl Default for FakeAllowedSignersStore {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeAllowedSignersStore {
    /// Create an empty fake with no files.
    pub fn new() -> Self {
        Self {
            files: Mutex::new(HashMap::new()),
            write_calls: Mutex::new(Vec::new()),
            fail_on_write: Mutex::new(None),
        }
    }

    /// Pre-populate a file with content.
    pub fn with_file(self, path: &Path, content: &str) -> Self {
        self.files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(path.to_path_buf(), content.to_string());
        self
    }

    /// Configure all writes to fail with the given message.
    pub fn write_fails_with(self, msg: &str) -> Self {
        *self.fail_on_write.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg.to_string());
        self
    }

    /// Return recorded write calls as `(path, content)` pairs.
    pub fn write_calls(&self) -> Vec<(PathBuf, String)> {
        self.write_calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Read file content from the in-memory store (for test assertions).
    pub fn content(&self, path: &Path) -> Option<String> {
        self.files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(path)
            .cloned()
    }
}

impl AllowedSignersStore for FakeAllowedSignersStore {
    fn read(&self, path: &Path) -> Result<Option<String>, AllowedSignersError> {
        Ok(self
            .files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(path)
            .cloned())
    }

    fn write(&self, path: &Path, content: &str) -> Result<(), AllowedSignersError> {
        if let Some(msg) = self
            .fail_on_write
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            return Err(AllowedSignersError::FileWrite {
                path: path.to_path_buf(),
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, msg.clone()),
            });
        }
        self.write_calls
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((path.to_path_buf(), content.to_string()));
        self.files
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(path.to_path_buf(), content.to_string());
        Ok(())
    }
}
