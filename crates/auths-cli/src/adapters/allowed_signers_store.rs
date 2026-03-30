//! File-based adapter for [`AllowedSignersStore`].

use std::path::Path;

use auths_sdk::ports::allowed_signers::{AllowedSignersError, AllowedSignersStore};

/// Reads and writes allowed_signers files using the local filesystem.
/// Uses atomic writes via `tempfile::NamedTempFile::persist`.
pub struct FileAllowedSignersStore;

impl AllowedSignersStore for FileAllowedSignersStore {
    fn read(&self, path: &Path) -> Result<Option<String>, AllowedSignersError> {
        match std::fs::read_to_string(path) {
            Ok(content) => Ok(Some(content)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(AllowedSignersError::FileRead {
                path: path.to_path_buf(),
                source: e,
            }),
        }
    }

    #[allow(clippy::expect_used)] // INVARIANT: path always has a parent (caller provides full file paths)
    fn write(&self, path: &Path, content: &str) -> Result<(), AllowedSignersError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AllowedSignersError::FileWrite {
                path: path.to_path_buf(),
                source: e,
            })?;
        }

        use std::io::Write;
        let dir = path.parent().expect("path has parent");
        let tmp =
            tempfile::NamedTempFile::new_in(dir).map_err(|e| AllowedSignersError::FileWrite {
                path: path.to_path_buf(),
                source: e,
            })?;
        (&tmp)
            .write_all(content.as_bytes())
            .map_err(|e| AllowedSignersError::FileWrite {
                path: path.to_path_buf(),
                source: e,
            })?;
        tmp.persist(path)
            .map_err(|e| AllowedSignersError::FileWrite {
                path: path.to_path_buf(),
                source: e.error,
            })?;
        Ok(())
    }
}
