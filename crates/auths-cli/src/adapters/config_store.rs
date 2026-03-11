//! File-based adapter for the `ConfigStore` port.

use std::path::Path;

use auths_core::ports::config_store::{ConfigStore, ConfigStoreError};

/// Reads and writes config files from the local filesystem.
pub struct FileConfigStore;

impl ConfigStore for FileConfigStore {
    fn read(&self, path: &Path) -> Result<Option<String>, ConfigStoreError> {
        match std::fs::read_to_string(path) {
            Ok(content) => Ok(Some(content)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ConfigStoreError::Read {
                path: path.to_path_buf(),
                source: e,
            }),
        }
    }

    fn write(&self, path: &Path, content: &str) -> Result<(), ConfigStoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| ConfigStoreError::Write {
                path: path.to_path_buf(),
                source: e,
            })?;
        }
        std::fs::write(path, content).map_err(|e| ConfigStoreError::Write {
            path: path.to_path_buf(),
            source: e,
        })
    }
}
