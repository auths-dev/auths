//! File-based adapter for the `ConfigStore` port.

use std::path::Path;

use auths_core::ports::config_store::{ConfigStore, ConfigStoreError};
use capsec::SendCap;

/// Reads and writes config files from the local filesystem.
pub struct FileConfigStore {
    _fs_read: SendCap<capsec::FsRead>,
    fs_write: SendCap<capsec::FsWrite>,
}

impl FileConfigStore {
    pub fn new(fs_read: SendCap<capsec::FsRead>, fs_write: SendCap<capsec::FsWrite>) -> Self {
        Self {
            _fs_read: fs_read,
            fs_write,
        }
    }
}

impl ConfigStore for FileConfigStore {
    fn read(&self, path: &Path) -> Result<Option<String>, ConfigStoreError> {
        match capsec::fs::read_to_string(path, &self._fs_read) {
            Ok(content) => Ok(Some(content)),
            Err(capsec::CapSecError::Io(ref io_err))
                if io_err.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(e) => Err(ConfigStoreError::Read {
                path: path.to_path_buf(),
                source: capsec_to_io(e),
            }),
        }
    }

    fn write(&self, path: &Path, content: &str) -> Result<(), ConfigStoreError> {
        if let Some(parent) = path.parent() {
            capsec::fs::create_dir_all(parent, &self.fs_write).map_err(|e| {
                ConfigStoreError::Write {
                    path: path.to_path_buf(),
                    source: capsec_to_io(e),
                }
            })?;
        }
        capsec::fs::write(path, content, &self.fs_write).map_err(|e| ConfigStoreError::Write {
            path: path.to_path_buf(),
            source: capsec_to_io(e),
        })
    }
}

fn capsec_to_io(e: capsec::CapSecError) -> std::io::Error {
    match e {
        capsec::CapSecError::Io(io) => io,
        other => std::io::Error::other(other.to_string()),
    }
}
