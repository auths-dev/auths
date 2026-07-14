use std::path::PathBuf;

use crate::error::TransparencyError;
use crate::store::TileStore;
use crate::writer::LogSigningKey;

/// PKCS#8 signing-key file kept inside a local log directory.
const LOG_KEY_FILE: &str = "log.key";

/// Filesystem-backed tile store.
///
/// Stores tiles and checkpoints as plain files under a base directory.
/// Full tiles (paths without `.p/`) are write-once: subsequent writes
/// are silently skipped. Partial tiles (paths containing `.p/`) and
/// the checkpoint file are always overwritable.
///
/// Args:
/// * `base_path` — Root directory for all tile and checkpoint files.
///
/// Usage:
/// ```ignore
/// let store = FsTileStore::new("/home/user/.auths/tlog".into());
/// store.write_tile("tile/0/000", &data).await?;
/// ```
pub struct FsTileStore {
    base_path: PathBuf,
}

impl FsTileStore {
    /// Creates a new filesystem tile store rooted at the given path.
    ///
    /// Args:
    /// * `base_path` — Directory where tiles and checkpoints are stored.
    ///
    /// Usage:
    /// ```ignore
    /// let store = FsTileStore::new(PathBuf::from("/tmp/tlog"));
    /// ```
    pub fn new(base_path: PathBuf) -> Self {
        Self { base_path }
    }

    /// Create the store's base directory (and any missing parents).
    ///
    /// Args:
    /// * none beyond `self`.
    ///
    /// Usage:
    /// ```ignore
    /// store.ensure_base_dir()?;
    /// ```
    pub fn ensure_base_dir(&self) -> Result<(), TransparencyError> {
        std::fs::create_dir_all(&self.base_path)
            .map_err(|e| TransparencyError::StoreError(e.to_string()))
    }

    /// Load the log's signing key from `<base>/log.key`, minting and
    /// persisting a fresh one (mode `0600` on Unix) on first use when `create`
    /// is set.
    ///
    /// Returns `Ok(None)` when the key is absent and `create` is false, so a
    /// caller can distinguish "no log here yet" from an I/O failure without
    /// itself touching the filesystem.
    ///
    /// Args:
    /// * `create` — Generate and persist a key if none exists yet.
    ///
    /// Usage:
    /// ```ignore
    /// let key = store.load_or_create_key(true)?.expect("created on first use");
    /// ```
    pub fn load_or_create_key(
        &self,
        create: bool,
    ) -> Result<Option<LogSigningKey>, TransparencyError> {
        let path = self.base_path.join(LOG_KEY_FILE);
        match std::fs::read(&path) {
            Ok(der) => LogSigningKey::from_pkcs8_der(&der).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && create => {
                let key = LogSigningKey::generate()?;
                let der = key.to_pkcs8_der()?;
                std::fs::write(&path, &der)
                    .map_err(|e| TransparencyError::StoreError(e.to_string()))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .map_err(|e| TransparencyError::StoreError(e.to_string()))?;
                }
                Ok(Some(key))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(TransparencyError::StoreError(e.to_string())),
        }
    }
}

fn is_partial_tile(path: &str) -> bool {
    path.contains(".p/")
}

#[async_trait::async_trait]
impl TileStore for FsTileStore {
    async fn read_tile(&self, path: &str) -> Result<Vec<u8>, TransparencyError> {
        let full_path = self.base_path.join(path);
        tokio::fs::read(&full_path)
            .await
            .map_err(|e| TransparencyError::StoreError(e.to_string()))
    }

    async fn write_tile(&self, path: &str, data: &[u8]) -> Result<(), TransparencyError> {
        let full_path = self.base_path.join(path);

        if !is_partial_tile(path) && full_path.exists() {
            return Ok(());
        }

        if let Some(parent) = full_path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| TransparencyError::StoreError(e.to_string()))?;
        }

        tokio::fs::write(&full_path, data)
            .await
            .map_err(|e| TransparencyError::StoreError(e.to_string()))
    }

    async fn read_checkpoint(&self) -> Result<Option<Vec<u8>>, TransparencyError> {
        let path = self.base_path.join("checkpoint");
        match tokio::fs::read(&path).await {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(TransparencyError::StoreError(e.to_string())),
        }
    }

    async fn write_checkpoint(&self, data: &[u8]) -> Result<(), TransparencyError> {
        let path = self.base_path.join("checkpoint");

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| TransparencyError::StoreError(e.to_string()))?;
        }

        tokio::fs::write(&path, data)
            .await
            .map_err(|e| TransparencyError::StoreError(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tile_write_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsTileStore::new(dir.path().to_path_buf());

        let data = b"leaf data";
        store.write_tile("tile/0/000", data).await.unwrap();

        let read_back = store.read_tile("tile/0/000").await.unwrap();
        assert_eq!(read_back, data);
    }

    #[tokio::test]
    async fn tile_creates_nested_directories() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsTileStore::new(dir.path().to_path_buf());

        store.write_tile("tile/2/001/002", b"deep").await.unwrap();

        let on_disk = dir.path().join("tile/2/001/002");
        assert!(on_disk.exists());
    }

    #[tokio::test]
    async fn full_tile_is_immutable() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsTileStore::new(dir.path().to_path_buf());

        store.write_tile("tile/0/000", b"first").await.unwrap();
        store.write_tile("tile/0/000", b"second").await.unwrap();

        let data = store.read_tile("tile/0/000").await.unwrap();
        assert_eq!(data, b"first");
    }

    #[tokio::test]
    async fn partial_tile_is_overwritable() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsTileStore::new(dir.path().to_path_buf());

        store
            .write_tile("tile/0/000.p/5", b"partial-v1")
            .await
            .unwrap();
        store
            .write_tile("tile/0/000.p/5", b"partial-v2")
            .await
            .unwrap();

        let data = store.read_tile("tile/0/000.p/5").await.unwrap();
        assert_eq!(data, b"partial-v2");
    }

    #[tokio::test]
    async fn checkpoint_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsTileStore::new(dir.path().to_path_buf());

        let result = store.read_checkpoint().await.unwrap();
        assert!(result.is_none());

        store.write_checkpoint(b"cp-v1").await.unwrap();
        let data = store.read_checkpoint().await.unwrap();
        assert_eq!(data, Some(b"cp-v1".to_vec()));

        store.write_checkpoint(b"cp-v2").await.unwrap();
        let data = store.read_checkpoint().await.unwrap();
        assert_eq!(data, Some(b"cp-v2".to_vec()));
    }

    #[tokio::test]
    async fn read_nonexistent_tile_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = FsTileStore::new(dir.path().to_path_buf());

        let result = store.read_tile("tile/0/999").await;
        assert!(result.is_err());
    }
}
