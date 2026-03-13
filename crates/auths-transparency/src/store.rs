#[cfg(feature = "native")]
use crate::error::TransparencyError;

/// Async tile storage backend.
///
/// Implementations provide reading and writing of tile data and
/// checkpoint blobs. The filesystem implementation is in [`crate::FsTileStore`]
/// (available with the `native` feature).
///
/// Usage:
/// ```ignore
/// async fn read_tile(store: &dyn TileStore) {
///     let data = store.read_tile("tile/0/000").await?;
/// }
/// ```
#[cfg(feature = "native")]
#[async_trait::async_trait]
pub trait TileStore: Send + Sync {
    /// Read a tile by its C2SP path (e.g., "tile/0/000").
    async fn read_tile(&self, path: &str) -> Result<Vec<u8>, TransparencyError>;

    /// Write a tile at the given C2SP path.
    async fn write_tile(&self, path: &str, data: &[u8]) -> Result<(), TransparencyError>;

    /// Read the latest signed checkpoint.
    async fn read_checkpoint(&self) -> Result<Option<Vec<u8>>, TransparencyError>;

    /// Write a signed checkpoint.
    async fn write_checkpoint(&self, data: &[u8]) -> Result<(), TransparencyError>;
}
