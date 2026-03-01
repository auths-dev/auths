use super::StorageError;

/// Writes and deletes arbitrary binary blobs in storage by logical path.
///
/// Implementations handle the details of persisting bytes to the backing
/// store (Git tree mutations, filesystem writes, database inserts).
///
/// Usage:
/// ```ignore
/// use auths_core::ports::storage::BlobWriter;
///
/// fn save_metadata(writer: &dyn BlobWriter, id: &str, data: &[u8]) {
///     let path = format!("identities/{id}/metadata");
///     writer.put_blob(&path, data).unwrap();
/// }
/// ```
pub trait BlobWriter: Send + Sync {
    /// Writes raw bytes to the given logical path, creating or overwriting.
    ///
    /// Args:
    /// * `path`: The logical storage path for the blob.
    /// * `data`: The raw bytes to store.
    ///
    /// Usage:
    /// ```ignore
    /// writer.put_blob("identities/abc123/metadata", &serialized)?;
    /// ```
    fn put_blob(&self, path: &str, data: &[u8]) -> Result<(), StorageError>;

    /// Deletes the blob at the given logical path.
    ///
    /// Args:
    /// * `path`: The logical storage path to delete.
    ///
    /// Usage:
    /// ```ignore
    /// writer.delete_blob("identities/abc123/metadata")?;
    /// ```
    fn delete_blob(&self, path: &str) -> Result<(), StorageError>;
}
