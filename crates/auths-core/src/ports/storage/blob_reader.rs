use super::StorageError;

/// Reads arbitrary binary blobs from storage by logical path.
///
/// Paths are abstract identifiers (e.g., `"identities/abc123/metadata"`)
/// that the adapter maps to its backing store. The domain never constructs
/// filesystem or Git-specific paths.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::storage::BlobReader;
///
/// fn load_metadata(reader: &dyn BlobReader, id: &str) -> Vec<u8> {
///     let path = format!("identities/{id}/metadata");
///     reader.get_blob(&path).unwrap()
/// }
/// ```
pub trait BlobReader: Send + Sync {
    /// Returns the raw bytes stored at the given logical path.
    ///
    /// Args:
    /// * `path`: The logical storage path identifying the blob.
    ///
    /// Usage:
    /// ```ignore
    /// let data = reader.get_blob("identities/abc123/metadata")?;
    /// ```
    fn get_blob(&self, path: &str) -> Result<Vec<u8>, StorageError>;

    /// Lists all blob paths under the given prefix.
    ///
    /// Args:
    /// * `prefix`: The logical path prefix to enumerate.
    ///
    /// Usage:
    /// ```ignore
    /// let paths = reader.list_blobs("identities/")?;
    /// ```
    fn list_blobs(&self, prefix: &str) -> Result<Vec<String>, StorageError>;

    /// Checks whether a blob exists at the given logical path.
    ///
    /// Args:
    /// * `path`: The logical storage path to check.
    ///
    /// Usage:
    /// ```ignore
    /// if reader.blob_exists("identities/abc123/metadata")? {
    ///     // load it
    /// }
    /// ```
    fn blob_exists(&self, path: &str) -> Result<bool, StorageError>;
}
