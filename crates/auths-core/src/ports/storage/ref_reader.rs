use super::StorageError;

/// Reads abstract references that map names to opaque identifiers.
///
/// In a Git-backed implementation, these correspond to Git refs pointing
/// at commit OIDs. The domain treats them as opaque byte sequences
/// without assuming Git semantics.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::storage::RefReader;
///
/// fn current_tip(reader: &dyn RefReader, refname: &str) -> Vec<u8> {
///     reader.resolve_ref(refname).unwrap()
/// }
/// ```
pub trait RefReader: Send + Sync {
    /// Resolves a reference name to its current target bytes.
    ///
    /// Args:
    /// * `refname`: The reference name to resolve (e.g., `"refs/auths/registry"`).
    ///
    /// Usage:
    /// ```ignore
    /// let oid_bytes = reader.resolve_ref("refs/auths/registry")?;
    /// ```
    fn resolve_ref(&self, refname: &str) -> Result<Vec<u8>, StorageError>;

    /// Lists all reference names matching a glob pattern.
    ///
    /// Args:
    /// * `glob`: A glob pattern to match against reference names.
    ///
    /// Usage:
    /// ```ignore
    /// let refs = reader.list_refs("refs/auths/devices/nodes/*/signatures")?;
    /// ```
    fn list_refs(&self, glob: &str) -> Result<Vec<String>, StorageError>;
}
