use super::StorageError;

/// Creates, updates, and deletes abstract references.
///
/// In a Git-backed implementation, this corresponds to creating or
/// updating Git refs. The domain provides opaque target bytes and a
/// human-readable message for the reflog.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::storage::RefWriter;
///
/// fn advance_tip(writer: &dyn RefWriter, refname: &str, new_oid: &[u8]) {
///     writer.update_ref(refname, new_oid, "append attestation").unwrap();
/// }
/// ```
pub trait RefWriter: Send + Sync {
    /// Sets a reference to point at the given target bytes.
    ///
    /// Args:
    /// * `refname`: The reference name to create or update.
    /// * `target`: The opaque target bytes (e.g., a commit OID).
    /// * `message`: A human-readable description of the update for logging.
    ///
    /// Usage:
    /// ```ignore
    /// writer.update_ref("refs/auths/registry", &new_oid, "rotation event")?;
    /// ```
    fn update_ref(&self, refname: &str, target: &[u8], message: &str) -> Result<(), StorageError>;

    /// Deletes the named reference.
    ///
    /// Args:
    /// * `refname`: The reference name to delete.
    ///
    /// Usage:
    /// ```ignore
    /// writer.delete_ref("refs/auths/devices/nodes/old-device/signatures")?;
    /// ```
    fn delete_ref(&self, refname: &str) -> Result<(), StorageError>;
}
