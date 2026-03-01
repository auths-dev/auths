use auths_verifier::keri::Prefix;

use super::StorageError;

/// Appends serialized key events to a KERI prefix's event log.
///
/// Implementations handle the mechanics of persisting a new event
/// (e.g., writing a Git commit, inserting a database row) while the
/// domain only provides the serialized event bytes.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::storage::EventLogWriter;
/// use auths_verifier::keri::Prefix;
///
/// fn record_inception(writer: &dyn EventLogWriter, prefix: &Prefix, event: &[u8]) {
///     writer.append_event(prefix, event).unwrap();
/// }
/// ```
pub trait EventLogWriter: Send + Sync {
    /// Appends a serialized event to the log for the given KERI prefix.
    ///
    /// Args:
    /// * `prefix`: The KERI prefix identifying the event log.
    /// * `event`: The serialized event bytes to append.
    ///
    /// Usage:
    /// ```ignore
    /// let prefix = Prefix::new_unchecked("EAbcdef...".into());
    /// writer.append_event(&prefix, &serialized_icp)?;
    /// ```
    fn append_event(&self, prefix: &Prefix, event: &[u8]) -> Result<(), StorageError>;
}
