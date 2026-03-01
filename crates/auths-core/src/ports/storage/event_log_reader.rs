use auths_verifier::keri::Prefix;

use super::StorageError;

/// Reads serialized key event log (KEL) entries for a KERI prefix.
///
/// Implementations provide access to the ordered event history without
/// exposing how or where events are stored.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::storage::EventLogReader;
/// use auths_verifier::keri::Prefix;
///
/// fn latest_event(reader: &dyn EventLogReader, prefix: &Prefix) -> Vec<u8> {
///     let full_log = reader.read_event_log(prefix).unwrap();
///     full_log
/// }
/// ```
pub trait EventLogReader: Send + Sync {
    /// Returns the complete serialized event log for the given KERI prefix.
    ///
    /// Args:
    /// * `prefix`: The KERI prefix identifying the event log to read.
    ///
    /// Usage:
    /// ```ignore
    /// let prefix = Prefix::new_unchecked("EAbcdef...".into());
    /// let log_bytes = reader.read_event_log(&prefix)?;
    /// ```
    fn read_event_log(&self, prefix: &Prefix) -> Result<Vec<u8>, StorageError>;

    /// Returns a single serialized event at the given sequence number.
    ///
    /// Args:
    /// * `prefix`: The KERI prefix identifying the event log.
    /// * `seq`: The zero-based sequence number of the event to retrieve.
    ///
    /// Usage:
    /// ```ignore
    /// let prefix = Prefix::new_unchecked("EAbcdef...".into());
    /// let inception = reader.read_event_at(&prefix, 0)?;
    /// ```
    fn read_event_at(&self, prefix: &Prefix, seq: u64) -> Result<Vec<u8>, StorageError>;
}
