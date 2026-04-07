//! KEL storage port traits for reading and writing Key Event Logs.
//!
//! These traits are pure KERI abstractions — they operate on serialized event
//! bytes identified by KERI prefixes. They have no dependency on any specific
//! storage backend (git2, SQL, etc.) and compile for WASM targets.

use crate::Prefix;

/// Domain error type for KEL storage operations.
///
/// Variants mirror `auths_core::ports::storage::StorageError` so that
/// a `From<KelStorageError> for StorageError` impl can bridge between layers.
///
/// Usage:
/// ```ignore
/// use auths_keri::kel_io::KelStorageError;
///
/// fn handle(err: KelStorageError) {
///     match err {
///         KelStorageError::NotFound { path } => eprintln!("missing: {path}"),
///         KelStorageError::AlreadyExists { path } => eprintln!("duplicate: {path}"),
///         KelStorageError::CasConflict => eprintln!("concurrent modification"),
///         KelStorageError::Io(msg) => eprintln!("I/O: {msg}"),
///         KelStorageError::Internal(inner) => eprintln!("bug: {inner}"),
///     }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KelStorageError {
    /// The item was not found.
    #[error("not found: {path}")]
    NotFound {
        /// Path of the missing item.
        path: String,
    },

    /// An item already exists at this path.
    #[error("already exists: {path}")]
    AlreadyExists {
        /// Path of the existing item.
        path: String,
    },

    /// Optimistic concurrency conflict; retry the operation.
    #[error("compare-and-swap conflict")]
    CasConflict,

    /// An I/O error occurred.
    #[error("storage I/O error: {0}")]
    Io(String),

    /// An unexpected internal error.
    #[error("internal storage error: {0}")]
    Internal(Box<dyn std::error::Error + Send + Sync>),
}

/// Reads serialized key event log (KEL) entries for a KERI prefix.
///
/// Implementations provide access to the ordered event history without
/// exposing how or where events are stored.
///
/// Usage:
/// ```ignore
/// use auths_keri::kel_io::EventLogReader;
/// use auths_keri::Prefix;
///
/// fn latest_event(reader: &dyn EventLogReader, prefix: &Prefix) -> Vec<u8> {
///     reader.read_event_log(prefix).unwrap()
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
    fn read_event_log(&self, prefix: &Prefix) -> Result<Vec<u8>, KelStorageError>;

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
    fn read_event_at(&self, prefix: &Prefix, seq: u64) -> Result<Vec<u8>, KelStorageError>;
}

/// Appends serialized key events to a KERI prefix's event log.
///
/// Implementations handle the mechanics of persisting a new event
/// (e.g., writing a Git commit, inserting a database row) while the
/// domain only provides the serialized event bytes.
///
/// Usage:
/// ```ignore
/// use auths_keri::kel_io::EventLogWriter;
/// use auths_keri::Prefix;
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
    fn append_event(&self, prefix: &Prefix, event: &[u8]) -> Result<(), KelStorageError>;
}
