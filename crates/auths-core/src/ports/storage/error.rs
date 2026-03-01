use std::fmt;

/// Domain error type for all storage port operations.
///
/// Adapters map backend-specific errors (e.g., `git2::Error`, `std::io::Error`)
/// into these variants before returning. Domain logic never sees infrastructure
/// error types.
///
/// Usage:
/// ```ignore
/// use auths_core::ports::storage::StorageError;
///
/// fn handle(err: StorageError) {
///     match err {
///         StorageError::NotFound { path } => eprintln!("missing: {path}"),
///         StorageError::AlreadyExists { path } => eprintln!("duplicate: {path}"),
///         StorageError::CasConflict => eprintln!("concurrent modification"),
///         StorageError::Io(msg) => eprintln!("I/O: {msg}"),
///         StorageError::Internal(inner) => eprintln!("bug: {inner}"),
///     }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
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

impl StorageError {
    /// Convenience constructor for `NotFound`.
    pub fn not_found(path: impl fmt::Display) -> Self {
        StorageError::NotFound {
            path: path.to_string(),
        }
    }

    /// Convenience constructor for `AlreadyExists`.
    pub fn already_exists(path: impl fmt::Display) -> Self {
        StorageError::AlreadyExists {
            path: path.to_string(),
        }
    }

    /// Convenience constructor wrapping any error as `Internal`.
    pub fn internal(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        StorageError::Internal(Box::new(err))
    }
}
