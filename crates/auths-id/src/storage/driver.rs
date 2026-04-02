//! Async storage driver trait for backend-agnostic storage.
//!
//! This trait abstracts storage operations to support both local (Git) and
//! remote (S3, DynamoDB) backends. Local backends use `spawn_blocking` to
//! provide async semantics over synchronous operations.
//!
//! # Design
//!
//! The trait uses simple blob-based operations rather than mirroring the
//! full `RegistryBackend` API. Higher-level operations (identity storage,
//! attestation management) are built on top of these primitives.
//!
//! # Example
//!
//! ```rust,ignore
//! use auths_id::storage::{StorageDriver, StorageError};
//!
//! async fn store_data(driver: &dyn StorageDriver) -> Result<(), StorageError> {
//!     driver.put_blob("identities/abc123", b"data").await?;
//!     let data = driver.get_blob("identities/abc123").await?;
//!     Ok(())
//! }
//! ```

use async_trait::async_trait;
use auths_core::error::AuthsErrorInfo;
use std::fmt;

/// Error type for storage operations.
#[derive(Debug)]
#[non_exhaustive]
pub enum StorageError {
    /// The requested path was not found.
    NotFound(String),

    /// Compare-and-swap conflict: the expected value didn't match.
    CasConflict {
        /// The expected value (None = expected to not exist).
        expected: Option<Vec<u8>>,
        /// The actual value found.
        found: Option<Vec<u8>>,
    },

    /// An I/O or backend-specific error.
    Io(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::NotFound(path) => write!(f, "not found: {}", path),
            StorageError::CasConflict { expected, found } => {
                write!(
                    f,
                    "CAS conflict: expected {:?}, found {:?}",
                    expected.as_ref().map(|v| v.len()),
                    found.as_ref().map(|v| v.len())
                )
            }
            StorageError::Io(e) => write!(f, "storage I/O error: {}", e),
        }
    }
}

impl std::error::Error for StorageError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StorageError::Io(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl AuthsErrorInfo for StorageError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::NotFound(_) => "AUTHS-E4409",
            Self::CasConflict { .. } => "AUTHS-E4410",
            Self::Io(_) => "AUTHS-E4411",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::NotFound(_) => Some("Verify the storage path exists and is initialized"),
            Self::CasConflict { .. } => {
                Some("A concurrent modification was detected; retry the operation")
            }
            Self::Io(_) => {
                Some("Check file permissions, disk space, and storage backend connectivity")
            }
        }
    }
}

impl StorageError {
    /// Create a NotFound error for the given path.
    pub fn not_found(path: impl Into<String>) -> Self {
        StorageError::NotFound(path.into())
    }

    /// Create a CAS conflict error.
    pub fn cas_conflict(expected: Option<Vec<u8>>, found: Option<Vec<u8>>) -> Self {
        StorageError::CasConflict { expected, found }
    }

    /// Create an I/O error from any error type.
    pub fn io<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        StorageError::Io(Box::new(e))
    }
}

/// Async storage driver trait.
///
/// This trait provides low-level blob storage operations with async semantics.
/// Implementations can be backed by local filesystems (via `spawn_blocking`),
/// cloud storage (S3, GCS), or databases (DynamoDB).
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow sharing across async tasks.
///
/// # Error Handling
///
/// All methods return `StorageError` which distinguishes between:
/// - `NotFound`: The path doesn't exist (normal condition)
/// - `CasConflict`: Concurrent modification detected
/// - `Io`: Backend-specific errors
#[async_trait]
pub trait StorageDriver: Send + Sync {
    /// Read a blob from the given path.
    ///
    /// Returns `StorageError::NotFound` if the path doesn't exist.
    async fn get_blob(&self, path: &str) -> Result<Vec<u8>, StorageError>;

    /// Write a blob to the given path.
    ///
    /// Creates parent directories/prefixes as needed.
    /// Overwrites any existing content at the path.
    async fn put_blob(&self, path: &str, data: &[u8]) -> Result<(), StorageError>;

    /// Atomic compare-and-swap update.
    ///
    /// Updates the value at `ref_key` only if it currently matches `expected`.
    /// - `expected = None`: Only succeeds if the key doesn't exist (create)
    /// - `expected = Some(bytes)`: Only succeeds if the current value equals `bytes`
    ///
    /// Returns `StorageError::CasConflict` if the condition isn't met.
    async fn cas_update(
        &self,
        ref_key: &str,
        expected: Option<&[u8]>,
        new: &[u8],
    ) -> Result<(), StorageError>;

    /// List all paths under a prefix.
    ///
    /// Returns paths relative to the storage root, not relative to the prefix.
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, StorageError>;

    /// Check if a path exists.
    async fn exists(&self, path: &str) -> Result<bool, StorageError>;

    /// Delete a blob at the given path.
    ///
    /// Returns `Ok(())` even if the path didn't exist (idempotent).
    async fn delete(&self, path: &str) -> Result<(), StorageError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_error_display() {
        let err = StorageError::not_found("foo/bar");
        assert_eq!(err.to_string(), "not found: foo/bar");

        let err = StorageError::cas_conflict(Some(vec![1, 2, 3]), None);
        assert!(err.to_string().contains("CAS conflict"));
    }

    #[test]
    fn storage_error_io() {
        let io_err = std::io::Error::other("test");
        let err = StorageError::io(io_err);
        assert!(err.to_string().contains("I/O error"));
    }
}
