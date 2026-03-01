//! Virtual filesystem abstraction for the Git registry backend.
//!
//! Defines the [`Vfs`] trait for filesystem operations and provides
//! [`OsVfs`] as the production implementation backed by the OS + `tempfile`.
//!
//! The VFS layer lets unit tests substitute a fake or in-memory implementation
//! without touching the real filesystem.

use std::path::{Path, PathBuf};

use auths_id::ports::registry::RegistryError;

// ── Trait ────────────────────────────────────────────────────────────────────

/// Virtual filesystem abstraction over the operations the registry backend needs.
///
/// All implementations must be `Send + Sync` so they can be stored in
/// `Arc<dyn Vfs>` and shared across threads.
pub trait Vfs: Send + Sync {
    /// Read the full contents of a file.
    ///
    /// Args:
    /// * `path`: Absolute path to the file to read.
    ///
    /// Usage:
    /// ```ignore
    /// let bytes = vfs.read_file(Path::new("/var/lib/auths/tenant.json"))?;
    /// ```
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, RegistryError>;

    /// Write `contents` to `path` atomically via a temporary file.
    ///
    /// The file is first written to a sibling temp file, then renamed into
    /// `path` so readers never observe a partial write.
    ///
    /// Args:
    /// * `path`: Final destination path.
    /// * `contents`: Bytes to write.
    ///
    /// Usage:
    /// ```ignore
    /// vfs.atomic_write(Path::new("/var/lib/auths/tenant.json"), b"...")?;
    /// ```
    fn atomic_write(&self, path: &Path, contents: &[u8]) -> Result<(), RegistryError>;

    /// Delete the file at `path` if it exists.
    ///
    /// Args:
    /// * `path`: Path to the file to delete.
    ///
    /// Usage:
    /// ```ignore
    /// vfs.delete_file(Path::new("/var/lib/auths/tenant.json"))?;
    /// ```
    fn delete_file(&self, path: &Path) -> Result<(), RegistryError>;

    /// Return `true` if a file or directory exists at `path`.
    ///
    /// Args:
    /// * `path`: Path to check.
    ///
    /// Usage:
    /// ```ignore
    /// if vfs.exists(Path::new("/var/lib/auths/tenant.json")) { ... }
    /// ```
    fn exists(&self, path: &Path) -> bool;
}

// ── OsVfs ────────────────────────────────────────────────────────────────────

/// Production [`Vfs`] backed by the OS filesystem.
///
/// Atomic writes use [`tempfile::NamedTempFile`] + `.persist()` to guarantee
/// that readers never observe partial writes, and that orphaned temp files are
/// cleaned up automatically on panic.
///
/// Args:
/// * (no constructor arguments — uses the OS filesystem unconditionally)
///
/// Usage:
/// ```ignore
/// let vfs = OsVfs;
/// vfs.atomic_write(Path::new("/tmp/tenant.json"), b"{}")?;
/// ```
pub struct OsVfs;

impl Vfs for OsVfs {
    fn read_file(&self, path: &Path) -> Result<Vec<u8>, RegistryError> {
        std::fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                RegistryError::NotFound {
                    entity_type: "file".into(),
                    id: path.display().to_string(),
                }
            } else {
                RegistryError::storage(e)
            }
        })
    }

    fn atomic_write(&self, path: &Path, contents: &[u8]) -> Result<(), RegistryError> {
        let dir = path.parent().unwrap_or_else(|| Path::new("."));
        write_atomically(dir, path, contents)
    }

    fn delete_file(&self, path: &Path) -> Result<(), RegistryError> {
        std::fs::remove_file(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                RegistryError::NotFound {
                    entity_type: "file".into(),
                    id: path.display().to_string(),
                }
            } else {
                RegistryError::storage(e)
            }
        })
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }
}

/// Write `contents` to `final_path` atomically using `tempfile::NamedTempFile`.
///
/// Creates the temp file in `dir` (same directory as `final_path`) to ensure
/// rename is on the same filesystem and avoids `EXDEV` errors.
///
/// Args:
/// * `dir`: Directory where the temp file is created (must be on the same filesystem as `final_path`).
/// * `final_path`: Destination path.
/// * `contents`: Bytes to write.
fn write_atomically(dir: &Path, final_path: &Path, contents: &[u8]) -> Result<(), RegistryError> {
    use std::io::Write as _;
    use tempfile::Builder;

    let mut tmp = Builder::new()
        .tempfile_in(dir)
        .map_err(RegistryError::storage)?;
    tmp.write_all(contents).map_err(RegistryError::storage)?;
    tmp.flush().map_err(RegistryError::storage)?;

    let (_, tmp_path) = tmp.keep().map_err(|e| RegistryError::storage(e.error))?;
    persist_temp_file(&tmp_path, final_path)
}

/// Rename `tmp_path` to `final_path`, handling cross-device moves on Windows.
///
/// On POSIX systems, `rename` is atomic. On Windows, we fall back to
/// `copy + delete` if rename fails with a permission error (which occurs
/// across drives).
///
/// Args:
/// * `tmp_path`: Source temp file path.
/// * `final_path`: Destination path.
fn persist_temp_file(tmp_path: &PathBuf, final_path: &Path) -> Result<(), RegistryError> {
    match std::fs::rename(tmp_path, final_path) {
        Ok(()) => Ok(()),
        #[cfg(windows)]
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            std::fs::copy(tmp_path, final_path).map_err(RegistryError::storage)?;
            let _ = std::fs::remove_file(tmp_path);
            Ok(())
        }
        Err(e) => Err(RegistryError::storage(e)),
    }
}

// ── FixedClock ───────────────────────────────────────────────────────────────

/// A [`ClockProvider`] that always returns a fixed timestamp.
///
/// Use in tests to assert on timestamp-dependent behavior without relying on
/// wall-clock time.
///
/// Args:
/// * `at`: The fixed `DateTime<Utc>` that `now()` will always return.
///
/// Usage:
/// ```ignore
/// use auths_storage::git::vfs::FixedClock;
/// let clock = FixedClock::new(DateTime::from_timestamp(0, 0).unwrap());
/// assert_eq!(clock.now().timestamp(), 0);
/// ```
pub struct FixedClock {
    at: chrono::DateTime<chrono::Utc>,
}

impl FixedClock {
    /// Create a new `FixedClock` frozen at `at`.
    pub fn new(at: chrono::DateTime<chrono::Utc>) -> Self {
        Self { at }
    }
}

impl auths_verifier::clock::ClockProvider for FixedClock {
    fn now(&self) -> chrono::DateTime<chrono::Utc> {
        self.at
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn os_vfs_round_trip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.json");
        let vfs = OsVfs;

        assert!(!vfs.exists(&path));
        vfs.atomic_write(&path, b"{\"ok\":true}").unwrap();
        assert!(vfs.exists(&path));

        let bytes = vfs.read_file(&path).unwrap();
        assert_eq!(bytes, b"{\"ok\":true}");

        vfs.delete_file(&path).unwrap();
        assert!(!vfs.exists(&path));
    }

    #[test]
    fn atomic_write_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("data.json");
        let vfs = OsVfs;

        vfs.atomic_write(&path, b"first").unwrap();
        vfs.atomic_write(&path, b"second").unwrap();

        let bytes = vfs.read_file(&path).unwrap();
        assert_eq!(bytes, b"second");
    }

    #[test]
    fn read_file_returns_not_found() {
        let vfs = OsVfs;
        let err = vfs
            .read_file(Path::new("/nonexistent/path.json"))
            .unwrap_err();
        assert!(matches!(err, RegistryError::NotFound { .. }));
    }
}
