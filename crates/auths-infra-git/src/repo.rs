use auths_core::ports::storage::StorageError;
use capsec::SendCap;
use git2::Repository;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Newtype wrapper around `git2::Repository`.
///
/// Wraps the repository in a `Mutex` to satisfy `Send + Sync` bounds
/// required by the storage port traits, since `git2::Repository` is
/// not `Sync` by default.
///
/// Holds `SendCap` tokens to document that this adapter performs filesystem I/O.
/// The actual I/O is delegated to `git2` (libgit2), which cannot be capsec-gated;
/// the tokens enforce that only code granted FS capabilities can construct a `GitRepo`.
///
/// Usage:
/// ```ignore
/// use auths_infra_git::GitRepo;
///
/// let cap_root = capsec::test_root();
/// let fs_read = cap_root.fs_read().make_send();
/// let fs_write = cap_root.fs_write().make_send();
/// let repo = GitRepo::open("/path/to/repo", fs_read, fs_write)?;
/// ```
pub struct GitRepo {
    inner: Mutex<Repository>,
    path: PathBuf,
    _fs_read: SendCap<capsec::FsRead>,
    _fs_write: SendCap<capsec::FsWrite>,
}

impl GitRepo {
    /// Opens an existing Git repository at the given path.
    ///
    /// Args:
    /// * `path`: Filesystem path to the repository root.
    /// * `fs_read`: Capability token proving the caller has filesystem read permission.
    /// * `fs_write`: Capability token proving the caller has filesystem write permission.
    ///
    /// Usage:
    /// ```ignore
    /// let cap_root = capsec::test_root();
    /// let repo = GitRepo::open("/home/user/.auths", cap_root.fs_read().make_send(), cap_root.fs_write().make_send())?;
    /// ```
    pub fn open(
        path: impl AsRef<Path>,
        fs_read: SendCap<capsec::FsRead>,
        fs_write: SendCap<capsec::FsWrite>,
    ) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        let inner = Repository::open(&path).map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(Self {
            inner: Mutex::new(inner),
            path,
            _fs_read: fs_read,
            _fs_write: fs_write,
        })
    }

    /// Initializes a new Git repository at the given path.
    ///
    /// Args:
    /// * `path`: Filesystem path where the repository will be created.
    /// * `fs_read`: Capability token proving the caller has filesystem read permission.
    /// * `fs_write`: Capability token proving the caller has filesystem write permission.
    ///
    /// Usage:
    /// ```ignore
    /// let cap_root = capsec::test_root();
    /// let repo = GitRepo::init("/tmp/new-repo", cap_root.fs_read().make_send(), cap_root.fs_write().make_send())?;
    /// ```
    pub fn init(
        path: impl AsRef<Path>,
        fs_read: SendCap<capsec::FsRead>,
        fs_write: SendCap<capsec::FsWrite>,
    ) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        let inner = Repository::init(&path).map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(Self {
            inner: Mutex::new(inner),
            path,
            _fs_read: fs_read,
            _fs_write: fs_write,
        })
    }

    pub(crate) fn with_repo<T>(
        &self,
        f: impl FnOnce(&Repository) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let repo = self
            .inner
            .lock()
            .map_err(|e| StorageError::Io(format!("mutex poisoned: {}", e)))?;
        f(&repo)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
