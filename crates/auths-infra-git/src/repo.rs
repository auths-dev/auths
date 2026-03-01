use auths_core::ports::storage::StorageError;
use git2::Repository;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Newtype wrapper around `git2::Repository`.
///
/// Wraps the repository in a `Mutex` to satisfy `Send + Sync` bounds
/// required by the storage port traits, since `git2::Repository` is
/// not `Sync` by default.
///
/// Usage:
/// ```ignore
/// use auths_infra_git::GitRepo;
///
/// let repo = GitRepo::open("/path/to/repo")?;
/// ```
pub struct GitRepo {
    inner: Mutex<Repository>,
    path: PathBuf,
}

impl GitRepo {
    /// Opens an existing Git repository at the given path.
    ///
    /// Args:
    /// * `path`: Filesystem path to the repository root.
    ///
    /// Usage:
    /// ```ignore
    /// let repo = GitRepo::open("/home/user/.auths")?;
    /// ```
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        let inner = Repository::open(&path).map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(Self {
            inner: Mutex::new(inner),
            path,
        })
    }

    /// Initializes a new Git repository at the given path.
    ///
    /// Args:
    /// * `path`: Filesystem path where the repository will be created.
    ///
    /// Usage:
    /// ```ignore
    /// let repo = GitRepo::init("/tmp/new-repo")?;
    /// ```
    pub fn init(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let path = path.as_ref().to_path_buf();
        let inner = Repository::init(&path).map_err(|e| StorageError::Io(e.to_string()))?;
        Ok(Self {
            inner: Mutex::new(inner),
            path,
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
