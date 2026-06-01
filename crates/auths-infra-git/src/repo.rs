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
        disable_gc(&inner)?;
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

/// Disable automatic garbage collection and object pruning on a repository.
///
/// Identity KELs are stored as Git objects; an automatic `git gc` that prunes
/// an unreferenced object is silent identity loss. Every Auths repo is created
/// with `gc.auto = 0` and `gc.pruneExpire = never` so objects are retained
/// regardless of reachability.
///
/// Args:
/// * `repo`: The freshly-initialized repository to configure.
fn disable_gc(repo: &Repository) -> Result<(), StorageError> {
    let mut cfg = repo.config().map_err(|e| StorageError::Io(e.to_string()))?;
    cfg.set_i32("gc.auto", 0)
        .map_err(|e| StorageError::Io(e.to_string()))?;
    cfg.set_str("gc.pruneExpire", "never")
        .map_err(|e| StorageError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn init_disables_gc() {
        let dir = tempfile::tempdir().unwrap();
        let repo = GitRepo::init(dir.path()).unwrap();
        repo.with_repo(|r| {
            let cfg = r.config().map_err(|e| StorageError::Io(e.to_string()))?;
            assert_eq!(cfg.get_i32("gc.auto").unwrap(), 0);
            assert_eq!(cfg.get_string("gc.pruneExpire").unwrap(), "never");
            Ok(())
        })
        .unwrap();
    }
}
