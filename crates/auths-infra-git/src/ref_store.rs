use auths_core::ports::storage::{RefReader, RefWriter, StorageError};

use crate::error::map_git2_error;
use crate::helpers;
use crate::repo::GitRepo;

/// Git-backed implementation of `RefReader` and `RefWriter`.
///
/// References are Git refs. `resolve_ref` returns the commit OID bytes
/// the ref points to. `update_ref` creates or updates a ref to point
/// at a commit whose tree contains the given data.
///
/// Usage:
/// ```ignore
/// use auths_infra_git::{GitRepo, GitRefStore};
/// use auths_core::ports::storage::RefReader;
///
/// let repo = GitRepo::open("/path/to/repo")?;
/// let store = GitRefStore::new(&repo);
/// let oid_bytes = store.resolve_ref("refs/auths/registry")?;
/// ```
pub struct GitRefStore<'r> {
    repo: &'r GitRepo,
}

impl<'r> GitRefStore<'r> {
    pub fn new(repo: &'r GitRepo) -> Self {
        Self { repo }
    }
}

impl RefReader for GitRefStore<'_> {
    fn resolve_ref(&self, refname: &str) -> Result<Vec<u8>, StorageError> {
        self.repo.with_repo(|repo| {
            let oid = helpers::resolve_git_ref(repo, refname).map_err(map_git2_error)?;
            Ok(oid.as_bytes().to_vec())
        })
    }

    fn list_refs(&self, glob: &str) -> Result<Vec<String>, StorageError> {
        self.repo
            .with_repo(|repo| helpers::list_refs_matching(repo, glob).map_err(map_git2_error))
    }
}

impl RefWriter for GitRefStore<'_> {
    fn update_ref(&self, refname: &str, target: &[u8], message: &str) -> Result<(), StorageError> {
        self.repo.with_repo(|repo| {
            helpers::create_ref_commit(repo, refname, target, "data", message)
                .map_err(map_git2_error)?;
            Ok(())
        })
    }

    fn delete_ref(&self, refname: &str) -> Result<(), StorageError> {
        self.repo
            .with_repo(|repo| match repo.find_reference(refname) {
                Ok(mut r) => {
                    r.delete().map_err(map_git2_error)?;
                    Ok(())
                }
                Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(()),
                Err(e) => Err(map_git2_error(e)),
            })
    }
}
