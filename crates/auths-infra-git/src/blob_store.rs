use auths_core::ports::storage::{BlobReader, BlobWriter, StorageError};

use crate::error::map_git2_error;
use crate::helpers;
use crate::repo::GitRepo;

const BLOB_FILE: &str = "data";

/// Git-backed implementation of `BlobReader` and `BlobWriter`.
///
/// Stores blobs as single-file Git commits on refs derived from the
/// logical path. For example, the path `"identities/abc123/metadata"`
/// maps to the ref `refs/auths/blobs/identities/abc123/metadata`.
///
/// Usage:
/// ```ignore
/// use auths_infra_git::{GitRepo, GitBlobStore};
/// use auths_core::ports::storage::BlobReader;
///
/// let repo = GitRepo::open("/path/to/repo")?;
/// let store = GitBlobStore::new(&repo);
/// let data = store.get_blob("identities/abc123/metadata")?;
/// ```
pub struct GitBlobStore<'r> {
    repo: &'r GitRepo,
}

impl<'r> GitBlobStore<'r> {
    pub fn new(repo: &'r GitRepo) -> Self {
        Self { repo }
    }

    fn ref_for_path(path: &str) -> String {
        format!("refs/auths/blobs/{}", path)
    }
}

impl BlobReader for GitBlobStore<'_> {
    fn get_blob(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        let refname = Self::ref_for_path(path);
        self.repo.with_repo(|repo| {
            let oid = helpers::resolve_git_ref(repo, &refname).map_err(map_git2_error)?;
            let commit = repo.find_commit(oid).map_err(map_git2_error)?;
            let tree_oid = commit.tree_id();
            helpers::extract_blob_payload(repo, tree_oid, BLOB_FILE).map_err(map_git2_error)
        })
    }

    fn list_blobs(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let glob = format!("refs/auths/blobs/{}*", prefix);
        self.repo.with_repo(|repo| {
            let refs = helpers::list_refs_matching(repo, &glob).map_err(map_git2_error)?;
            let strip_prefix = "refs/auths/blobs/";
            Ok(refs
                .into_iter()
                .filter_map(|r| r.strip_prefix(strip_prefix).map(String::from))
                .collect())
        })
    }

    fn blob_exists(&self, path: &str) -> Result<bool, StorageError> {
        let refname = Self::ref_for_path(path);
        self.repo
            .with_repo(|repo| match repo.find_reference(&refname) {
                Ok(_) => Ok(true),
                Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(false),
                Err(e) => Err(map_git2_error(e)),
            })
    }
}

impl BlobWriter for GitBlobStore<'_> {
    fn put_blob(&self, path: &str, data: &[u8]) -> Result<(), StorageError> {
        let refname = Self::ref_for_path(path);
        self.repo.with_repo(|repo| {
            helpers::create_ref_commit(
                repo,
                &refname,
                data,
                BLOB_FILE,
                &format!("put blob {}", path),
            )
            .map_err(map_git2_error)?;
            Ok(())
        })
    }

    fn delete_blob(&self, path: &str) -> Result<(), StorageError> {
        let refname = Self::ref_for_path(path);
        self.repo
            .with_repo(|repo| match repo.find_reference(&refname) {
                Ok(mut r) => {
                    r.delete().map_err(map_git2_error)?;
                    Ok(())
                }
                Err(e) if e.code() == git2::ErrorCode::NotFound => Ok(()),
                Err(e) => Err(map_git2_error(e)),
            })
    }
}
