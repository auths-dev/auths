use auths_core::ports::storage::{EventLogReader, EventLogWriter, StorageError};
use auths_keri::Prefix;
use auths_keri::kel_io::KelStorageError;

use crate::error::map_git2_error;
use crate::helpers;
use crate::repo::GitRepo;

const EVENT_FILE: &str = "event.json";

/// Git-backed implementation of `EventLogReader` and `EventLogWriter`.
///
/// Events are stored as commits on `refs/keri/<prefix>/kel`. Each commit
/// contains a single blob named `event.json`. The commit chain forms the
/// ordered event log for that prefix.
///
/// Usage:
/// ```ignore
/// use auths_infra_git::{GitRepo, GitEventLog};
/// use auths_core::ports::storage::EventLogReader;
///
/// let repo = GitRepo::open("/path/to/repo")?;
/// let log = GitEventLog::new(&repo);
/// let events = log.read_event_log("EAbcdef...")?;
/// ```
pub struct GitEventLog<'r> {
    repo: &'r GitRepo,
}

impl<'r> GitEventLog<'r> {
    pub fn new(repo: &'r GitRepo) -> Self {
        Self { repo }
    }

    fn kel_ref(prefix: &str) -> String {
        format!("refs/keri/{}/kel", prefix)
    }
}

/// Convert a `StorageError` into `KelStorageError` (identical variant set).
fn to_kel(e: StorageError) -> KelStorageError {
    match e {
        StorageError::NotFound { path } => KelStorageError::NotFound { path },
        StorageError::AlreadyExists { path } => KelStorageError::AlreadyExists { path },
        StorageError::CasConflict => KelStorageError::CasConflict,
        StorageError::Io(s) => KelStorageError::Io(s),
        StorageError::Internal(e) => KelStorageError::Internal(e),
        // #[non_exhaustive]: forward any future variants as internal errors
        other => KelStorageError::Internal(Box::new(other)),
    }
}

// auths_core::ports::storage::EventLogReader re-exports auths_keri::kel_io::EventLogReader,
// so these impls satisfy both paths simultaneously.
impl EventLogReader for GitEventLog<'_> {
    fn read_event_log(&self, prefix: &Prefix) -> Result<Vec<u8>, KelStorageError> {
        let refname = Self::kel_ref(prefix.as_str());
        self.repo
            .with_repo(|repo| {
                let events = walk_commits(repo, &refname)?;
                let joined: Vec<u8> = events.into_iter().flatten().collect();
                Ok(joined)
            })
            .map_err(to_kel)
    }

    fn read_event_at(&self, prefix: &Prefix, seq: u64) -> Result<Vec<u8>, KelStorageError> {
        let refname = Self::kel_ref(prefix.as_str());
        self.repo
            .with_repo(|repo| {
                let events = walk_commits(repo, &refname)?;
                events.into_iter().nth(seq as usize).ok_or_else(|| {
                    StorageError::not_found(format!("{}/seq/{}", prefix.as_str(), seq))
                })
            })
            .map_err(to_kel)
    }
}

impl EventLogWriter for GitEventLog<'_> {
    fn append_event(&self, prefix: &Prefix, event: &[u8]) -> Result<(), KelStorageError> {
        let refname = Self::kel_ref(prefix.as_str());
        self.repo
            .with_repo(|repo| {
                helpers::create_ref_commit(
                    repo,
                    &refname,
                    event,
                    EVENT_FILE,
                    &format!("append event to {}", prefix.as_str()),
                )
                .map_err(map_git2_error)?;
                Ok(())
            })
            .map_err(to_kel)
    }
}

fn walk_commits(repo: &git2::Repository, refname: &str) -> Result<Vec<Vec<u8>>, StorageError> {
    let reference = match repo.find_reference(refname) {
        Ok(r) => r,
        Err(e) if e.code() == git2::ErrorCode::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(map_git2_error(e)),
    };

    let mut commit = reference.peel_to_commit().map_err(map_git2_error)?;
    let mut events = Vec::new();

    loop {
        let tree_oid = commit.tree_id();
        match helpers::extract_blob_payload(repo, tree_oid, EVENT_FILE) {
            Ok(data) => events.push(data),
            Err(e) => {
                log::warn!("skipping commit {}: {}", commit.id(), e);
            }
        }

        if commit.parent_count() > 0 {
            commit = commit.parent(0).map_err(map_git2_error)?;
        } else {
            break;
        }
    }

    events.reverse();
    Ok(events)
}
