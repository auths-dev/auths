//! Git2-based audit log provider.
//!
//! Reads commit history using libgit2 instead of subprocess calls.

use auths_sdk::ports::git::{CommitRecord, GitLogProvider, GitProviderError, SignatureStatus};
use std::path::Path;
use std::sync::Mutex;

/// Production adapter that reads commit history via git2.
///
/// Wraps `git2::Repository` in a `Mutex` to satisfy `Send + Sync`.
///
/// Args:
/// * `repo`: Mutex-wrapped git2 repository handle.
///
/// Usage:
/// ```ignore
/// let provider = Git2LogProvider::open(Path::new("."))?;
/// let commits = provider.walk_commits(None, Some(100))?;
/// ```
pub struct Git2LogProvider {
    repo: Mutex<git2::Repository>,
}

impl Git2LogProvider {
    /// Open a git repository at the given path.
    ///
    /// Args:
    /// * `path`: Filesystem path to the repository root.
    pub fn open(path: &Path) -> Result<Self, GitProviderError> {
        let repo =
            git2::Repository::open(path).map_err(|e| GitProviderError::Open(e.to_string()))?;
        Ok(Self {
            repo: Mutex::new(repo),
        })
    }
}

impl GitLogProvider for Git2LogProvider {
    fn walk_commits(
        &self,
        range: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<CommitRecord>, GitProviderError> {
        let repo = self
            .repo
            .lock()
            .map_err(|_| GitProviderError::LockPoisoned)?;

        let mut revwalk = repo
            .revwalk()
            .map_err(|e| GitProviderError::Walk(e.to_string()))?;
        revwalk
            .set_sorting(git2::Sort::TOPOLOGICAL | git2::Sort::TIME)
            .map_err(|e| GitProviderError::Walk(e.to_string()))?;

        if let Some(range_spec) = range {
            revwalk
                .push_range(range_spec)
                .map_err(|e| GitProviderError::Walk(e.to_string()))?;
        } else {
            revwalk
                .push_head()
                .map_err(|e| GitProviderError::Walk(e.to_string()))?;
        }

        let mut records = Vec::new();
        let max = limit.unwrap_or(usize::MAX);

        for oid_result in revwalk {
            if records.len() >= max {
                break;
            }

            let oid = oid_result.map_err(|e| GitProviderError::Walk(e.to_string()))?;
            let commit = repo
                .find_commit(oid)
                .map_err(|e| GitProviderError::NotFound(e.to_string()))?;

            let signature_status = classify_signature(&repo, &commit);

            let author = commit.author();
            records.push(CommitRecord {
                hash: oid.to_string()[..7].to_string(),
                author_name: author.name().unwrap_or("unknown").to_string(),
                author_email: author.email().unwrap_or("").to_string(),
                timestamp: format_commit_time(&commit),
                message: commit.summary().unwrap_or("").to_string(),
                signature_status,
            });
        }

        Ok(records)
    }
}

fn classify_signature(repo: &git2::Repository, commit: &git2::Commit) -> SignatureStatus {
    match repo.extract_signature(&commit.id(), None) {
        Ok(sig_buf) => {
            let sig_bytes = sig_buf.0;
            let sig_str = String::from_utf8_lossy(sig_bytes.as_ref());

            if sig_str.contains("-----BEGIN SSH SIGNATURE-----") {
                // SSH signature — check if it's auths-signed by looking for auths namespace
                if sig_str.contains("auths") {
                    SignatureStatus::AuthsSigned {
                        signer_did: String::new(),
                    }
                } else {
                    SignatureStatus::SshSigned
                }
            } else if sig_str.contains("-----BEGIN PGP SIGNATURE-----") {
                SignatureStatus::GpgSigned { verified: false }
            } else {
                SignatureStatus::InvalidSignature {
                    reason: "unknown signature format".to_string(),
                }
            }
        }
        Err(_) => SignatureStatus::Unsigned,
    }
}

fn format_commit_time(commit: &git2::Commit) -> String {
    let time = commit.time();
    let secs = time.seconds();
    let offset_minutes = time.offset_minutes();
    let offset_hours = offset_minutes / 60;
    let offset_mins = (offset_minutes % 60).abs();
    let sign = if offset_minutes >= 0 { '+' } else { '-' };

    // Convert epoch seconds to date components using chrono if available,
    // otherwise format as epoch. Since auths-sdk already depends on chrono:
    format!(
        "{}{}{}:{:02}",
        chrono::DateTime::from_timestamp(secs, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S").to_string())
            .unwrap_or_else(|| secs.to_string()),
        sign,
        offset_hours.abs(),
        offset_mins
    )
}
