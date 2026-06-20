//! Git2-based audit log provider.
//!
//! Reads commit history using libgit2 instead of subprocess calls.

use auths_sdk::ports::git::{CommitRecord, GitLogProvider, GitProviderError, SignatureStatus};
use auths_sdk::workflows::commit_trust::commit_signer_trailers;
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
                message: commit.summary().ok().flatten().unwrap_or("").to_string(),
                signature_status,
            });
        }

        Ok(records)
    }
}

fn classify_signature(repo: &git2::Repository, commit: &git2::Commit) -> SignatureStatus {
    let signature = repo.extract_signature(&commit.id(), None).ok();
    classify_commit_signature(
        commit.message().unwrap_or_default(),
        signature.as_ref().map(|sig| sig.0.as_ref()),
    )
}

/// Classify a commit's signature for the audit view. An auths-signed commit names its signer in the
/// in-band `Auths-Id` / `Auths-Device` trailers, so the signer DID is read from those trailers rather
/// than by scanning the signature bytes. The remaining arms describe the signature format only; they
/// do not assert that the signature verifies.
///
/// Args:
/// * `message`: the commit message (the trailers live in its body).
/// * `signature`: the raw signature bytes if the commit is signed.
fn classify_commit_signature(message: &str, signature: Option<&[u8]>) -> SignatureStatus {
    if let Some((_id_did, device_did)) = commit_signer_trailers(message) {
        return SignatureStatus::AuthsSigned {
            signer_did: device_did,
        };
    }
    let Some(sig_bytes) = signature else {
        return SignatureStatus::Unsigned;
    };
    let sig_str = String::from_utf8_lossy(sig_bytes);
    if sig_str.contains("-----BEGIN SSH SIGNATURE-----") {
        SignatureStatus::SshSigned
    } else if sig_str.contains("-----BEGIN PGP SIGNATURE-----") {
        SignatureStatus::GpgSigned { verified: false }
    } else {
        SignatureStatus::InvalidSignature {
            reason: "unknown signature format".to_string(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_whose_bytes_contain_auths_is_not_auths_signed_without_trailers() {
        let ssh_signature =
            b"-----BEGIN SSH SIGNATURE-----\nU1NIU0lHauthsZZ\n-----END SSH SIGNATURE-----\n";
        assert!(matches!(
            classify_commit_signature("a commit\n\njust a message", Some(ssh_signature)),
            SignatureStatus::SshSigned
        ));
    }

    #[test]
    fn the_auths_trailers_name_the_signer() {
        let message =
            "a commit\n\nbody text\n\nAuths-Id: did:keri:root\nAuths-Device: did:keri:device";
        match classify_commit_signature(message, None) {
            SignatureStatus::AuthsSigned { signer_did } => {
                assert_eq!(signer_did, "did:keri:device");
            }
            other => panic!("expected AuthsSigned, got {other:?}"),
        }
    }
}
