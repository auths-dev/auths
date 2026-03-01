//! Git log provider port for audit and compliance workflows.
//!
//! Defines the trait boundary for reading commit history.
//! Production adapters (e.g. git2-based) live in infra crates.

/// A single commit record from the repository history.
///
/// Args:
/// * `hash`: The abbreviated commit hash.
/// * `author_name`: The commit author's name.
/// * `author_email`: The commit author's email.
/// * `timestamp`: ISO-8601 formatted commit timestamp.
/// * `message`: First line of the commit message.
/// * `signature_status`: Classification of the commit's signature.
///
/// Usage:
/// ```ignore
/// let record = CommitRecord {
///     hash: "abc1234".to_string(),
///     author_name: "Alice".to_string(),
///     author_email: "alice@example.com".to_string(),
///     timestamp: "2024-01-15T10:00:00Z".to_string(),
///     message: "initial commit".to_string(),
///     signature_status: SignatureStatus::Unsigned,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct CommitRecord {
    /// The abbreviated commit hash.
    pub hash: String,
    /// The commit author's name.
    pub author_name: String,
    /// The commit author's email.
    pub author_email: String,
    /// ISO-8601 formatted commit timestamp.
    pub timestamp: String,
    /// First line of the commit message.
    pub message: String,
    /// Classification of the commit's signature.
    pub signature_status: SignatureStatus,
}

/// Classification of a commit's cryptographic signature.
///
/// Usage:
/// ```ignore
/// match status {
///     SignatureStatus::AuthsSigned { signer_did } => println!("Signed by {signer_did}"),
///     SignatureStatus::SshSigned => println!("SSH signed"),
///     SignatureStatus::GpgSigned { verified } => println!("GPG signed, verified={verified}"),
///     SignatureStatus::Unsigned => println!("No signature"),
///     SignatureStatus::InvalidSignature { reason } => println!("Bad sig: {reason}"),
/// }
/// ```
#[derive(Debug, Clone)]
pub enum SignatureStatus {
    /// Signed using the auths workflow.
    AuthsSigned {
        /// The DID of the signer.
        signer_did: String,
    },
    /// Signed using SSH.
    SshSigned,
    /// Signed using GPG.
    GpgSigned {
        /// Whether the GPG signature was verified.
        verified: bool,
    },
    /// No signature present.
    Unsigned,
    /// A signature was present but invalid.
    InvalidSignature {
        /// The reason the signature is invalid.
        reason: String,
    },
}

/// Errors from git log provider operations.
#[derive(Debug, thiserror::Error)]
pub enum GitProviderError {
    /// Failed to open the git repository.
    #[error("failed to open repository: {0}")]
    Open(String),
    /// Failed to walk the commit history.
    #[error("failed to walk commits: {0}")]
    Walk(String),
    /// An object ID could not be parsed.
    #[error("invalid oid: {0}")]
    InvalidOid(String),
    /// The requested commit was not found.
    #[error("commit not found: {0}")]
    NotFound(String),
    /// The repository lock was poisoned by a panicking thread.
    #[error("repository lock poisoned")]
    LockPoisoned,
}

/// Port for reading commit history from a Git repository.
///
/// Usage:
/// ```ignore
/// let commits: Vec<CommitRecord> = provider
///     .walk_commits(None, Some(100))?
///     .collect::<Result<Vec<_>, _>>()?;
/// ```
pub trait GitLogProvider: Send + Sync {
    /// Walk commit history, optionally constrained by a range spec and limit.
    ///
    /// Args:
    /// * `range`: Optional git revision range (e.g. "HEAD~10..HEAD").
    /// * `limit`: Optional maximum number of commits to return.
    fn walk_commits(
        &self,
        range: Option<&str>,
        limit: Option<usize>,
    ) -> Result<Vec<CommitRecord>, GitProviderError>;
}
