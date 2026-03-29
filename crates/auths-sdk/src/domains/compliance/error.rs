use auths_core::error::AuthsErrorInfo;
use thiserror::Error;

/// Errors from approval workflow operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApprovalError {
    /// The decision is not RequiresApproval.
    #[error("decision is not RequiresApproval")]
    NotApprovalRequired,

    /// Approval request not found.
    #[error("approval request not found: {hash}")]
    RequestNotFound {
        /// The hex-encoded request hash.
        hash: String,
    },

    /// Approval request expired.
    #[error("approval request expired at {expires_at}")]
    RequestExpired {
        /// When the request expired.
        expires_at: chrono::DateTime<chrono::Utc>,
    },

    /// Approval JTI already used (replay attempt).
    #[error("approval already used (JTI: {jti})")]
    ApprovalAlreadyUsed {
        /// The consumed JTI.
        jti: String,
    },

    /// Approval partially applied — attestation stored but nonce/cleanup failed.
    #[error("approval partially applied — attestation stored but nonce/cleanup failed: {0}")]
    PartialApproval(String),

    /// A storage operation failed.
    #[error("storage error: {0}")]
    ApprovalStorage(#[source] crate::error::SdkStorageError),
}

impl AuthsErrorInfo for ApprovalError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::NotApprovalRequired => "AUTHS-E5701",
            Self::RequestNotFound { .. } => "AUTHS-E5702",
            Self::RequestExpired { .. } => "AUTHS-E5703",
            Self::ApprovalAlreadyUsed { .. } => "AUTHS-E5704",
            Self::PartialApproval(_) => "AUTHS-E5705",
            Self::ApprovalStorage(_) => "AUTHS-E5706",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::NotApprovalRequired => Some(
                "This operation does not require approval; run it directly without the --approve flag",
            ),
            Self::RequestNotFound { .. } => {
                Some("Run `auths approval list` to see pending requests")
            }
            Self::RequestExpired { .. } => Some("Submit a new approval request"),
            Self::ApprovalAlreadyUsed { .. } => Some("Submit a new approval request"),
            Self::PartialApproval(_) => Some("Check approval status and retry if needed"),
            Self::ApprovalStorage(_) => Some("Check file permissions and disk space"),
        }
    }
}
