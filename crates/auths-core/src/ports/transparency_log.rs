//! Transparency log port trait for pluggable log backends.
//!
//! Abstracts appending attestations to a transparency log and
//! retrieving inclusion proofs. The SDK and CLI depend only on this
//! trait — adapter selection happens at the composition root.

use async_trait::async_trait;
use auths_transparency::checkpoint::SignedCheckpoint;
use auths_transparency::proof::{ConsistencyProof, InclusionProof};
use auths_transparency::types::LogOrigin;
use auths_verifier::Ed25519PublicKey;

/// Result of submitting a leaf to a transparency log.
///
/// Args:
/// * `leaf_index` — The zero-based index assigned to the leaf.
/// * `inclusion_proof` — Merkle inclusion proof against the checkpoint.
/// * `signed_checkpoint` — The log's signed checkpoint at submission time.
///
/// Usage:
/// ```ignore
/// let submission = log.submit(data, &pk, &sig).await?;
/// assert!(submission.inclusion_proof.verify(&leaf_hash).is_ok());
/// ```
#[derive(Debug, Clone)]
pub struct LogSubmission {
    /// Zero-based leaf index in the log.
    pub leaf_index: u64,
    /// Merkle inclusion proof for the leaf against the checkpoint.
    pub inclusion_proof: InclusionProof,
    /// Signed checkpoint at the time of submission.
    pub signed_checkpoint: SignedCheckpoint,
}

/// Static metadata about a transparency log backend.
///
/// Args:
/// * `log_id` — Stable identifier for trust config lookup (e.g., `"sigstore-rekor"`).
/// * `log_origin` — C2SP checkpoint origin string.
/// * `log_public_key` — The log's public key for checkpoint verification.
/// * `api_url` — Optional API endpoint URL.
///
/// Usage:
/// ```ignore
/// let meta = log.metadata();
/// println!("Log: {} ({})", meta.log_id, meta.log_origin);
/// ```
#[derive(Debug, Clone)]
pub struct LogMetadata {
    /// Stable identifier used in trust config and bundle format.
    pub log_id: String,
    /// C2SP checkpoint origin string (byte-for-byte match required).
    pub log_origin: LogOrigin,
    /// The log's public key for checkpoint signature verification.
    pub log_public_key: Ed25519PublicKey,
    /// API endpoint URL, if applicable.
    pub api_url: Option<String>,
}

/// Errors from transparency log operations.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    /// The log rejected the submitted entry.
    #[error("submission rejected: {reason}")]
    SubmissionRejected {
        /// Why the submission was rejected.
        reason: String,
    },

    /// Network or connection error reaching the log.
    #[error("network error: {0}")]
    NetworkError(String),

    /// Log returned HTTP 429; caller should wait and retry.
    #[error("rate limited, retry after {retry_after_secs}s")]
    RateLimited {
        /// Seconds to wait before retrying.
        retry_after_secs: u64,
    },

    /// Log returned an unparseable or unexpected response.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// Requested entry not found in the log.
    #[error("entry not found")]
    EntryNotFound,

    /// Consistency or inclusion proof verification failed.
    #[error("consistency violation: {0}")]
    ConsistencyViolation(String),

    /// Log is temporarily or permanently unavailable.
    #[error("log unavailable: {0}")]
    Unavailable(String),
}

impl auths_crypto::AuthsErrorInfo for LogError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::SubmissionRejected { .. } => "AUTHS-E9001",
            Self::NetworkError(_) => "AUTHS-E9002",
            Self::RateLimited { .. } => "AUTHS-E9003",
            Self::InvalidResponse(_) => "AUTHS-E9004",
            Self::EntryNotFound => "AUTHS-E9005",
            Self::ConsistencyViolation(_) => "AUTHS-E9006",
            Self::Unavailable(_) => "AUTHS-E9007",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::SubmissionRejected { .. } => {
                Some("Check the attestation format and payload size")
            }
            Self::NetworkError(_) => Some("Check your internet connection and the log's API URL"),
            Self::RateLimited { .. } => Some("Wait and retry; the log is rate-limiting requests"),
            Self::InvalidResponse(_) => {
                Some("The log returned an unexpected response; check the log version")
            }
            Self::EntryNotFound => Some("The entry may not be sequenced yet; retry after a moment"),
            Self::ConsistencyViolation(_) => {
                Some("The log returned data that does not match what was submitted")
            }
            Self::Unavailable(_) => {
                Some("The transparency log is unavailable; retry later or use --allow-unlogged")
            }
        }
    }
}

/// Pluggable transparency log backend.
///
/// Abstracts appending attestations to a transparency log and retrieving
/// Merkle proofs. Adapters translate backend-native formats (e.g., Rekor
/// hashedrekord) to canonical `auths-transparency` types at the boundary.
///
/// Usage:
/// ```ignore
/// let log: Arc<dyn TransparencyLog> = factory.create_log(&config)?;
/// let submission = log.submit(&attestation_bytes, &pk, &sig).await?;
/// ```
#[async_trait]
pub trait TransparencyLog: Send + Sync {
    /// Submit a leaf to the log and receive an inclusion proof.
    ///
    /// The adapter wraps `leaf_data` in whatever envelope the backend
    /// requires. `public_key` and `signature` are provided for backends
    /// that verify entry signatures on submission.
    ///
    /// Args:
    /// * `leaf_data` — Raw bytes to log (typically serialized attestation JSON).
    /// * `public_key` — Signer's public key (Ed25519 DER or P-256 SEC1).
    /// * `signature` — Signature over `leaf_data`.
    async fn submit(
        &self,
        leaf_data: &[u8],
        public_key: &[u8],
        signature: &[u8],
    ) -> Result<LogSubmission, LogError>;

    /// Fetch the log's current signed checkpoint.
    async fn get_checkpoint(&self) -> Result<SignedCheckpoint, LogError>;

    /// Fetch an inclusion proof for a leaf at `leaf_index` in a tree of `tree_size`.
    ///
    /// Args:
    /// * `leaf_index` — Zero-based index of the leaf.
    /// * `tree_size` — Tree size to prove inclusion against.
    async fn get_inclusion_proof(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> Result<InclusionProof, LogError>;

    /// Fetch a consistency proof between two tree sizes.
    ///
    /// Args:
    /// * `old_size` — Earlier tree size.
    /// * `new_size` — Later tree size.
    async fn get_consistency_proof(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProof, LogError>;

    /// Return static metadata about this log backend.
    fn metadata(&self) -> LogMetadata;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_error_display() {
        let err = LogError::SubmissionRejected {
            reason: "payload too large".into(),
        };
        assert_eq!(err.to_string(), "submission rejected: payload too large");

        let err = LogError::RateLimited {
            retry_after_secs: 30,
        };
        assert_eq!(err.to_string(), "rate limited, retry after 30s");

        let err = LogError::NetworkError("connection refused".into());
        assert_eq!(err.to_string(), "network error: connection refused");

        let err = LogError::Unavailable("service unavailable".into());
        assert_eq!(err.to_string(), "log unavailable: service unavailable");
    }

    #[test]
    fn log_error_codes() {
        use auths_crypto::AuthsErrorInfo;

        assert_eq!(
            LogError::SubmissionRejected {
                reason: String::new()
            }
            .error_code(),
            "AUTHS-E9001"
        );
        assert_eq!(
            LogError::NetworkError(String::new()).error_code(),
            "AUTHS-E9002"
        );
        assert_eq!(
            LogError::RateLimited {
                retry_after_secs: 0
            }
            .error_code(),
            "AUTHS-E9003"
        );
        assert_eq!(
            LogError::InvalidResponse(String::new()).error_code(),
            "AUTHS-E9004"
        );
        assert_eq!(LogError::EntryNotFound.error_code(), "AUTHS-E9005");
        assert_eq!(
            LogError::ConsistencyViolation(String::new()).error_code(),
            "AUTHS-E9006"
        );
        assert_eq!(
            LogError::Unavailable(String::new()).error_code(),
            "AUTHS-E9007"
        );
    }

    #[test]
    fn log_error_suggestions_not_none() {
        use auths_crypto::AuthsErrorInfo;

        let variants: Vec<LogError> = vec![
            LogError::SubmissionRejected {
                reason: String::new(),
            },
            LogError::NetworkError(String::new()),
            LogError::RateLimited {
                retry_after_secs: 0,
            },
            LogError::InvalidResponse(String::new()),
            LogError::EntryNotFound,
            LogError::ConsistencyViolation(String::new()),
            LogError::Unavailable(String::new()),
        ];
        for v in &variants {
            assert!(
                v.suggestion().is_some(),
                "missing suggestion for {}",
                v.error_code()
            );
        }
    }

    // Compile-time check: trait must be object-safe for Arc<dyn TransparencyLog>
    fn _assert_object_safe(_: std::sync::Arc<dyn TransparencyLog>) {}
}
