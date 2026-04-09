//! SDK workflow for submitting attestations to a transparency log.
//!
//! This module provides [`submit_attestation_to_log`], the async workflow
//! that takes a signed attestation and submits it to whichever transparency
//! log backend is configured. The function does NOT retry on rate limits —
//! the caller (CLI) owns retry policy.

use auths_core::ports::transparency_log::{LogError, TransparencyLog};
use auths_transparency::checkpoint::SignedCheckpoint;
use auths_transparency::proof::InclusionProof;
use thiserror::Error;

/// Result of submitting an attestation to a transparency log.
///
/// Named `LogSubmissionBundle` to avoid collision with the existing
/// `OfflineBundle` type in `auths-transparency`.
///
/// Args:
/// * `log_id` — Stable log identifier for trust config lookup.
/// * `leaf_index` — Zero-based index of the logged leaf.
/// * `inclusion_proof` — Merkle inclusion proof.
/// * `signed_checkpoint` — Signed checkpoint at submission time.
///
/// Usage:
/// ```ignore
/// let bundle = submit_attestation_to_log(&json, &pk, &sig, &log).await?;
/// println!("Logged at index {} in {}", bundle.leaf_index, bundle.log_id);
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LogSubmissionBundle {
    /// Stable log identifier for trust config lookup.
    pub log_id: String,
    /// Zero-based leaf index in the log.
    pub leaf_index: u64,
    /// Merkle inclusion proof against the checkpoint.
    pub inclusion_proof: InclusionProof,
    /// Signed checkpoint at submission time.
    pub signed_checkpoint: SignedCheckpoint,
}

/// Errors from the log submission workflow.
#[derive(Debug, Error)]
pub enum LogSubmitError {
    /// The transparency log returned an error.
    #[error("log error: {0}")]
    LogError(#[from] LogError),

    /// Post-submission verification failed (GHSA-whqx-f9j3-ch6m countermeasure).
    #[error("post-submission verification failed: {0}")]
    VerificationFailed(String),
}

/// Submit an attestation to a transparency log and verify the response.
///
/// This function:
/// 1. Submits the attestation as a leaf to the log
/// 2. Verifies the returned inclusion proof against the checkpoint (GHSA-whqx-f9j3-ch6m)
/// 3. Returns the bundle for embedding in `.auths.json`
///
/// **Does NOT retry** on `LogError::RateLimited`. The caller owns retry policy.
///
/// Args:
/// * `attestation_json` — Serialized attestation JSON bytes.
/// * `public_key` — Signer's Ed25519 public key (raw 32 bytes or PKIX DER).
/// * `signature` — Ed25519 signature over the attestation.
/// * `log` — The transparency log backend to submit to.
///
/// Usage:
/// ```ignore
/// let bundle = submit_attestation_to_log(
///     attestation_json.as_bytes(),
///     &public_key_bytes,
///     &signature_bytes,
///     &log,
/// ).await?;
/// ```
pub async fn submit_attestation_to_log(
    attestation_json: &[u8],
    public_key: &[u8],
    signature: &[u8],
    log: &dyn TransparencyLog,
) -> Result<LogSubmissionBundle, LogSubmitError> {
    // 1. Submit to the log
    let submission = log.submit(attestation_json, public_key, signature).await?;

    // 2. Verify the inclusion proof against the checkpoint root
    //    (GHSA-whqx-f9j3-ch6m: verify the response matches what we submitted)
    let leaf_hash = auths_transparency::merkle::hash_leaf(attestation_json);
    if let Err(e) = submission.inclusion_proof.verify(&leaf_hash) {
        return Err(LogSubmitError::VerificationFailed(format!(
            "inclusion proof does not match submitted attestation: {e}"
        )));
    }

    // 3. Verify the proof root matches the checkpoint root
    if submission.inclusion_proof.root != submission.signed_checkpoint.checkpoint.root {
        return Err(LogSubmitError::VerificationFailed(
            "inclusion proof root does not match checkpoint root".into(),
        ));
    }

    // The inclusion proof verification in step 2 already confirms the leaf
    // data matches (H(0x00 || data)), closing the GHSA-whqx-f9j3-ch6m vector.

    let metadata = log.metadata();

    Ok(LogSubmissionBundle {
        log_id: metadata.log_id,
        leaf_index: submission.leaf_index,
        inclusion_proof: submission.inclusion_proof,
        signed_checkpoint: submission.signed_checkpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::fakes::FakeTransparencyLog;

    #[tokio::test]
    async fn submit_succeeds_with_fake() {
        let log = FakeTransparencyLog::succeeding();
        let result =
            submit_attestation_to_log(b"test attestation", b"public_key", b"signature", &log).await;

        assert!(result.is_ok());
        let bundle = result.unwrap();
        assert_eq!(bundle.log_id, "fake-test-log");
        assert_eq!(bundle.leaf_index, 0);
    }

    #[tokio::test]
    async fn submit_propagates_rate_limit() {
        let log = FakeTransparencyLog::rate_limited(30);
        let result = submit_attestation_to_log(b"test", b"pk", b"sig", &log).await;

        match result {
            Err(LogSubmitError::LogError(LogError::RateLimited { retry_after_secs })) => {
                assert_eq!(retry_after_secs, 30);
            }
            other => panic!("expected RateLimited, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn submit_propagates_network_error() {
        let log = FakeTransparencyLog::failing(LogError::NetworkError("connection refused".into()));
        let result = submit_attestation_to_log(b"test", b"pk", b"sig", &log).await;

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("connection refused")
        );
    }
}
