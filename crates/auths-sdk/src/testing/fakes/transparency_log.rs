//! Fake transparency log for testing SDK workflows.
//!
//! Maintains an in-memory Merkle tree using the same functions
//! the verifier uses (`auths_transparency::merkle`).

use async_trait::async_trait;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::sync::Mutex;

use auths_core::ports::transparency_log::{LogError, LogMetadata, LogSubmission, TransparencyLog};
use auths_transparency::checkpoint::{Checkpoint, SignedCheckpoint};
use auths_transparency::merkle::{compute_root, hash_leaf};
use auths_transparency::proof::{ConsistencyProof, InclusionProof};
use auths_transparency::types::{LogOrigin, MerkleHash};
use auths_verifier::{Ed25519PublicKey, Ed25519Signature};

/// Deterministic test seed for the fake log's signing key.
const FAKE_LOG_SEED: [u8; 32] = [42u8; 32];

/// A recorded call to the fake transparency log.
#[derive(Debug, Clone)]
pub enum FakeLogCall {
    /// A `submit()` call with the leaf data length.
    Submit {
        /// Length of the submitted leaf data in bytes.
        leaf_data_len: usize,
    },
    /// A `get_checkpoint()` call.
    GetCheckpoint,
    /// A `get_inclusion_proof()` call.
    GetInclusionProof {
        /// Requested leaf index.
        leaf_index: u64,
        /// Requested tree size.
        tree_size: u64,
    },
}

/// Internal state of the fake log.
struct FakeLogState {
    /// All leaf hashes in insertion order.
    leaves: Vec<MerkleHash>,
    /// Recorded calls for assertions.
    calls: Vec<FakeLogCall>,
}

/// Configurable fake transparency log for testing.
///
/// Uses `auths_transparency::merkle::compute_root` and `hash_leaf` —
/// the same functions the verifier uses. Not a parallel implementation.
pub struct FakeTransparencyLog {
    state: Mutex<FakeLogState>,
    keypair: Ed25519KeyPair,
    public_key: [u8; 32],
    /// If set, all trait methods return this error instead of succeeding.
    forced_error: Option<LogError>,
}

impl FakeTransparencyLog {
    /// Create a fake that succeeds and builds real Merkle proofs.
    pub fn succeeding() -> Self {
        #[allow(clippy::expect_used)] // INVARIANT: fixed test seed is always valid
        let keypair =
            Ed25519KeyPair::from_seed_unchecked(&FAKE_LOG_SEED).expect("valid Ed25519 seed");
        #[allow(clippy::expect_used)] // INVARIANT: Ed25519 public key is always 32 bytes
        let public_key: [u8; 32] = keypair
            .public_key()
            .as_ref()
            .try_into()
            .expect("Ed25519 public key is 32 bytes");

        Self {
            state: Mutex::new(FakeLogState {
                leaves: Vec::new(),
                calls: Vec::new(),
            }),
            keypair,
            public_key,
            forced_error: None,
        }
    }

    /// Create a fake that always returns the given error.
    pub fn failing(error: LogError) -> Self {
        let mut fake = Self::succeeding();
        fake.forced_error = Some(error);
        fake
    }

    /// Create a fake that returns `RateLimited`.
    pub fn rate_limited(secs: u64) -> Self {
        Self::failing(LogError::RateLimited {
            retry_after_secs: secs,
        })
    }

    /// Get recorded calls for assertions.
    pub fn calls(&self) -> Vec<FakeLogCall> {
        #[allow(clippy::expect_used)] // INVARIANT: test code only
        self.state.lock().expect("lock").calls.clone()
    }

    /// Build a `TrustRoot` matching this fake's signing key.
    pub fn trust_root(&self) -> auths_transparency::TrustRoot {
        auths_transparency::TrustRoot {
            log_public_key: Ed25519PublicKey::from_bytes(self.public_key),
            log_origin: LogOrigin::new_unchecked("fake.test/log"),
            witnesses: vec![],
            signature_algorithm: auths_verifier::SignatureAlgorithm::Ed25519,
        }
    }

    fn check_forced_error(&self) -> Result<(), LogError> {
        if let Some(ref err) = self.forced_error {
            // Clone the error for return
            Err(match err {
                LogError::SubmissionRejected { reason } => LogError::SubmissionRejected {
                    reason: reason.clone(),
                },
                LogError::NetworkError(s) => LogError::NetworkError(s.clone()),
                LogError::RateLimited { retry_after_secs } => LogError::RateLimited {
                    retry_after_secs: *retry_after_secs,
                },
                LogError::InvalidResponse(s) => LogError::InvalidResponse(s.clone()),
                LogError::EntryNotFound => LogError::EntryNotFound,
                LogError::ConsistencyViolation(s) => LogError::ConsistencyViolation(s.clone()),
                LogError::Unavailable(s) => LogError::Unavailable(s.clone()),
            })
        } else {
            Ok(())
        }
    }

    /// Build the signed checkpoint for the current tree state.
    fn sign_checkpoint(&self, leaves: &[MerkleHash]) -> SignedCheckpoint {
        let root = if leaves.is_empty() {
            MerkleHash::from_bytes([0u8; 32])
        } else {
            compute_root(leaves)
        };

        let checkpoint = Checkpoint {
            origin: LogOrigin::new_unchecked("fake.test/log"),
            size: leaves.len() as u64,
            root,
            #[allow(clippy::expect_used)] // INVARIANT: hardcoded test timestamp is valid
            timestamp: chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .expect("valid timestamp")
                .with_timezone(&chrono::Utc),
        };

        let note_body = checkpoint.to_note_body();
        let sig_bytes = self.keypair.sign(note_body.as_bytes());
        #[allow(clippy::expect_used)] // INVARIANT: Ed25519 signature is always 64 bytes
        let log_signature =
            Ed25519Signature::try_from_slice(sig_bytes.as_ref()).expect("64-byte sig");

        SignedCheckpoint {
            checkpoint,
            log_signature,
            log_public_key: Ed25519PublicKey::from_bytes(self.public_key),
            witnesses: vec![],
            ecdsa_checkpoint_signature: None,
            ecdsa_checkpoint_key: None,
        }
    }

    /// Compute an inclusion proof for leaf at `index` in a tree of `leaves`.
    fn compute_inclusion_proof(leaves: &[MerkleHash], index: u64) -> InclusionProof {
        let size = leaves.len() as u64;
        let root = compute_root(leaves);

        // For a simple implementation: walk up the tree collecting siblings
        let hashes = Self::merkle_path(leaves, index as usize);

        InclusionProof {
            index,
            size,
            root,
            hashes,
        }
    }

    /// Compute the Merkle sibling path for the leaf at `index`.
    fn merkle_path(leaves: &[MerkleHash], index: usize) -> Vec<MerkleHash> {
        if leaves.len() <= 1 {
            return vec![];
        }

        let k = largest_power_of_2_less_than(leaves.len());
        if index < k {
            let mut path = Self::merkle_path(&leaves[..k], index);
            path.push(compute_root(&leaves[k..]));
            path
        } else {
            let mut path = Self::merkle_path(&leaves[k..], index - k);
            path.push(compute_root(&leaves[..k]));
            path
        }
    }
}

fn largest_power_of_2_less_than(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

#[async_trait]
impl TransparencyLog for FakeTransparencyLog {
    async fn submit(
        &self,
        leaf_data: &[u8],
        _public_key: &[u8],
        _curve: auths_crypto::CurveType,
        _signature: &[u8],
    ) -> Result<LogSubmission, LogError> {
        self.check_forced_error()?;

        #[allow(clippy::expect_used)] // INVARIANT: test code
        let mut state = self.state.lock().expect("lock");
        state.calls.push(FakeLogCall::Submit {
            leaf_data_len: leaf_data.len(),
        });

        let leaf_hash = hash_leaf(leaf_data);
        state.leaves.push(leaf_hash);

        let leaf_index = (state.leaves.len() - 1) as u64;
        let inclusion_proof = Self::compute_inclusion_proof(&state.leaves, leaf_index);
        let signed_checkpoint = self.sign_checkpoint(&state.leaves);

        Ok(LogSubmission {
            leaf_index,
            inclusion_proof,
            signed_checkpoint,
        })
    }

    async fn get_checkpoint(&self) -> Result<SignedCheckpoint, LogError> {
        self.check_forced_error()?;

        #[allow(clippy::expect_used)]
        let mut state = self.state.lock().expect("lock");
        state.calls.push(FakeLogCall::GetCheckpoint);
        Ok(self.sign_checkpoint(&state.leaves))
    }

    async fn get_inclusion_proof(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> Result<InclusionProof, LogError> {
        self.check_forced_error()?;

        #[allow(clippy::expect_used)]
        let mut state = self.state.lock().expect("lock");
        state.calls.push(FakeLogCall::GetInclusionProof {
            leaf_index,
            tree_size,
        });

        if leaf_index >= state.leaves.len() as u64 {
            return Err(LogError::EntryNotFound);
        }
        let end = std::cmp::min(tree_size as usize, state.leaves.len());
        Ok(Self::compute_inclusion_proof(
            &state.leaves[..end],
            leaf_index,
        ))
    }

    async fn get_consistency_proof(
        &self,
        _old_size: u64,
        _new_size: u64,
    ) -> Result<ConsistencyProof, LogError> {
        self.check_forced_error()?;

        // Simplified: return empty proof (tests that need real consistency
        // proofs should use the full Merkle math directly)
        Ok(ConsistencyProof {
            old_size: _old_size,
            new_size: _new_size,
            old_root: MerkleHash::from_bytes([0u8; 32]),
            new_root: MerkleHash::from_bytes([0u8; 32]),
            hashes: vec![],
        })
    }

    fn metadata(&self) -> LogMetadata {
        LogMetadata {
            log_id: "fake-test-log".to_string(),
            log_origin: LogOrigin::new_unchecked("fake.test/log"),
            log_public_key: Ed25519PublicKey::from_bytes(self.public_key),
            api_url: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn succeeding_submit_returns_valid_proof() {
        let log = FakeTransparencyLog::succeeding();
        let result = log
            .submit(b"hello", b"pk", auths_crypto::CurveType::default(), b"sig")
            .await;
        assert!(result.is_ok());
        let submission = result.unwrap();
        assert_eq!(submission.leaf_index, 0);

        // Verify the inclusion proof using the same Merkle math
        let leaf_hash = hash_leaf(b"hello");
        assert!(submission.inclusion_proof.verify(&leaf_hash).is_ok());
    }

    #[tokio::test]
    async fn succeeding_multiple_submits() {
        let log = FakeTransparencyLog::succeeding();

        let s1 = log
            .submit(b"a", b"pk", auths_crypto::CurveType::default(), b"sig")
            .await
            .unwrap();
        let s2 = log
            .submit(b"b", b"pk", auths_crypto::CurveType::default(), b"sig")
            .await
            .unwrap();
        let s3 = log
            .submit(b"c", b"pk", auths_crypto::CurveType::default(), b"sig")
            .await
            .unwrap();

        assert_eq!(s1.leaf_index, 0);
        assert_eq!(s2.leaf_index, 1);
        assert_eq!(s3.leaf_index, 2);

        // Each proof should verify
        assert!(s1.inclusion_proof.verify(&hash_leaf(b"a")).is_ok());
        assert!(s2.inclusion_proof.verify(&hash_leaf(b"b")).is_ok());
        assert!(s3.inclusion_proof.verify(&hash_leaf(b"c")).is_ok());
    }

    #[tokio::test]
    async fn failing_returns_configured_error() {
        let log = FakeTransparencyLog::failing(LogError::NetworkError("test error".into()));
        let result = log
            .submit(b"hello", b"pk", auths_crypto::CurveType::default(), b"sig")
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("test error"));
    }

    #[tokio::test]
    async fn rate_limited_returns_retry_after() {
        let log = FakeTransparencyLog::rate_limited(30);
        let result = log
            .submit(b"hello", b"pk", auths_crypto::CurveType::default(), b"sig")
            .await;
        match result {
            Err(LogError::RateLimited { retry_after_secs }) => {
                assert_eq!(retry_after_secs, 30);
            }
            other => panic!("expected RateLimited, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn calls_are_recorded() {
        let log = FakeTransparencyLog::succeeding();
        log.submit(b"a", b"pk", auths_crypto::CurveType::default(), b"sig")
            .await
            .unwrap();
        log.get_checkpoint().await.unwrap();

        let calls = log.calls();
        assert_eq!(calls.len(), 2);
        assert!(matches!(calls[0], FakeLogCall::Submit { .. }));
        assert!(matches!(calls[1], FakeLogCall::GetCheckpoint));
    }

    #[tokio::test]
    async fn trust_root_matches_checkpoint_signature() {
        let log = FakeTransparencyLog::succeeding();
        let submission = log
            .submit(b"test", b"pk", auths_crypto::CurveType::default(), b"sig")
            .await
            .unwrap();
        let trust_root = log.trust_root();

        // The checkpoint should verify against the trust root
        let note_body = submission.signed_checkpoint.checkpoint.to_note_body();
        let peer_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            trust_root.log_public_key.as_bytes(),
        );
        assert!(
            peer_key
                .verify(
                    note_body.as_bytes(),
                    submission.signed_checkpoint.log_signature.as_bytes()
                )
                .is_ok()
        );
    }
}
