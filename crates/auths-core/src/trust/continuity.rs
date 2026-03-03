//! KEL continuity checking trait for key rotation verification.
//!
//! This module defines the trait that `auths-id` implements to verify
//! rotation continuity without `auths-core` depending on `auths-id`.

/// Proof that a key rotation is valid from a known state to a new state.
///
/// Returned by implementors of [`KelContinuityChecker`]. The trust module
/// consumes this without knowing anything about KEL internals.
#[derive(Debug, Clone)]
pub struct RotationProof {
    /// The new public key bytes (raw Ed25519, 32 bytes).
    pub new_public_key: Vec<u8>,

    /// The new KEL tip SAID after the rotation chain.
    pub new_kel_tip: String,

    /// The new sequence number.
    pub new_sequence: u64,
}

/// Trait for verifying rotation continuity from a pinned state to a presented key.
///
/// Implemented by `auths-id` (which owns KEL types). The trust module in
/// `auths-core` calls this trait without importing `auths-id`.
///
/// # Implementation Requirements
///
/// The implementation must:
/// 1. Locate the event with SAID == `pinned_tip_said` in the KEL.
/// 2. Replay **forward from that event** (not from inception), verifying:
///    - Hash chain linkage (each event's `p` matches predecessor's `d`).
///    - Sequence ordering (strict monotonic increment).
///    - Pre-rotation commitment satisfaction for rotation events.
///    - Event signatures.
/// 3. Confirm the resulting key state's current key matches `presented_pk`.
///
/// # Return Values
///
/// - `Ok(Some(proof))` if continuity is verified.
/// - `Ok(None)` if the pinned tip is not found or the chain doesn't lead to the presented key.
/// - `Err` on internal errors (corrupt KEL, deserialization failure).
pub trait KelContinuityChecker {
    /// Verify that there is a valid, unbroken event chain from `pinned_tip_said`
    /// to a state whose current key matches `presented_pk`.
    ///
    /// # Arguments
    ///
    /// * `did` - The DID being verified (e.g., "did:keri:EXq5...")
    /// * `pinned_tip_said` - The SAID of the event at which we last pinned this identity
    /// * `presented_pk` - The raw public key bytes presented for verification
    ///
    /// # Returns
    ///
    /// * `Ok(Some(proof))` - Rotation verified, contains new state to update pin
    /// * `Ok(None)` - Cannot verify continuity (tip not found, chain broken, key mismatch)
    /// * `Err(...)` - Internal error (corrupt data, I/O failure)
    fn verify_rotation_continuity(
        &self,
        did: &str,
        pinned_tip_said: &str,
        presented_pk: &[u8],
    ) -> Result<Option<RotationProof>, crate::error::TrustError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock implementation for testing
    struct MockChecker {
        should_verify: bool,
        proof: Option<RotationProof>,
    }

    impl KelContinuityChecker for MockChecker {
        fn verify_rotation_continuity(
            &self,
            _did: &str,
            _pinned_tip_said: &str,
            _presented_pk: &[u8],
        ) -> Result<Option<RotationProof>, crate::error::TrustError> {
            if self.should_verify {
                Ok(self.proof.clone())
            } else {
                Ok(None)
            }
        }
    }

    #[test]
    fn test_rotation_proof_fields() {
        let proof = RotationProof {
            new_public_key: vec![1, 2, 3, 4],
            new_kel_tip: "ENewTipSaid".to_string(),
            new_sequence: 5,
        };

        assert_eq!(proof.new_public_key, vec![1, 2, 3, 4]);
        assert_eq!(proof.new_kel_tip, "ENewTipSaid");
        assert_eq!(proof.new_sequence, 5);
    }

    #[test]
    fn test_mock_checker_verifies() {
        let proof = RotationProof {
            new_public_key: vec![5, 6, 7, 8],
            new_kel_tip: "ENewTip".to_string(),
            new_sequence: 2,
        };

        let checker = MockChecker {
            should_verify: true,
            proof: Some(proof.clone()),
        };

        let result = checker
            .verify_rotation_continuity("did:keri:ETest", "EOldTip", &[1, 2, 3])
            .unwrap();

        assert!(result.is_some());
        let returned_proof = result.unwrap();
        assert_eq!(returned_proof.new_sequence, 2);
    }

    #[test]
    fn test_mock_checker_fails() {
        let checker = MockChecker {
            should_verify: false,
            proof: None,
        };

        let result = checker
            .verify_rotation_continuity("did:keri:ETest", "EOldTip", &[1, 2, 3])
            .unwrap();

        assert!(result.is_none());
    }
}
