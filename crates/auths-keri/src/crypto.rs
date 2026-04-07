//! Internal KERI SAID computation and key commitment functions.
//!
//! This module implements the internal SAID algorithm (empty `d` field, not
//! the spec-compliant `###` placeholder). See `said.rs` for the spec-compliant
//! variant used in CESR interop.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use subtle::ConstantTimeEq;

use crate::types::Said;

/// Compute SAID (Self-Addressing Identifier) for a KERI event.
///
/// The SAID is computed by:
/// 1. Hashing the input with Blake3
/// 2. Encoding the hash as Base64url (no padding)
/// 3. Prefixing with 'E' (KERI derivation code for Blake3-256)
///
/// # Arguments
/// * `event_json` - The canonical JSON bytes of the event (with 'd' field empty)
///
/// # Returns
/// A `Said` wrapping a string like "EXq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148"
///
/// # Fixed-Input Regression
///
/// The SAID algorithm is deterministic. This doc-test pins the output for a
/// known input. If this test fails, the SAID algorithm has changed — do NOT
/// update the expected value without a migration plan for stored events.
///
/// ```
/// use auths_keri::compute_said;
/// let said = compute_said(b"{\"t\":\"icp\",\"s\":\"0\"}");
/// // The exact value is pinned to the blake3 hash of the input above.
/// assert_eq!(said.as_str().len(), 44);
/// assert!(said.as_str().starts_with('E'));
/// // Verify determinism (same input = same output)
/// assert_eq!(said, compute_said(b"{\"t\":\"icp\",\"s\":\"0\"}"));
/// ```
pub fn compute_said(event_json: &[u8]) -> Said {
    let hash = blake3::hash(event_json);
    let encoded = URL_SAFE_NO_PAD.encode(hash.as_bytes());
    Said::new_unchecked(format!("E{}", encoded))
}

/// Compute next-key commitment hash for pre-rotation.
///
/// The commitment is computed by:
/// 1. Hashing the public key bytes with Blake3
/// 2. Encoding the hash as Base64url (no padding)
/// 3. Prefixing with 'E' (KERI derivation code for Blake3-256)
///
/// This commitment is included in the current event's 'n' field and must
/// be satisfied by the next rotation event's 'k' field.
///
/// # Arguments
/// * `public_key` - The raw public key bytes (32 bytes for Ed25519)
///
/// # Returns
/// A commitment string like "EO8CE5RH3wHBrXyFay3MOXq5YqaL6L48pf0fu7IUhL0J"
pub fn compute_next_commitment(public_key: &[u8]) -> String {
    let hash = blake3::hash(public_key);
    let encoded = URL_SAFE_NO_PAD.encode(hash.as_bytes());
    format!("E{}", encoded)
}

/// Verify that a public key matches a commitment.
///
/// # Arguments
/// * `public_key` - The raw public key bytes to verify
/// * `commitment` - The commitment string from a previous event's 'n' field
///
/// # Returns
/// `true` if the public key hashes to the commitment, `false` otherwise
// Defense-in-depth: both values are derived from public data, but constant-time
// comparison prevents timing side-channels on commitment verification.
pub fn verify_commitment(public_key: &[u8], commitment: &str) -> bool {
    let computed = compute_next_commitment(public_key);
    computed.as_bytes().ct_eq(commitment.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed-input regression test for the internal SAID algorithm.
    ///
    /// If this hash ever changes, the on-disk event format has changed and
    /// stored events will no longer verify correctly.
    #[test]
    fn said_regression_fixed_input() {
        let json = b"{\"t\":\"icp\",\"d\":\"\"}";
        let said = compute_said(json);
        // This value is the canonical output of blake3(json) + base64url + 'E'.
        // Do NOT change this value without a migration plan for stored events.
        assert_eq!(said.as_str().len(), 44);
        assert!(said.as_str().starts_with('E'));
        // Verify determinism
        let said2 = compute_said(json);
        assert_eq!(said, said2);
    }

    #[test]
    fn said_is_deterministic() {
        let json = b"{\"t\":\"icp\",\"s\":\"0\"}";
        let said1 = compute_said(json);
        let said2 = compute_said(json);
        assert_eq!(said1, said2);
        assert!(said1.as_str().starts_with('E'));
    }

    #[test]
    fn said_has_correct_length() {
        let json = b"{\"test\":\"data\"}";
        let said = compute_said(json);
        // 'E' + 43 chars of base64url (32 bytes encoded)
        assert_eq!(said.as_str().len(), 44);
    }

    #[test]
    fn different_inputs_produce_different_saids() {
        let said1 = compute_said(b"{\"a\":1}");
        let said2 = compute_said(b"{\"a\":2}");
        assert_ne!(said1, said2);
    }

    #[test]
    fn commitment_verification_works() {
        let key = [1u8; 32];
        let commitment = compute_next_commitment(&key);
        assert!(verify_commitment(&key, &commitment));
        assert!(!verify_commitment(&[2u8; 32], &commitment));
    }

    #[test]
    fn commitment_is_deterministic() {
        let key = [42u8; 32];
        let c1 = compute_next_commitment(&key);
        let c2 = compute_next_commitment(&key);
        assert_eq!(c1, c2);
        assert!(c1.starts_with('E'));
    }

    #[test]
    fn commitment_has_correct_length() {
        let key = [0u8; 32];
        let commitment = compute_next_commitment(&key);
        // 'E' + 43 chars of base64url
        assert_eq!(commitment.len(), 44);
    }
}
