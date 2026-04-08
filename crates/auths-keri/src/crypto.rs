//! KERI pre-rotation commitment functions.
//!
//! Key commitment hashes for pre-rotation are computed here.
//! SAID computation lives in `said.rs`.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use subtle::ConstantTimeEq;

use crate::types::Said;

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
/// Args:
/// * `public_key` - The raw public key bytes (32 bytes for Ed25519)
///
/// Usage:
/// ```
/// use auths_keri::compute_next_commitment;
/// let commitment = compute_next_commitment(&[0u8; 32]);
/// assert_eq!(commitment.as_str().len(), 44);
/// assert!(commitment.as_str().starts_with('E'));
/// ```
pub fn compute_next_commitment(public_key: &[u8]) -> Said {
    let hash = blake3::hash(public_key);
    let encoded = URL_SAFE_NO_PAD.encode(hash.as_bytes());
    Said::new_unchecked(format!("E{}", encoded))
}

/// Verify that a public key matches a commitment.
///
/// Args:
/// * `public_key` - The raw public key bytes to verify
/// * `commitment` - The commitment `Said` from a previous event's 'n' field
///
/// Usage:
/// ```
/// use auths_keri::{compute_next_commitment, verify_commitment};
/// let key = [1u8; 32];
/// let c = compute_next_commitment(&key);
/// assert!(verify_commitment(&key, &c));
/// assert!(!verify_commitment(&[2u8; 32], &c));
/// ```
// Defense-in-depth: both values are derived from public data, but constant-time
// comparison prevents timing side-channels on commitment verification.
pub fn verify_commitment(public_key: &[u8], commitment: &Said) -> bool {
    let computed = compute_next_commitment(public_key);
    computed
        .as_str()
        .as_bytes()
        .ct_eq(commitment.as_str().as_bytes())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(c1.as_str().starts_with('E'));
    }

    #[test]
    fn commitment_has_correct_length() {
        let key = [0u8; 32];
        let commitment = compute_next_commitment(&key);
        // 'E' + 43 chars of base64url
        assert_eq!(commitment.as_str().len(), 44);
    }
}
