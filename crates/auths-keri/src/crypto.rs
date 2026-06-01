//! KERI pre-rotation commitment functions.
//!
//! Key commitment hashes for pre-rotation are computed here.
//! SAID computation lives in `said.rs`.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use subtle::ConstantTimeEq;

use crate::keys::KeriPublicKey;
use crate::types::Said;

/// Compute the next-key commitment digest for pre-rotation.
///
/// The commitment is the Blake3-256 digest of the next verkey, CESR-encoded with
/// the `E` derivation code. It goes in the current event's `n` field and must be
/// satisfied by the next rotation's `k`.
///
/// The key is typed (`KeriPublicKey`) so its curve travels with it — the curve is
/// required to encode the verkey, and a typed key makes a "key without a curve"
/// unrepresentable at the call site.
///
/// Args:
/// * `key` - The next public key (Ed25519 or P-256), carrying its curve.
///
/// Usage:
/// ```
/// use auths_keri::{compute_next_commitment, KeriPublicKey};
/// let commitment = compute_next_commitment(&KeriPublicKey::Ed25519([0u8; 32]));
/// assert_eq!(commitment.as_str().len(), 44);
/// assert!(commitment.as_str().starts_with('E'));
/// ```
pub fn compute_next_commitment(key: &KeriPublicKey) -> Said {
    // NOTE (CESR alignment, part 1/2): this still hashes the raw verkey bytes
    // (legacy scheme) so commitment values are unchanged while call sites migrate
    // to the typed key. Part 2 switches this to hash the cesride qb64 of `key`,
    // which needs no call-site changes precisely because the curve is now in hand.
    let hash = blake3::hash(key.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(hash.as_bytes());
    Said::new_unchecked(format!("E{}", encoded))
}

/// Verify that a public key satisfies a commitment.
///
/// Args:
/// * `key` - The next public key to check, carrying its curve.
/// * `commitment` - The commitment `Said` from a previous event's `n` field.
///
/// Usage:
/// ```
/// use auths_keri::{compute_next_commitment, verify_commitment, KeriPublicKey};
/// let key = KeriPublicKey::Ed25519([1u8; 32]);
/// let c = compute_next_commitment(&key);
/// assert!(verify_commitment(&key, &c));
/// assert!(!verify_commitment(&KeriPublicKey::Ed25519([2u8; 32]), &c));
/// ```
// Defense-in-depth: both values are derived from public data, but constant-time
// comparison prevents timing side-channels on commitment verification.
pub fn verify_commitment(key: &KeriPublicKey, commitment: &Said) -> bool {
    let computed = compute_next_commitment(key);
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
        let key = KeriPublicKey::Ed25519([1u8; 32]);
        let commitment = compute_next_commitment(&key);
        assert!(verify_commitment(&key, &commitment));
        assert!(!verify_commitment(
            &KeriPublicKey::Ed25519([2u8; 32]),
            &commitment
        ));
    }

    #[test]
    fn commitment_is_deterministic() {
        let key = KeriPublicKey::Ed25519([42u8; 32]);
        let c1 = compute_next_commitment(&key);
        let c2 = compute_next_commitment(&key);
        assert_eq!(c1, c2);
        assert!(c1.as_str().starts_with('E'));
    }

    #[test]
    fn commitment_has_correct_length() {
        let commitment = compute_next_commitment(&KeriPublicKey::Ed25519([0u8; 32]));
        // 'E' + 43 chars of base64url
        assert_eq!(commitment.as_str().len(), 44);
    }
}
