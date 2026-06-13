//! KERI pre-rotation commitment functions.
//!
//! Key commitment hashes for pre-rotation are computed here.
//! SAID computation lives in `said.rs`.

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
/// let commitment = compute_next_commitment(&KeriPublicKey::ed25519(&[0u8; 32]).unwrap());
/// assert_eq!(commitment.as_str().len(), 44);
/// assert!(commitment.as_str().starts_with('E'));
/// ```
pub fn compute_next_commitment(key: &KeriPublicKey) -> Said {
    // keripy: the next-key commitment is Diger(ser=verfer.qb64b) — the Blake3-256
    // digest of the CESR-qualified verkey *text*, itself CESR-encoded (`E…`). The
    // typed `key` carries the curve needed to produce that qualified form.
    #[allow(clippy::expect_used)] // INVARIANT: a valid KeriPublicKey always CESR-encodes
    let qb64 = key
        .to_qb64()
        .expect("a valid KeriPublicKey always CESR-encodes");
    let hash = blake3::hash(qb64.as_bytes());
    #[allow(clippy::expect_used)] // INVARIANT: a 32-byte Blake3 digest always CESR-encodes
    let said = crate::cesr_encode::encode_blake3_digest(hash.as_bytes())
        .expect("32-byte Blake3 digest always encodes");
    Said::new_unchecked(said)
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
/// let key = KeriPublicKey::ed25519(&[1u8; 32]).unwrap();
/// let c = compute_next_commitment(&key);
/// assert!(verify_commitment(&key, &c));
/// assert!(!verify_commitment(&KeriPublicKey::ed25519(&[2u8; 32]).unwrap(), &c));
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
        let key = KeriPublicKey::ed25519(&[1u8; 32]).unwrap();
        let commitment = compute_next_commitment(&key);
        assert!(verify_commitment(&key, &commitment));
        assert!(!verify_commitment(
            &KeriPublicKey::ed25519(&[2u8; 32]).unwrap(),
            &commitment
        ));
    }

    #[test]
    fn commitment_is_deterministic() {
        let key = KeriPublicKey::ed25519(&[42u8; 32]).unwrap();
        let c1 = compute_next_commitment(&key);
        let c2 = compute_next_commitment(&key);
        assert_eq!(c1, c2);
        assert!(c1.as_str().starts_with('E'));
    }

    #[test]
    fn commitment_has_correct_length() {
        let commitment = compute_next_commitment(&KeriPublicKey::ed25519(&[0u8; 32]).unwrap());
        // 'E' + 43 chars of base64url
        assert_eq!(commitment.as_str().len(), 44);
    }
}
