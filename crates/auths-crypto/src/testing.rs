// allow during curve-agnostic refactor
#![allow(clippy::disallowed_methods)]

use std::sync::OnceLock;

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::{CurveType, TypedSignerKey, parse_key_material};

/// Every curve the workspace supports today. Iterate over this in
/// [`test_all_curves!`]-style parameterized tests so curve-agnostic APIs are
/// exercised on both branches.
pub const ALL_CURVES: &[CurveType] = &[CurveType::Ed25519, CurveType::P256];

/// Generate a fresh [`TypedSignerKey`] on the requested curve. Test-only;
/// uses ring / p256 directly. Both code paths route through
/// [`parse_key_material`] so the resulting signer is identical in shape to
/// what production code receives from PKCS8 ingestion.
pub fn generate_typed_signer(curve: CurveType) -> TypedSignerKey {
    match curve {
        CurveType::Ed25519 => {
            let rng = SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
            TypedSignerKey::from_pkcs8(pkcs8.as_ref()).unwrap()
        }
        CurveType::P256 => {
            use p256::ecdsa::SigningKey;
            use p256::elliptic_curve::rand_core::OsRng as P256Rng;
            use p256::pkcs8::EncodePrivateKey;

            let sk = SigningKey::random(&mut P256Rng);
            let pkcs8 = sk.to_pkcs8_der().unwrap();
            TypedSignerKey::from_pkcs8(pkcs8.as_bytes()).unwrap()
        }
    }
}

/// Generate a deterministic [`TypedSignerKey`] from a 32-byte seed on the
/// requested curve. Routes through [`parse_key_material`] so the resulting
/// signer is shaped identically to production-ingested keys.
pub fn typed_signer_from_seed(curve: CurveType, seed: &[u8; 32]) -> TypedSignerKey {
    match curve {
        CurveType::Ed25519 => {
            // parse_key_material accepts a raw 32-byte input as an Ed25519 seed.
            let parsed = parse_key_material(seed).unwrap();
            TypedSignerKey::from_parts(parsed.seed, parsed.public_key).unwrap()
        }
        CurveType::P256 => {
            use p256::ecdsa::SigningKey;
            use p256::pkcs8::EncodePrivateKey;
            let sk = SigningKey::from_slice(seed).unwrap();
            let pkcs8 = sk.to_pkcs8_der().unwrap();
            TypedSignerKey::from_pkcs8(pkcs8.as_bytes()).unwrap()
        }
    }
}

/// Run a test body once per supported curve. Generates a fresh `#[test]`
/// function whose body iterates through [`ALL_CURVES`].
///
/// Use it on any test that exercises a curve-agnostic API where the
/// Ed25519-only assertion would silently pass on P-256 too — those are the
/// "accidentally Ed25519-only path" cases this macro is designed to catch.
///
/// Usage:
/// ```ignore
/// use auths_crypto::testing::{ALL_CURVES, generate_typed_signer};
/// use auths_crypto::test_all_curves;
///
/// test_all_curves!(sign_then_verify_roundtrips, |curve| {
///     let signer = generate_typed_signer(curve);
///     let sig = signer.sign(b"msg").unwrap();
///     // ...curve-aware verify...
///     assert_eq!(signer.curve(), curve);
/// });
/// ```
#[macro_export]
macro_rules! test_all_curves {
    ($name:ident, |$curve:ident| $body:block) => {
        #[test]
        fn $name() {
            for &$curve in $crate::testing::ALL_CURVES {
                $body
            }
        }
    };
}

#[cfg(all(test, feature = "native", not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::key_ops::{public_key, sign};

    #[test]
    fn all_curves_lists_both_supported() {
        assert!(ALL_CURVES.contains(&CurveType::Ed25519));
        assert!(ALL_CURVES.contains(&CurveType::P256));
        assert_eq!(ALL_CURVES.len(), 2);
    }

    test_all_curves!(generate_typed_signer_returns_requested_curve, |curve| {
        let signer = generate_typed_signer(curve);
        assert_eq!(signer.curve(), curve);
        assert_eq!(signer.public_key().len(), curve.public_key_len());
    });

    test_all_curves!(typed_signer_from_seed_round_trips, |curve| {
        let seed = [0x42u8; 32];
        let signer = typed_signer_from_seed(curve, &seed);
        assert_eq!(signer.curve(), curve);
        let sig = signer.sign(b"deterministic test message").unwrap();
        assert_eq!(sig.len(), curve.signature_len());
    });

    test_all_curves!(typed_sign_dispatches_per_curve, |curve| {
        let signer = generate_typed_signer(curve);
        let sig = sign(signer.seed(), b"parameterized roundtrip").unwrap();
        assert_eq!(sig.len(), curve.signature_len());
    });

    test_all_curves!(public_key_derivation_matches_signer_pubkey, |curve| {
        let signer = generate_typed_signer(curve);
        let derived = public_key(signer.seed()).unwrap();
        assert_eq!(derived, signer.public_key());
    });

    test_all_curves!(cesr_pubkey_prefix_matches_curve, |curve| {
        let signer = generate_typed_signer(curve);
        let cesr = signer.cesr_encoded_pubkey();
        match curve {
            CurveType::Ed25519 => assert!(cesr.starts_with('D')),
            CurveType::P256 => assert!(cesr.starts_with("1AAI")),
        }
    });
}

/// Returns a shared, lazily initialized PKCS8-encoded Ed25519 keypair.
///
/// The keypair is generated once on first call and reused for all subsequent
/// calls within the same test binary. This eliminates the cost of repeated
/// key generation across tests.
///
/// Args:
/// * None
///
/// Usage:
/// ```ignore
/// let pkcs8_bytes = get_shared_keypair();
/// let keypair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes).unwrap();
/// ```
pub fn get_shared_keypair() -> &'static [u8] {
    static KEYPAIR: OnceLock<Vec<u8>> = OnceLock::new();

    KEYPAIR.get_or_init(|| {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        pkcs8.as_ref().to_vec()
    })
}

/// Creates a deterministic Ed25519 keypair from a 32-byte seed.
///
/// Useful when tests need multiple distinct keypairs with reproducible output.
/// Returns both the `Ed25519KeyPair` (ring) and the raw 32-byte public key.
///
/// Args:
/// * `seed`: A 32-byte array used as the private key seed.
///
/// Usage:
/// ```ignore
/// let (keypair, public_key) = create_test_keypair(&[1u8; 32]);
/// ```
pub fn create_test_keypair(seed: &[u8; 32]) -> (Ed25519KeyPair, [u8; 32]) {
    let keypair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
    let public_key: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();
    (keypair, public_key)
}

/// Generates a fresh random Ed25519 keypair.
///
/// Convenience wrapper for tests that need a unique keypair but don't care
/// about reproducibility.
///
/// Args:
/// * None
///
/// Usage:
/// ```ignore
/// let keypair = gen_keypair();
/// ```
pub fn gen_keypair() -> Ed25519KeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}
