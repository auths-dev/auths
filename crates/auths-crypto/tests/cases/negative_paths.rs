//! Negative-path coverage for the curve-generic provider surface.
//!
//! Exercises rejection behaviour across both curves (P-256 default, Ed25519):
//! wrong-curve verification, truncated/extended/tampered signatures, tampered
//! payloads, and bad seed/key lengths at every public construction boundary.

use auths_crypto::{
    CryptoError, CurveType, TypedSeed, TypedSignerKey, default_provider, normalize_verkey,
    parse_ed25519_seed, parse_key_material, typed_public_key, typed_sign,
};

const MESSAGE: &[u8] = b"negative-path fixture message";

async fn generate(curve: CurveType) -> (TypedSeed, Vec<u8>) {
    default_provider()
        .generate_typed_keypair(curve)
        .await
        .unwrap()
}

async fn signed_fixture(curve: CurveType) -> (Vec<u8>, Vec<u8>) {
    let (seed, pubkey) = generate(curve).await;
    let sig = default_provider().sign_typed(&seed, MESSAGE).await.unwrap();
    (pubkey, sig)
}

// ---------------------------------------------------------------------------
// Wrong-curve verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ed25519_signature_rejected_against_p256_key_for_same_message() {
    let (_, ed_sig) = signed_fixture(CurveType::Ed25519).await;
    let (_, p256_pk) = generate(CurveType::P256).await;
    let result = default_provider()
        .verify_typed(CurveType::P256, &p256_pk, MESSAGE, &ed_sig)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn p256_signature_rejected_against_ed25519_key_for_same_message() {
    let (_, p256_sig) = signed_fixture(CurveType::P256).await;
    let (_, ed_pk) = generate(CurveType::Ed25519).await;
    let err = default_provider()
        .verify_typed(CurveType::Ed25519, &ed_pk, MESSAGE, &p256_sig)
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[tokio::test]
async fn ed25519_pubkey_rejected_by_p256_verifier() {
    let (ed_pk, ed_sig) = signed_fixture(CurveType::Ed25519).await;
    let result = default_provider()
        .verify_typed(CurveType::P256, &ed_pk, MESSAGE, &ed_sig)
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn p256_pubkey_rejected_by_ed25519_verifier_as_invalid_key_length() {
    let (p256_pk, p256_sig) = signed_fixture(CurveType::P256).await;
    let err = default_provider()
        .verify_typed(CurveType::Ed25519, &p256_pk, MESSAGE, &p256_sig)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 33
        }
    ));
}

// ---------------------------------------------------------------------------
// Truncated / extended / empty signatures
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ed25519_truncated_signature_rejected() {
    let (pk, mut sig) = signed_fixture(CurveType::Ed25519).await;
    sig.pop();
    let err = default_provider()
        .verify_ed25519(&pk, MESSAGE, &sig)
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[tokio::test]
async fn ed25519_extended_signature_rejected() {
    let (pk, mut sig) = signed_fixture(CurveType::Ed25519).await;
    sig.push(0x00);
    let err = default_provider()
        .verify_ed25519(&pk, MESSAGE, &sig)
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[tokio::test]
async fn ed25519_empty_signature_rejected() {
    let (pk, _) = signed_fixture(CurveType::Ed25519).await;
    let err = default_provider()
        .verify_ed25519(&pk, MESSAGE, &[])
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[tokio::test]
async fn p256_truncated_signature_rejected() {
    let (pk, mut sig) = signed_fixture(CurveType::P256).await;
    sig.pop();
    let err = default_provider()
        .verify_p256(&pk, MESSAGE, &sig)
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::OperationFailed(_)));
}

#[tokio::test]
async fn p256_extended_signature_rejected() {
    let (pk, mut sig) = signed_fixture(CurveType::P256).await;
    sig.push(0x00);
    let err = default_provider()
        .verify_p256(&pk, MESSAGE, &sig)
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::OperationFailed(_)));
}

#[tokio::test]
async fn p256_empty_signature_rejected() {
    let (pk, _) = signed_fixture(CurveType::P256).await;
    let err = default_provider()
        .verify_p256(&pk, MESSAGE, &[])
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::OperationFailed(_)));
}

// ---------------------------------------------------------------------------
// Tampered payload (single bit flip)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ed25519_tampered_message_bit_flip_rejected() {
    let (pk, sig) = signed_fixture(CurveType::Ed25519).await;
    let mut tampered = MESSAGE.to_vec();
    tampered[0] ^= 0x01;
    let err = default_provider()
        .verify_ed25519(&pk, &tampered, &sig)
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[tokio::test]
async fn p256_tampered_message_bit_flip_rejected() {
    let (pk, sig) = signed_fixture(CurveType::P256).await;
    let mut tampered = MESSAGE.to_vec();
    tampered[0] ^= 0x01;
    let err = default_provider()
        .verify_p256(&pk, &tampered, &sig)
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::InvalidSignature));
}

// ---------------------------------------------------------------------------
// Tampered signature (single bit flip)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ed25519_tampered_signature_bit_flip_rejected() {
    let (pk, mut sig) = signed_fixture(CurveType::Ed25519).await;
    sig[10] ^= 0x01;
    let err = default_provider()
        .verify_ed25519(&pk, MESSAGE, &sig)
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[tokio::test]
async fn p256_tampered_signature_bit_flip_rejected() {
    let (pk, mut sig) = signed_fixture(CurveType::P256).await;
    sig[10] ^= 0x01;
    let result = default_provider().verify_p256(&pk, MESSAGE, &sig).await;
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Bad public-key lengths at the verify boundary
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ed25519_verify_rejects_bad_pubkey_lengths() {
    for len in [0usize, 31, 33, 64] {
        let pk = vec![0u8; len];
        let err = default_provider()
            .verify_ed25519(&pk, MESSAGE, &[0u8; 64])
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                CryptoError::InvalidKeyLength {
                    expected: 32,
                    actual
                } if actual == len
            ),
            "expected InvalidKeyLength for {len}-byte pubkey, got {err:?}"
        );
    }
}

#[tokio::test]
async fn p256_verify_rejects_bad_pubkey_lengths() {
    for len in [0usize, 31, 32, 34, 64] {
        let pk = vec![0x02u8; len];
        let err = default_provider()
            .verify_p256(&pk, MESSAGE, &[0u8; 64])
            .await
            .unwrap_err();
        assert!(
            matches!(err, CryptoError::OperationFailed(_)),
            "expected OperationFailed for {len}-byte pubkey, got {err:?}"
        );
    }
}

#[tokio::test]
async fn p256_verify_rejects_pubkey_point_not_on_curve() {
    let mut pk = vec![0x02u8];
    pk.extend_from_slice(&[0xFF; 32]);
    let err = default_provider()
        .verify_p256(&pk, MESSAGE, &[0u8; 64])
        .await
        .unwrap_err();
    assert!(matches!(err, CryptoError::OperationFailed(_)));
}

// ---------------------------------------------------------------------------
// Bad seed / key lengths at construction boundaries
// ---------------------------------------------------------------------------

#[test]
fn parse_key_material_rejects_bad_lengths() {
    for len in [0usize, 31, 33, 64] {
        let err = parse_key_material(&vec![7u8; len]).unwrap_err();
        assert!(
            matches!(err, CryptoError::InvalidPrivateKey(_)),
            "expected InvalidPrivateKey for {len}-byte input, got {err:?}"
        );
    }
}

#[test]
fn parse_ed25519_seed_rejects_bad_lengths() {
    for len in [0usize, 31, 33, 64] {
        let err = parse_ed25519_seed(&vec![7u8; len]).unwrap_err();
        assert!(
            matches!(err, CryptoError::InvalidPrivateKey(_)),
            "expected InvalidPrivateKey for {len}-byte input, got {err:?}"
        );
    }
}

#[test]
fn typed_signer_key_from_parts_rejects_bad_pubkey_lengths_for_ed25519() {
    for len in [0usize, 31, 33, 64] {
        let err =
            TypedSignerKey::from_parts(TypedSeed::Ed25519([1u8; 32]), vec![0u8; len]).unwrap_err();
        assert!(
            matches!(err, CryptoError::InvalidPrivateKey(_)),
            "expected InvalidPrivateKey for {len}-byte pubkey, got {err:?}"
        );
    }
}

#[test]
fn typed_signer_key_from_parts_rejects_bad_pubkey_lengths_for_p256() {
    for len in [0usize, 32, 34, 64] {
        let err =
            TypedSignerKey::from_parts(TypedSeed::P256([1u8; 32]), vec![0u8; len]).unwrap_err();
        assert!(
            matches!(err, CryptoError::InvalidPrivateKey(_)),
            "expected InvalidPrivateKey for {len}-byte pubkey, got {err:?}"
        );
    }
}

#[test]
fn p256_sign_rejects_zero_scalar_seed() {
    let err = typed_sign(&TypedSeed::P256([0u8; 32]), MESSAGE).unwrap_err();
    assert!(matches!(err, CryptoError::InvalidPrivateKey(_)));
}

#[test]
fn p256_sign_rejects_overflow_scalar_seed() {
    let err = typed_sign(&TypedSeed::P256([0xFF; 32]), MESSAGE).unwrap_err();
    assert!(matches!(err, CryptoError::InvalidPrivateKey(_)));
}

#[test]
fn p256_public_key_derivation_rejects_zero_scalar_seed() {
    let err = typed_public_key(&TypedSeed::P256([0u8; 32])).unwrap_err();
    assert!(matches!(err, CryptoError::InvalidPrivateKey(_)));
}

// ---------------------------------------------------------------------------
// normalize_verkey rejection paths
// ---------------------------------------------------------------------------

#[test]
fn normalize_verkey_rejects_bad_ed25519_lengths() {
    for len in [0usize, 31, 33, 64] {
        let err = normalize_verkey(&vec![1u8; len], CurveType::Ed25519).unwrap_err();
        assert!(
            matches!(err, CryptoError::OperationFailed(_)),
            "expected OperationFailed for {len}-byte verkey, got {err:?}"
        );
    }
}

#[test]
fn normalize_verkey_rejects_bad_p256_lengths() {
    for len in [0usize, 31, 32, 34, 64] {
        let err = normalize_verkey(&vec![0x02u8; len], CurveType::P256).unwrap_err();
        assert!(
            matches!(err, CryptoError::OperationFailed(_)),
            "expected OperationFailed for {len}-byte verkey, got {err:?}"
        );
    }
}

#[test]
fn normalize_verkey_rejects_p256_point_not_on_curve() {
    let mut bytes = vec![0x02u8];
    bytes.extend_from_slice(&[0xFF; 32]);
    let err = normalize_verkey(&bytes, CurveType::P256).unwrap_err();
    assert!(matches!(err, CryptoError::OperationFailed(_)));
}
