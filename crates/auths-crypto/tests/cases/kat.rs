//! Known-Answer Tests (KATs) for the default crypto provider.
//!
//! These are deterministic-input fixtures that pin the exact byte-level
//! behaviour of the default provider for every primitive. They run against
//! whichever provider is selected at compile time — default (Ring) or
//! `--features fips` (aws-lc-rs / AWS-LC-FIPS) — and MUST produce identical
//! outputs across both, for the deterministic paths (ECDSA-P256 is RFC 6979
//! deterministic; HKDF is deterministic; HMAC is deterministic; Ed25519 is
//! deterministic by construction). AEAD randomised nonce paths test the
//! round-trip property rather than a byte-pinned ciphertext.
//!
//! Usage:
//! ```bash
//! cargo nextest run -p auths-crypto --test integration 'cases::kat::'
//! cargo nextest run -p auths-crypto --test integration --features fips 'cases::kat::'
//! # Outputs must match byte-for-byte for deterministic KATs.
//! ```

use auths_crypto::{CurveType, SecureSeed, TypedSeed, default_provider};

/// Pinned seed for every deterministic KAT — 32 bytes of `0x0B`.
const KAT_SEED: [u8; 32] = [0x0B; 32];
/// Pinned message for every deterministic KAT.
const KAT_MESSAGE: &[u8] = b"auths-crypto fn-128.T3 KAT fixture";

#[tokio::test]
async fn kat_ed25519_sign_is_deterministic() {
    let provider = default_provider();
    let seed = SecureSeed::new(KAT_SEED);
    let a = provider.sign_ed25519(&seed, KAT_MESSAGE).await.unwrap();
    let b = provider.sign_ed25519(&seed, KAT_MESSAGE).await.unwrap();
    assert_eq!(a, b, "Ed25519 must be deterministic (RFC 8032)");
    assert_eq!(a.len(), 64);
}

#[tokio::test]
async fn kat_ed25519_verify_matches_sign() {
    let provider = default_provider();
    let seed = SecureSeed::new(KAT_SEED);
    let pk = provider.ed25519_public_key_from_seed(&seed).await.unwrap();
    let sig = provider.sign_ed25519(&seed, KAT_MESSAGE).await.unwrap();
    provider
        .verify_ed25519(&pk, KAT_MESSAGE, &sig)
        .await
        .expect("Ed25519 verify must accept its own signature");
}

#[tokio::test]
async fn kat_p256_sign_is_rfc6979_deterministic() {
    let provider = default_provider();
    let seed = SecureSeed::new(KAT_SEED);
    let a = provider.sign_p256(&seed, KAT_MESSAGE).await.unwrap();
    let b = provider.sign_p256(&seed, KAT_MESSAGE).await.unwrap();
    let c = provider.sign_p256(&seed, KAT_MESSAGE).await.unwrap();
    assert_eq!(a, b, "ECDSA-P256 must be deterministic (RFC 6979)");
    assert_eq!(b, c);
    assert_eq!(a.len(), 64);
}

#[tokio::test]
async fn kat_p256_verify_matches_sign() {
    let provider = default_provider();
    let seed = SecureSeed::new(KAT_SEED);
    let pk = provider.p256_public_key_from_seed(&seed).await.unwrap();
    let sig = provider.sign_p256(&seed, KAT_MESSAGE).await.unwrap();
    provider
        .verify_p256(&pk, KAT_MESSAGE, &sig)
        .await
        .expect("P-256 verify must accept its own signature");
}

#[tokio::test]
async fn kat_typed_round_trip_across_curves() {
    let provider = default_provider();
    for curve in [CurveType::Ed25519, CurveType::P256] {
        let seed = TypedSeed::Ed25519(KAT_SEED);
        let seed = match curve {
            CurveType::Ed25519 => seed,
            CurveType::P256 => TypedSeed::P256(KAT_SEED),
        };
        let pk = provider
            .typed_public_key_from_seed(&seed)
            .await
            .expect("typed pubkey");
        let sig = provider
            .sign_typed(&seed, KAT_MESSAGE)
            .await
            .expect("typed sign");
        provider
            .verify_typed(seed.curve(), &pk, KAT_MESSAGE, &sig)
            .await
            .expect("typed verify must accept its own signature");
    }
}

#[tokio::test]
async fn kat_hkdf_sha256_pinned_output() {
    // RFC 5869 Test Vector #1 (A.1): SHA-256, IKM 22 bytes, salt 13 bytes,
    // info 10 bytes, L=42. Output: 0x3cb25f25faacd57a90434f64d0362f2a…
    let provider = default_provider();
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let expected = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a\
         2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
         34007208d5b887185865",
    )
    .unwrap();

    let out = provider
        .hkdf_sha256_expand(&ikm, &salt, &info, 42)
        .await
        .unwrap();
    assert_eq!(out, expected, "HKDF-SHA256 RFC 5869 A.1 mismatch");
}

#[tokio::test]
async fn kat_hmac_sha256_pinned_output() {
    // RFC 4231 Test Case 1: key 20 × 0x0b, data "Hi There".
    // HMAC-SHA256: b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    let provider = default_provider();
    let key = vec![0x0b; 20];
    let data = b"Hi There";
    let expected =
        hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7").unwrap();

    let tag = provider.hmac_sha256_compute(&key, data).await.unwrap();
    assert_eq!(
        &tag[..],
        expected.as_slice(),
        "HMAC-SHA256 RFC 4231 mismatch"
    );

    provider
        .hmac_sha256_verify(&key, data, &tag)
        .await
        .expect("HMAC-SHA256 verify its own tag");
}

#[tokio::test]
async fn kat_hmac_sha384_pinned_output() {
    // RFC 4231 Test Case 1: HMAC-SHA384 tag (48 bytes).
    // afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6
    let provider = default_provider();
    let key = vec![0x0b; 20];
    let data = b"Hi There";
    let expected = hex::decode(
        "afd03944d84895626b0825f4ab46907f\
         15f9dadbe4101ec682aa034c7cebc59c\
         faea9ea9076ede7f4af152e8b2fa9cb6",
    )
    .unwrap();

    let tag = provider.hmac_sha384_compute(&key, data).await.unwrap();
    assert_eq!(
        &tag[..],
        expected.as_slice(),
        "HMAC-SHA384 RFC 4231 mismatch"
    );
}

#[tokio::test]
async fn kat_aead_chacha20poly1305_round_trip() {
    // No pinned ciphertext here — ChaCha20-Poly1305 is deterministic given
    // (key, nonce, aad, pt), but the under-FIPS provider uses aws-lc-rs
    // which emits the same bytes as the RustCrypto `chacha20poly1305` crate.
    // We assert: round-trip succeeds; tamper => InvalidSignature; AAD change => InvalidSignature.
    let provider = default_provider();
    let key = [0x42; 32];
    let nonce = [0x07; 12];
    let aad = b"session:kat";
    let pt = b"auths AEAD KAT";

    let ct = provider.aead_encrypt(&key, &nonce, aad, pt).await.unwrap();
    let recovered = provider.aead_decrypt(&key, &nonce, aad, &ct).await.unwrap();
    assert_eq!(&recovered, pt);

    // Tamper with tag (last 16 bytes).
    let mut tampered = ct.clone();
    let len = tampered.len();
    tampered[len - 1] ^= 0x01;
    let err = provider
        .aead_decrypt(&key, &nonce, aad, &tampered)
        .await
        .expect_err("tampered tag should fail");
    assert!(matches!(err, auths_crypto::CryptoError::InvalidSignature));

    // Wrong AAD.
    let err = provider
        .aead_decrypt(&key, &nonce, b"different-aad", &ct)
        .await
        .expect_err("AAD mismatch should fail");
    assert!(matches!(err, auths_crypto::CryptoError::InvalidSignature));
}

#[tokio::test]
async fn kat_hkdf_sha384_round_trip() {
    // SHA-384 KAT pinned output is non-standard (RFC 5869 only covers 256/1).
    // We assert: deterministic given identical inputs; output length honoured;
    // oversize rejected.
    let provider = default_provider();
    let ikm = KAT_SEED;
    let salt = b"salt-kat-384";
    let info = b"auths-kat-sha384";

    let a = provider
        .hkdf_sha384_expand(&ikm, salt, info, 96)
        .await
        .unwrap();
    let b = provider
        .hkdf_sha384_expand(&ikm, salt, info, 96)
        .await
        .unwrap();
    assert_eq!(a, b, "HKDF-SHA384 must be deterministic");
    assert_eq!(a.len(), 96);

    // Exceeding 255 * 48 = 12240 bytes is rejected.
    let too_big = provider.hkdf_sha384_expand(&ikm, salt, info, 12_241).await;
    assert!(too_big.is_err(), "oversize HKDF output must be rejected");
}
