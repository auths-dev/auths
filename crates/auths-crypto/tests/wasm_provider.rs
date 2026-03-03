#![cfg(target_arch = "wasm32")]

use auths_crypto::{CryptoError, CryptoProvider, WebCryptoProvider};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// RFC 8032 Section 7.1, Test Vector 2 (single-byte message 0x72)
const RFC8032_PUBKEY: [u8; 32] = [
    0x3d, 0x40, 0x17, 0xc3, 0xe8, 0x43, 0x89, 0x5a, 0x92, 0xb7, 0x0a, 0xa7, 0x4d, 0x1b, 0x7e, 0xbc,
    0x9c, 0x98, 0x2c, 0xcf, 0x2e, 0xc4, 0x96, 0x8c, 0xc0, 0xcd, 0x55, 0xf1, 0x2a, 0xf4, 0x66, 0x0c,
];

const RFC8032_MESSAGE: [u8; 1] = [0x72];

const RFC8032_SIGNATURE: [u8; 64] = [
    0x92, 0xa0, 0x09, 0xa9, 0xf0, 0xd4, 0xca, 0xb8, 0x72, 0x0e, 0x82, 0x0b, 0x5f, 0x64, 0x25, 0x40,
    0xa2, 0xb2, 0x7b, 0x54, 0x16, 0x50, 0x3f, 0x8f, 0xb3, 0x76, 0x22, 0x23, 0xeb, 0xdb, 0x69, 0xda,
    0x08, 0x5a, 0xc1, 0xe4, 0x3e, 0x15, 0x9c, 0x7e, 0x94, 0xe7, 0xc3, 0x65, 0x0c, 0x95, 0xb3, 0x9a,
    0x2d, 0xd9, 0xe4, 0x4b, 0x5b, 0xe7, 0xcc, 0x20, 0x5f, 0xd3, 0xc1, 0xb5, 0x7d, 0x52, 0xd3, 0xc1,
];

// A different valid public key (RFC 8032, Test Vector 1)
const RFC8032_OTHER_PUBKEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa3, 0xf4, 0xa1, 0x84, 0x46, 0xb0, 0xb8, 0xd1, 0x83, 0xf8, 0xe3,
];

#[wasm_bindgen_test]
async fn webcrypto_provider_verifies_valid_signature() {
    let provider = WebCryptoProvider;
    provider
        .verify_ed25519(&RFC8032_PUBKEY, &RFC8032_MESSAGE, &RFC8032_SIGNATURE)
        .await
        .unwrap();
}

#[wasm_bindgen_test]
async fn webcrypto_provider_rejects_invalid_signature() {
    let bad_sig = [0u8; 64];
    let provider = WebCryptoProvider;
    let result = provider
        .verify_ed25519(&RFC8032_PUBKEY, &RFC8032_MESSAGE, &bad_sig)
        .await;
    assert!(result.is_err());
}

#[wasm_bindgen_test]
async fn webcrypto_provider_rejects_wrong_pubkey() {
    let provider = WebCryptoProvider;
    let result = provider
        .verify_ed25519(&RFC8032_OTHER_PUBKEY, &RFC8032_MESSAGE, &RFC8032_SIGNATURE)
        .await;
    assert!(result.is_err());
}

#[wasm_bindgen_test]
async fn webcrypto_provider_rejects_invalid_key_length() {
    let short_key = [0u8; 16];
    let provider = WebCryptoProvider;
    let result = provider
        .verify_ed25519(&short_key, &RFC8032_MESSAGE, &[0u8; 64])
        .await;

    match result {
        Err(CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        }) => {}
        other => panic!("expected InvalidKeyLength, got {other:?}"),
    }
}

#[wasm_bindgen_test]
async fn webcrypto_provider_rejects_corrupted_signature() {
    let mut sig = RFC8032_SIGNATURE;
    sig[0] ^= 0xFF;

    let provider = WebCryptoProvider;
    let result = provider
        .verify_ed25519(&RFC8032_PUBKEY, &RFC8032_MESSAGE, &sig)
        .await;
    assert!(result.is_err());
}
