use auths_crypto::{CryptoProvider, RingCryptoProvider};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn create_test_keypair(seed: &[u8; 32]) -> (Ed25519KeyPair, [u8; 32]) {
    let keypair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
    let public_key: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();
    (keypair, public_key)
}

#[tokio::test]
async fn ring_provider_verifies_valid_signature() {
    let (keypair, pubkey) = create_test_keypair(&[1u8; 32]);
    let message = b"hello world";
    let signature = keypair.sign(message);

    let provider = RingCryptoProvider;
    provider
        .verify_ed25519(&pubkey, message, signature.as_ref())
        .await
        .unwrap();
}

#[tokio::test]
async fn ring_provider_rejects_invalid_signature() {
    let (_, pubkey) = create_test_keypair(&[1u8; 32]);
    let message = b"hello world";
    let bad_sig = [0u8; 64];

    let provider = RingCryptoProvider;
    let result = provider.verify_ed25519(&pubkey, message, &bad_sig).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn ring_provider_rejects_wrong_pubkey() {
    let (keypair_a, _) = create_test_keypair(&[1u8; 32]);
    let (_, pubkey_b) = create_test_keypair(&[2u8; 32]);
    let message = b"hello world";
    let signature = keypair_a.sign(message);

    let provider = RingCryptoProvider;
    let result = provider
        .verify_ed25519(&pubkey_b, message, signature.as_ref())
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn ring_provider_rejects_invalid_key_length() {
    let provider = RingCryptoProvider;
    let short_key = [0u8; 16];
    let result = provider
        .verify_ed25519(&short_key, b"msg", &[0u8; 64])
        .await;

    match result {
        Err(auths_crypto::CryptoError::InvalidKeyLength {
            expected: 32,
            actual: 16,
        }) => {}
        other => panic!("expected InvalidKeyLength, got {other:?}"),
    }
}

#[tokio::test]
async fn ring_provider_rejects_corrupted_signature() {
    let (keypair, pubkey) = create_test_keypair(&[1u8; 32]);
    let message = b"hello world";
    let mut sig_bytes: Vec<u8> = keypair.sign(message).as_ref().to_vec();
    sig_bytes[0] ^= 0xFF;

    let provider = RingCryptoProvider;
    let result = provider.verify_ed25519(&pubkey, message, &sig_bytes).await;
    assert!(result.is_err());
}
