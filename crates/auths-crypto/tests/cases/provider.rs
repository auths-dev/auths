use auths_crypto::{CryptoProvider, RingCryptoProvider};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn test_keypair(seed: &[u8; 32]) -> (Ed25519KeyPair, [u8; 32]) {
    let kp = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
    let pk: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();
    (kp, pk)
}

#[tokio::test]
async fn ring_provider_verifies_valid_signature() {
    let (keypair, pubkey) = test_keypair(&[1u8; 32]);
    let message = b"hello world";
    let signature = <ring::signature::Ed25519KeyPair>::sign(&keypair, message);

    let provider = RingCryptoProvider;
    provider
        .verify_ed25519(&pubkey, message, signature.as_ref())
        .await
        .unwrap();
}

#[tokio::test]
async fn ring_provider_rejects_invalid_signature() {
    let (_, pubkey) = test_keypair(&[1u8; 32]);
    let message = b"hello world";
    let bad_sig = [0u8; 64];

    let provider = RingCryptoProvider;
    let result = provider.verify_ed25519(&pubkey, message, &bad_sig).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn ring_provider_rejects_wrong_pubkey() {
    let (keypair_a, _) = test_keypair(&[1u8; 32]);
    let (_, pubkey_b) = test_keypair(&[2u8; 32]);
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
    let (keypair, pubkey) = test_keypair(&[1u8; 32]);
    let message = b"hello world";
    let mut sig_bytes: Vec<u8> = <ring::signature::Ed25519KeyPair>::sign(&keypair, message)
        .as_ref()
        .to_vec();
    sig_bytes[0] ^= 0xFF;

    let provider = RingCryptoProvider;
    let result = provider.verify_ed25519(&pubkey, message, &sig_bytes).await;
    assert!(result.is_err());
}
