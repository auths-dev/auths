// INVARIANT: sanctioned FIPS-validated crypto boundary. Like `ring_provider`,
// this is the one place aws-lc-rs is allowed to live; domain code must route
// through the CryptoProvider trait.
#![allow(clippy::disallowed_methods)]

//! FIPS 140-3 validated provider backed by `aws-lc-rs` (AWS-LC-FIPS).
//!
//! Selected at compile time when `--features fips` is active. Mutually
//! exclusive with `cnsa` and with `wasm32` targets (see `compile_error!`
//! guards at `crate::provider`). API-compatible with [`ring`]; we mirror
//! [`crate::ring_provider::RingCryptoProvider`] nearly line-for-line so the
//! swap is purely a build-feature flip.
//!
//! Usage:
//! ```ignore
//! use auths_crypto::{CryptoProvider, AwsLcProvider};
//! let provider = AwsLcProvider;
//! let sig = provider.sign_ed25519(&seed, b"msg").await?;
//! ```

use async_trait::async_trait;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

use crate::provider::{CryptoError, CryptoProvider, ED25519_PUBLIC_KEY_LEN, SecureSeed};

/// FIPS 140-3 validated provider. Use via [`crate::default_provider()`] when
/// the workspace is built with `--features fips`.
pub struct AwsLcProvider;

impl AwsLcProvider {
    /// Generate a P-256 keypair via aws-lc-rs. Returns `(scalar_seed, compressed_pubkey)`.
    pub fn p256_generate() -> Result<(SecureSeed, Vec<u8>), CryptoError> {
        // We still use RustCrypto's `p256` crate for keygen / SEC1 compressed
        // encoding because aws-lc-rs's ECDSA signing works from PKCS8 rather
        // than a raw 32-byte scalar. Under `fips` the validated module is
        // the aws-lc-rs path; keygen stays on p256 for byte-level parity
        // with existing KELs. Swap to aws-lc-rs keygen once downstream code
        // no longer assumes 32-byte scalar seed extraction.
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
        let compressed = verifying_key.to_encoded_point(true);
        let pubkey_bytes = compressed.as_bytes().to_vec();
        let scalar_bytes = signing_key.to_bytes();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&scalar_bytes);
        Ok((SecureSeed::new(seed), pubkey_bytes))
    }

    /// Sign with P-256 via aws-lc-rs (FIPS-validated). Returns 64-byte r||s.
    pub fn p256_sign(seed: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
        use p256::pkcs8::EncodePrivateKey;

        // aws-lc-rs's ECDSA signer consumes PKCS8 DER. Convert the raw scalar
        // first via the p256 crate (pure-Rust; not FIPS). The subsequent
        // signing is FIPS-validated.
        let sk = p256::ecdsa::SigningKey::from_slice(seed)
            .map_err(|e| CryptoError::InvalidPrivateKey(format!("P-256 scalar: {e}")))?;
        let pkcs8 = sk
            .to_pkcs8_der()
            .map_err(|e| CryptoError::OperationFailed(format!("P-256 PKCS8: {e}")))?;

        let rng = SystemRandom::new();
        let keypair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_bytes())
            .map_err(|e| CryptoError::InvalidPrivateKey(format!("aws-lc-rs P-256: {e}")))?;
        let sig = keypair
            .sign(&rng, message)
            .map_err(|e| CryptoError::OperationFailed(format!("aws-lc-rs P-256 sign: {e}")))?;
        Ok(sig.as_ref().to_vec())
    }

    /// Derive compressed P-256 pubkey from scalar. Uses p256 (same as
    /// [`Self::p256_generate`]); aws-lc-rs does not expose a FIPS-validated
    /// seed-to-pubkey derivation path.
    pub fn p256_public_key_from_seed(seed: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        use p256::ecdsa::SigningKey;
        let sk = SigningKey::from_slice(seed)
            .map_err(|e| CryptoError::InvalidPrivateKey(format!("P-256: {e}")))?;
        let vk = p256::ecdsa::VerifyingKey::from(&sk);
        let compressed = vk.to_encoded_point(true);
        Ok(compressed.as_bytes().to_vec())
    }

    /// Verify P-256 via aws-lc-rs (FIPS-validated). Accepts 33-byte compressed
    /// or 65-byte uncompressed SEC1.
    pub fn p256_verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        use aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED;

        // aws-lc-rs's fixed-format verify expects uncompressed (65 bytes).
        // Decompress via p256 if we got the 33-byte form.
        let uncompressed: Vec<u8>;
        let pubkey_bytes: &[u8] = match pubkey.len() {
            65 => pubkey,
            33 => {
                use p256::ecdsa::VerifyingKey;
                let vk = VerifyingKey::from_sec1_bytes(pubkey)
                    .map_err(|e| CryptoError::OperationFailed(format!("P-256 decompress: {e}")))?;
                uncompressed = vk.to_encoded_point(false).as_bytes().to_vec();
                uncompressed.as_slice()
            }
            other => {
                return Err(CryptoError::InvalidKeyLength {
                    expected: crate::provider::P256_PUBLIC_KEY_LEN,
                    actual: other,
                });
            }
        };

        let peer = UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, pubkey_bytes);
        peer.verify(message, signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Sign with Ed25519 via aws-lc-rs (FIPS-validated). 64-byte signature.
    pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let kp = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|e| CryptoError::InvalidPrivateKey(format!("Ed25519: {e}")))?;
        Ok(kp.sign(message).as_ref().to_vec())
    }

    /// Derive 32-byte Ed25519 public key from seed, synchronously.
    pub fn ed25519_public_key(seed: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        let kp = Ed25519KeyPair::from_seed_unchecked(seed)
            .map_err(|e| CryptoError::OperationFailed(format!("Ed25519 pubkey: {e}")))?;
        kp.public_key()
            .as_ref()
            .try_into()
            .map_err(|_| CryptoError::OperationFailed("Ed25519 public key not 32 bytes".into()))
    }

    /// Verify an Ed25519 signature via aws-lc-rs.
    pub fn ed25519_verify(
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let pk = UnparsedPublicKey::new(&ED25519, pubkey);
        pk.verify(message, signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

#[async_trait]
impl CryptoProvider for AwsLcProvider {
    async fn verify_ed25519(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if pubkey.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: ED25519_PUBLIC_KEY_LEN,
                actual: pubkey.len(),
            });
        }
        let pubkey = pubkey.to_vec();
        let message = message.to_vec();
        let signature = signature.to_vec();
        tokio::task::spawn_blocking(move || Self::ed25519_verify(&pubkey, &message, &signature))
            .await
            .map_err(|_| CryptoError::OperationFailed("aws-lc-rs Ed25519 verify panicked".into()))?
    }

    async fn verify_p256(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        Self::p256_verify(pubkey, message, signature)
    }

    async fn sign_ed25519(
        &self,
        seed: &SecureSeed,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let seed_bytes = *seed.as_bytes();
        let message = message.to_vec();
        tokio::task::spawn_blocking(move || Self::ed25519_sign(&seed_bytes, &message))
            .await
            .map_err(|_| CryptoError::OperationFailed("aws-lc-rs Ed25519 sign panicked".into()))?
    }

    async fn generate_ed25519_keypair(&self) -> Result<(SecureSeed, [u8; 32]), CryptoError> {
        tokio::task::spawn_blocking(move || {
            let rng = SystemRandom::new();
            let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|_| CryptoError::OperationFailed("aws-lc-rs Ed25519 keygen".into()))?;
            let keypair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref())
                .map_err(|e| CryptoError::OperationFailed(format!("parse generated key: {e}")))?;
            let public_key: [u8; 32] =
                keypair.public_key().as_ref().try_into().map_err(|_| {
                    CryptoError::OperationFailed("aws-lc-rs Ed25519 pubkey len".into())
                })?;
            // PKCS#8 v2 layout: seed at bytes [16..48]. Same as ring's emission.
            let pkcs8_bytes = pkcs8_doc.as_ref();
            let seed: [u8; 32] = pkcs8_bytes[16..48]
                .try_into()
                .map_err(|_| CryptoError::OperationFailed("seed extraction".into()))?;
            Ok((SecureSeed::new(seed), public_key))
        })
        .await
        .map_err(|_| CryptoError::OperationFailed("aws-lc-rs keygen task panicked".into()))?
    }

    async fn ed25519_public_key_from_seed(
        &self,
        seed: &SecureSeed,
    ) -> Result<[u8; 32], CryptoError> {
        let seed_bytes = *seed.as_bytes();
        tokio::task::spawn_blocking(move || Self::ed25519_public_key(&seed_bytes))
            .await
            .map_err(|_| CryptoError::OperationFailed("aws-lc-rs pubkey task panicked".into()))?
    }

    async fn sign_p256(&self, seed: &SecureSeed, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Self::p256_sign(seed.as_bytes(), message)
    }

    async fn generate_p256_keypair(&self) -> Result<(SecureSeed, Vec<u8>), CryptoError> {
        Self::p256_generate()
    }

    async fn p256_public_key_from_seed(&self, seed: &SecureSeed) -> Result<Vec<u8>, CryptoError> {
        Self::p256_public_key_from_seed(seed.as_bytes())
    }

    async fn aead_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

        let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)
            .map_err(|e| CryptoError::OperationFailed(format!("aws-lc-rs AEAD key: {e}")))?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let aad = Aad::from(aad);
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, aad, &mut in_out)
            .map_err(|e| CryptoError::OperationFailed(format!("aws-lc-rs AEAD seal: {e}")))?;
        Ok(in_out)
    }

    async fn aead_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use aws_lc_rs::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};

        let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)
            .map_err(|e| CryptoError::OperationFailed(format!("aws-lc-rs AEAD key: {e}")))?;
        let key = LessSafeKey::new(unbound);
        let nonce = Nonce::assume_unique_for_key(*nonce);
        let aad = Aad::from(aad);
        let mut in_out = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, aad, &mut in_out)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(plaintext.to_vec())
    }

    async fn hkdf_sha256_expand(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};

        if out_len > 255 * 32 {
            return Err(CryptoError::OperationFailed(
                "HKDF-SHA256 output length exceeds 255 * 32 = 8160 bytes".into(),
            ));
        }
        let salt = Salt::new(HKDF_SHA256, salt);
        let prk = salt.extract(ikm);
        struct Len(usize);
        impl KeyType for Len {
            fn len(&self) -> usize {
                self.0
            }
        }
        let info_slices = [info];
        let okm = prk
            .expand(&info_slices, Len(out_len))
            .map_err(|e| CryptoError::OperationFailed(format!("aws-lc-rs HKDF256: {e}")))?;
        let mut out = vec![0u8; out_len];
        okm.fill(&mut out)
            .map_err(|e| CryptoError::OperationFailed(format!("aws-lc-rs HKDF fill: {e}")))?;
        Ok(out)
    }

    async fn hkdf_sha384_expand(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        use aws_lc_rs::hkdf::{HKDF_SHA384, KeyType, Salt};

        if out_len > 255 * 48 {
            return Err(CryptoError::OperationFailed(
                "HKDF-SHA384 output length exceeds 255 * 48 = 12240 bytes".into(),
            ));
        }
        let salt = Salt::new(HKDF_SHA384, salt);
        let prk = salt.extract(ikm);
        struct Len(usize);
        impl KeyType for Len {
            fn len(&self) -> usize {
                self.0
            }
        }
        let info_slices = [info];
        let okm = prk
            .expand(&info_slices, Len(out_len))
            .map_err(|e| CryptoError::OperationFailed(format!("aws-lc-rs HKDF384: {e}")))?;
        let mut out = vec![0u8; out_len];
        okm.fill(&mut out)
            .map_err(|e| CryptoError::OperationFailed(format!("aws-lc-rs HKDF fill: {e}")))?;
        Ok(out)
    }

    async fn hmac_sha256_compute(&self, key: &[u8], msg: &[u8]) -> Result<[u8; 32], CryptoError> {
        use aws_lc_rs::hmac::{HMAC_SHA256, Key};

        let k = Key::new(HMAC_SHA256, key);
        let tag = aws_lc_rs::hmac::sign(&k, msg);
        let bytes = tag.as_ref();
        let out: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::OperationFailed("HMAC-SHA256 tag not 32 bytes".into()))?;
        Ok(out)
    }

    async fn hmac_sha256_verify(
        &self,
        key: &[u8],
        msg: &[u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        use aws_lc_rs::hmac::{HMAC_SHA256, Key};

        let k = Key::new(HMAC_SHA256, key);
        // aws-lc-rs's `verify` is constant-time.
        aws_lc_rs::hmac::verify(&k, msg, tag).map_err(|_| CryptoError::InvalidSignature)
    }

    async fn hmac_sha384_compute(&self, key: &[u8], msg: &[u8]) -> Result<[u8; 48], CryptoError> {
        use aws_lc_rs::hmac::{HMAC_SHA384, Key};

        let k = Key::new(HMAC_SHA384, key);
        let tag = aws_lc_rs::hmac::sign(&k, msg);
        let bytes = tag.as_ref();
        let out: [u8; 48] = bytes
            .try_into()
            .map_err(|_| CryptoError::OperationFailed("HMAC-SHA384 tag not 48 bytes".into()))?;
        Ok(out)
    }

    async fn hmac_sha384_verify(
        &self,
        key: &[u8],
        msg: &[u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        use aws_lc_rs::hmac::{HMAC_SHA384, Key};

        let k = Key::new(HMAC_SHA384, key);
        aws_lc_rs::hmac::verify(&k, msg, tag).map_err(|_| CryptoError::InvalidSignature)
    }
}
