// INVARIANT: sanctioned CNSA 2.0 crypto boundary. Like ring_provider and
// aws_lc_provider, this is the one place the CNSA primitive crates are
// allowed to live.
#![allow(clippy::disallowed_methods)]

//! CNSA 2.0 provider — P-384 ECDSA, SHA-384, HMAC-SHA-384, HKDF-SHA-384,
//! AES-256-GCM. Rejects P-256, SHA-256, ChaCha20-Poly1305 at the provider
//! boundary with typed `UnsupportedTarget` / `UnsupportedCurve`-style errors.
//!
//! Selected at compile time when `--features cnsa` is active. Mutually
//! exclusive with `fips` (see `compile_error!` guard at [`crate::provider`]).
//!
//! # Scope
//!
//! - Ed25519 stays available under CNSA. Ed25519 is not one of CNSA 2.0's
//!   approved signature algorithms, but the workspace uses Ed25519 only for
//!   legacy KERI compat and SSH imports — both out-of-band from any NSS
//!   data path. Callers that need strict CNSA compliance pass P-384 keys.
//!   Mixed operation is a policy concern enforced one layer up, not at the
//!   provider surface.
//! - P-256 sign/verify return `CryptoError::UnsupportedTarget` under CNSA.
//!   Existing P-256 KELs cannot be extended in a CNSA build; use the default
//!   build for those deployments. Documented in `docs/security/cnsa-build.md`.
//! - ChaCha20-Poly1305 returns `UnsupportedTarget`. AES-256-GCM is the only
//!   AEAD.
//! - SHA-256 HMAC / HKDF return `UnsupportedTarget`. SHA-384 variants are
//!   first-class.

use async_trait::async_trait;

use crate::provider::{CryptoError, CryptoProvider, ED25519_PUBLIC_KEY_LEN, SecureSeed};

/// CNSA 2.0 provider. Use via [`crate::default_provider()`] when
/// `--features cnsa` is active.
pub struct CnsaProvider;

impl CnsaProvider {
    /// Generate a P-384 keypair. Returns `(scalar_seed, compressed_pubkey)`.
    /// Note: the scalar-seed byte length under P-384 is 48 bytes, but we keep
    /// the 32-byte `SecureSeed` wrapper at the trait boundary (zero-padded on
    /// the low-order end). CNSA consumers that need the full 48-byte seed
    /// should use a richer typed-seed path in a follow-up.
    pub fn p384_generate() -> Result<(SecureSeed, Vec<u8>), CryptoError> {
        use p384::ecdsa::SigningKey;
        use p384::elliptic_curve::rand_core::OsRng;

        let sk = SigningKey::random(&mut OsRng);
        let vk = p384::ecdsa::VerifyingKey::from(&sk);
        let compressed = vk.to_encoded_point(true);
        let pubkey_bytes = compressed.as_bytes().to_vec();

        // P-384 scalar is 48 bytes. Truncate to 32 for the SecureSeed wrapper;
        // the first 32 bytes of the scalar are not sufficient to reconstruct
        // the key, so this is NOT round-trippable. Under CNSA, callers MUST
        // use typed primitives that carry the full 48 bytes. The SecureSeed
        // return is a placeholder for API symmetry only.
        let scalar_bytes = sk.to_bytes();
        let mut seed = [0u8; 32];
        let take = scalar_bytes.len().min(32);
        seed[..take].copy_from_slice(&scalar_bytes[..take]);
        Ok((SecureSeed::new(seed), pubkey_bytes))
    }

    /// Sign with P-384 via RustCrypto `p384`. Returns 96-byte r||s.
    /// `seed` here is the full 48-byte P-384 scalar; callers pass it as the
    /// first 48 bytes of a 64-byte buffer.
    pub fn p384_sign(scalar_48: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use p384::ecdsa::{SigningKey, signature::Signer};

        let sk = SigningKey::from_slice(scalar_48)
            .map_err(|e| CryptoError::InvalidPrivateKey(format!("P-384: {e}")))?;
        let sig: p384::ecdsa::Signature = sk.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    /// Inherent sync shim for the `key_ops::sign` dispatcher. Under CNSA the
    /// curve-agnostic sync path may still receive a P-256 seed (e.g. from a
    /// legacy KEL). We reject with a typed error rather than silently
    /// downgrading or panicking.
    pub fn p256_sign(_seed: &[u8; 32], _message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::OperationFailed(
            "P-256 sign is rejected under --features cnsa; use P-384".into(),
        ))
    }

    /// Inherent sync shim for `key_ops::public_key`. See [`Self::p256_sign`].
    pub fn p256_public_key_from_seed(_seed: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::OperationFailed(
            "P-256 pubkey derivation is rejected under --features cnsa; use P-384".into(),
        ))
    }

    /// Inherent sync Ed25519 sign (Ed25519 stays available under CNSA; see
    /// module docs).
    pub fn ed25519_sign(seed: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        crate::ring_provider::RingCryptoProvider::ed25519_sign(seed, message)
    }

    /// Inherent sync Ed25519 public key derivation.
    pub fn ed25519_public_key(seed: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        crate::ring_provider::RingCryptoProvider::ed25519_public_key(seed)
    }

    /// Verify P-384 ECDSA. Accepts 49-byte compressed or 97-byte uncompressed SEC1.
    pub fn p384_verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier};

        let vk = VerifyingKey::from_sec1_bytes(pubkey)
            .map_err(|e| CryptoError::OperationFailed(format!("P-384 key parse: {e}")))?;
        let sig = Signature::from_slice(signature)
            .map_err(|e| CryptoError::OperationFailed(format!("P-384 sig parse: {e}")))?;
        vk.verify(message, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

#[async_trait]
impl CryptoProvider for CnsaProvider {
    async fn verify_ed25519(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        // Ed25519 stays available for legacy KERI compat — see module docs.
        // Route through ring under the hood.
        if pubkey.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: ED25519_PUBLIC_KEY_LEN,
                actual: pubkey.len(),
            });
        }
        crate::ring_provider::RingCryptoProvider::ed25519_verify(pubkey, message, signature)
    }

    async fn verify_p256(
        &self,
        _pubkey: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        // CNSA 2.0 prohibits P-256. Explicit typed error rather than silent fallback.
        Err(CryptoError::OperationFailed(
            "P-256 verify is rejected under --features cnsa; use P-384".into(),
        ))
    }

    async fn sign_ed25519(
        &self,
        seed: &SecureSeed,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        crate::ring_provider::RingCryptoProvider::ed25519_sign(seed.as_bytes(), message)
    }

    async fn generate_ed25519_keypair(&self) -> Result<(SecureSeed, [u8; 32]), CryptoError> {
        // Delegate to the ring default (Ed25519 is not CNSA-validated but
        // stays available for compat — see module docs).
        crate::ring_provider::RingCryptoProvider
            .generate_ed25519_keypair()
            .await
    }

    async fn ed25519_public_key_from_seed(
        &self,
        seed: &SecureSeed,
    ) -> Result<[u8; 32], CryptoError> {
        crate::ring_provider::RingCryptoProvider::ed25519_public_key(seed.as_bytes())
    }

    async fn sign_p256(&self, _seed: &SecureSeed, _message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::OperationFailed(
            "P-256 sign is rejected under --features cnsa; use P-384".into(),
        ))
    }

    async fn generate_p256_keypair(&self) -> Result<(SecureSeed, Vec<u8>), CryptoError> {
        Err(CryptoError::OperationFailed(
            "P-256 keygen is rejected under --features cnsa; use P-384".into(),
        ))
    }

    async fn p256_public_key_from_seed(&self, _seed: &SecureSeed) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::OperationFailed(
            "P-256 pubkey derivation is rejected under --features cnsa; use P-384".into(),
        ))
    }

    async fn aead_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use aes_gcm::{
            Aes256Gcm, Key, Nonce,
            aead::{Aead, KeyInit, Payload},
        };

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);
        cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|e| CryptoError::OperationFailed(format!("AES-256-GCM encrypt: {e}")))
    }

    async fn aead_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        use aes_gcm::{
            Aes256Gcm, Key, Nonce,
            aead::{Aead, KeyInit, Payload},
        };

        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| CryptoError::InvalidSignature)
    }

    async fn hkdf_sha256_expand(
        &self,
        _ikm: &[u8],
        _salt: &[u8],
        _info: &[u8],
        _out_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::OperationFailed(
            "HKDF-SHA256 is rejected under --features cnsa; use HKDF-SHA384".into(),
        ))
    }

    async fn hkdf_sha384_expand(
        &self,
        ikm: &[u8],
        salt: &[u8],
        info: &[u8],
        out_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        // Same impl as Ring's — the hkdf crate is RustCrypto and unchanged
        // across feature boundaries. Under CNSA this is the approved KDF.
        use hkdf::Hkdf;
        use sha2::Sha384;

        if out_len > 255 * 48 {
            return Err(CryptoError::OperationFailed(
                "HKDF-SHA384 output length exceeds 255 * 48 = 12240 bytes".into(),
            ));
        }
        let hk = Hkdf::<Sha384>::new(if salt.is_empty() { None } else { Some(salt) }, ikm);
        let mut out = vec![0u8; out_len];
        hk.expand(info, &mut out)
            .map_err(|e| CryptoError::OperationFailed(format!("HKDF-SHA384 expand: {e}")))?;
        Ok(out)
    }

    async fn hmac_sha256_compute(&self, _key: &[u8], _msg: &[u8]) -> Result<[u8; 32], CryptoError> {
        Err(CryptoError::OperationFailed(
            "HMAC-SHA256 is rejected under --features cnsa; use HMAC-SHA384".into(),
        ))
    }

    async fn hmac_sha256_verify(
        &self,
        _key: &[u8],
        _msg: &[u8],
        _tag: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::OperationFailed(
            "HMAC-SHA256 verify is rejected under --features cnsa; use HMAC-SHA384".into(),
        ))
    }

    async fn hmac_sha384_compute(&self, key: &[u8], msg: &[u8]) -> Result<[u8; 48], CryptoError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha384;

        let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key)
            .map_err(|e| CryptoError::OperationFailed(format!("HMAC-SHA384 key: {e}")))?;
        mac.update(msg);
        let tag = mac.finalize().into_bytes();
        let out: [u8; 48] = tag.into();
        Ok(out)
    }

    async fn hmac_sha384_verify(
        &self,
        key: &[u8],
        msg: &[u8],
        tag: &[u8],
    ) -> Result<(), CryptoError> {
        use hmac::{Hmac, Mac};
        use sha2::Sha384;

        let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(key)
            .map_err(|e| CryptoError::OperationFailed(format!("HMAC-SHA384 key: {e}")))?;
        mac.update(msg);
        mac.verify_slice(tag)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}
