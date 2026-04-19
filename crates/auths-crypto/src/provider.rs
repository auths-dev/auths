//! Curve-agnostic cryptographic abstraction supporting Ed25519 and ECDSA P-256.
//!
//! Defines the [`CryptoProvider`] trait for signature verification, signing, and
//! key generation — enabling `ring`/`p256` on native targets and `WebCrypto` on WASM.
//! P-256 is the workspace default curve; Ed25519 is supported as a peer alternative
//! (SSH/Radicle/legacy KERI compat). See `docs/architecture/cryptography.md`.

use async_trait::async_trait;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Error type for cryptographic operations.
///
/// Usage:
/// ```ignore
/// match result {
///     Err(CryptoError::InvalidSignature) => { /* signature did not verify */ }
///     Err(CryptoError::UnsupportedTarget) => { /* not available on this platform */ }
///     Err(CryptoError::OperationFailed(msg)) => { /* backend error */ }
///     Ok(()) => { /* success */ }
/// }
/// ```
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid public key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("Crypto operation failed: {0}")]
    OperationFailed(String),

    #[error("Operation not supported on current compilation target")]
    UnsupportedTarget,
}

impl crate::AuthsErrorInfo for CryptoError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidSignature => "AUTHS-E1001",
            Self::InvalidKeyLength { .. } => {
                "
            "
            }
            Self::InvalidPrivateKey(_) => "AUTHS-E1003",
            Self::OperationFailed(_) => "AUTHS-E1004",
            Self::UnsupportedTarget => "AUTHS-E1005",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::InvalidSignature => Some("The signature does not match the data or public key"),
            Self::InvalidKeyLength { .. } => Some(
                "Ensure the key length matches the declared curve (32 bytes Ed25519, 33 bytes P-256 compressed SEC1)",
            ),
            Self::UnsupportedTarget => {
                Some("This operation is not available on the current platform")
            }
            _ => None,
        }
    }
}

/// Zeroize-on-drop wrapper for a raw 32-byte signing seed.
///
/// Curve-untyped — both Ed25519 and P-256 use 32-byte scalars, so the curve
/// must be carried separately (e.g. via [`crate::TypedSeed`]). For curve-aware
/// flows prefer `TypedSeed`; `SecureSeed` exists for the curve-agnostic
/// trait surface on [`CryptoProvider`].
///
/// This is the portable key representation that crosses the [`CryptoProvider`]
/// boundary. No ring types leak through the trait — only this raw seed.
/// The provider materializes the internal keypair from the seed on each call.
///
/// Usage:
/// ```ignore
/// let (seed, pubkey) = provider.generate_ed25519_keypair().await?;
/// let sig = provider.sign_ed25519(&seed, b"hello").await?;
/// // seed is securely zeroed when dropped
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureSeed([u8; 32]);

impl SecureSeed {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecureSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecureSeed([REDACTED])")
    }
}

/// Curve-agnostic abstraction for cryptographic operations across target architectures.
///
/// All method signatures use primitive Rust types or [`SecureSeed`] — no
/// ring-specific types. This ensures domain crates (`auths-core`, `auths-sdk`)
/// compile without any ring dependency.
///
/// Usage:
/// ```ignore
/// use auths_crypto::CryptoProvider;
///
/// async fn roundtrip(provider: &dyn CryptoProvider) {
///     let (seed, pk) = provider.generate_ed25519_keypair().await.unwrap();
///     let sig = provider.sign_ed25519(&seed, b"msg").await.unwrap();
///     provider.verify_ed25519(&pk, b"msg", &sig).await.unwrap();
/// }
/// ```
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait CryptoProvider: Send + Sync {
    /// Verify an Ed25519 signature against a public key and message.
    async fn verify_ed25519(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;

    /// Verify an ECDSA P-256 signature (r||s, 64 bytes) against a public key
    /// (33-byte compressed or 65-byte uncompressed SEC1) and message.
    ///
    /// Default impl returns `UnsupportedTarget`; override in providers that
    /// support P-256 (`RingCryptoProvider` via `p256` crate on native,
    /// `WebCryptoProvider` via `SubtleCrypto.verify("ECDSA", …)` on WASM).
    async fn verify_p256(
        &self,
        _pubkey: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    /// Sign a message using a raw 32-byte Ed25519 seed.
    ///
    /// The provider materializes the internal keypair from the seed on each
    /// call. This trades minor CPU overhead for a pure, ring-free domain layer.
    ///
    /// Args:
    /// * `seed`: Raw 32-byte Ed25519 private key seed.
    /// * `message`: The data to sign.
    ///
    /// Usage:
    /// ```ignore
    /// let sig = provider.sign_ed25519(&seed, b"hello").await?;
    /// assert_eq!(sig.len(), 64);
    /// ```
    async fn sign_ed25519(&self, seed: &SecureSeed, message: &[u8])
    -> Result<Vec<u8>, CryptoError>;

    /// Generate a fresh Ed25519 keypair.
    ///
    /// Returns the raw 32-byte seed and 32-byte public key.
    ///
    /// Usage:
    /// ```ignore
    /// let (seed, pubkey) = provider.generate_ed25519_keypair().await?;
    /// assert_eq!(pubkey.len(), 32);
    /// ```
    async fn generate_ed25519_keypair(&self) -> Result<(SecureSeed, [u8; 32]), CryptoError>;

    /// Derive the 32-byte public key from a raw seed.
    ///
    /// Args:
    /// * `seed`: Raw 32-byte Ed25519 private key seed.
    ///
    /// Usage:
    /// ```ignore
    /// let pk = provider.ed25519_public_key_from_seed(&seed).await?;
    /// assert_eq!(pk.len(), 32);
    /// ```
    async fn ed25519_public_key_from_seed(
        &self,
        seed: &SecureSeed,
    ) -> Result<[u8; 32], CryptoError>;

    /// Sign a message using a raw 32-byte P-256 scalar seed. Deterministic
    /// ECDSA per RFC 6979. Returns a 64-byte compact r||s signature.
    ///
    /// Args:
    /// * `seed`: Raw 32-byte P-256 private scalar.
    /// * `message`: The data to sign.
    ///
    /// Usage:
    /// ```ignore
    /// let sig = provider.sign_p256(&seed, b"hello").await?;
    /// assert_eq!(sig.len(), P256_SIGNATURE_LEN);
    /// ```
    async fn sign_p256(&self, _seed: &SecureSeed, _message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    /// Generate a fresh P-256 keypair. Returns the raw 32-byte scalar seed
    /// and the 33-byte SEC1 compressed public key.
    ///
    /// Usage:
    /// ```ignore
    /// let (seed, pubkey) = provider.generate_p256_keypair().await?;
    /// assert_eq!(pubkey.len(), P256_PUBLIC_KEY_LEN);
    /// ```
    async fn generate_p256_keypair(&self) -> Result<(SecureSeed, Vec<u8>), CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    /// Derive the 33-byte SEC1 compressed P-256 public key from a raw seed.
    ///
    /// Args:
    /// * `seed`: Raw 32-byte P-256 private scalar.
    ///
    /// Usage:
    /// ```ignore
    /// let pk = provider.p256_public_key_from_seed(&seed).await?;
    /// assert_eq!(pk.len(), P256_PUBLIC_KEY_LEN);
    /// ```
    async fn p256_public_key_from_seed(&self, _seed: &SecureSeed) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    /// Encrypt `plaintext` under a 256-bit symmetric `key` with a 96-bit
    /// `nonce` and Additional Authenticated Data (AAD). Output is
    /// `ciphertext || tag` (tag is 16 bytes for both ChaCha20-Poly1305 and
    /// AES-256-GCM).
    ///
    /// Algorithm selection is compile-time via Cargo feature:
    /// - default build: ChaCha20-Poly1305
    /// - `cnsa` feature (fn-128.T4): AES-256-GCM
    ///
    /// Args:
    /// * `key`: 32-byte symmetric key.
    /// * `nonce`: 12-byte per-message nonce; MUST NOT repeat under the same key.
    /// * `aad`: Additional authenticated data (authenticated but not encrypted).
    /// * `plaintext`: Bytes to encrypt.
    ///
    /// Usage:
    /// ```ignore
    /// let ct = provider.aead_encrypt(&key, &nonce, b"session:1", b"secret").await?;
    /// ```
    async fn aead_encrypt(
        &self,
        _key: &[u8; 32],
        _nonce: &[u8; 12],
        _aad: &[u8],
        _plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    /// Decrypt `ciphertext` (`ct || tag`) under a 256-bit symmetric `key`,
    /// 96-bit `nonce`, and matching AAD. Returns the plaintext on success;
    /// `InvalidSignature` on tag mismatch.
    ///
    /// Args:
    /// * `key`: 32-byte symmetric key.
    /// * `nonce`: 12-byte nonce (must match the one used at encryption).
    /// * `aad`: Additional authenticated data (must match encryption AAD byte-for-byte).
    /// * `ciphertext`: `encrypt` output (`ct || tag`).
    ///
    /// Usage:
    /// ```ignore
    /// let pt = provider.aead_decrypt(&key, &nonce, b"session:1", &ct).await?;
    /// ```
    async fn aead_decrypt(
        &self,
        _key: &[u8; 32],
        _nonce: &[u8; 12],
        _aad: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    /// One-shot HKDF-SHA256 extract-then-expand (RFC 5869).
    ///
    /// Args:
    /// * `ikm`: Input keying material (secret).
    /// * `salt`: Non-secret salt (empty slice is acceptable).
    /// * `info`: Domain-separating context tag.
    /// * `out_len`: Desired output length in bytes (max 255 × 32 = 8160).
    ///
    /// Usage:
    /// ```ignore
    /// let okm = provider.hkdf_sha256_expand(&ikm, &salt, b"my-proto-v1", 32).await?;
    /// ```
    async fn hkdf_sha256_expand(
        &self,
        _ikm: &[u8],
        _salt: &[u8],
        _info: &[u8],
        _out_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    /// One-shot HKDF-SHA384 extract-then-expand. Same shape as
    /// [`hkdf_sha256_expand`] but with SHA-384 as the underlying hash. CNSA 2.0
    /// requires SHA-384 for NSS workloads; default builds may return
    /// [`CryptoError::UnsupportedTarget`] if SHA-384 is not available.
    ///
    /// Max output length is 255 × 48 = 12240 bytes.
    async fn hkdf_sha384_expand(
        &self,
        _ikm: &[u8],
        _salt: &[u8],
        _info: &[u8],
        _out_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    /// Compute HMAC-SHA256 over `msg` under `key`. Returns a 32-byte tag.
    ///
    /// Args:
    /// * `key`: MAC key (any length; HMAC hashes over-long keys internally).
    /// * `msg`: Bytes to authenticate.
    ///
    /// Usage:
    /// ```ignore
    /// let tag = provider.hmac_sha256_compute(&key, b"GET\n/path\n...").await?;
    /// ```
    async fn hmac_sha256_compute(&self, _key: &[u8], _msg: &[u8]) -> Result<[u8; 32], CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    /// Verify an HMAC-SHA256 `tag` over `msg` under `key`, constant-time.
    ///
    /// Returns `Ok(())` on match, `Err(CryptoError::InvalidSignature)` on
    /// mismatch. Implementations MUST use a constant-time comparator
    /// (`subtle::ct_eq`, `ring::constant_time`, or equivalent).
    ///
    /// Args:
    /// * `key`: MAC key used at compute time.
    /// * `msg`: Bytes whose authenticity is being checked.
    /// * `tag`: Claimed 32-byte tag.
    ///
    /// Usage:
    /// ```ignore
    /// provider.hmac_sha256_verify(&key, &msg, &claimed_tag).await?;
    /// ```
    async fn hmac_sha256_verify(
        &self,
        _key: &[u8],
        _msg: &[u8],
        _tag: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    /// Compute HMAC-SHA384 over `msg` under `key`. Returns a 48-byte tag.
    /// CNSA counterpart of [`hmac_sha256_compute`].
    async fn hmac_sha384_compute(&self, _key: &[u8], _msg: &[u8]) -> Result<[u8; 48], CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    /// Verify an HMAC-SHA384 `tag` over `msg` under `key`, constant-time.
    /// CNSA counterpart of [`hmac_sha256_verify`].
    async fn hmac_sha384_verify(
        &self,
        _key: &[u8],
        _msg: &[u8],
        _tag: &[u8],
    ) -> Result<(), CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    // -------------------------------------------------------------------------
    // Curve-agnostic entry points (default-impl'd; domain code SHOULD use these)
    //
    // These route through a single `match` on the caller-supplied curve, then
    // dispatch to the primitive methods above. Domain code never needs to
    // `match CurveType` again — that's fn-121's ethos at the provider boundary.
    // -------------------------------------------------------------------------

    /// Sign a message using a curve-carrying seed. Dispatches internally based
    /// on `seed.curve()`; the caller never sees a curve-specific method.
    ///
    /// Args:
    /// * `seed`: Typed seed carrying its curve tag.
    /// * `message`: Bytes to sign.
    ///
    /// Usage:
    /// ```ignore
    /// let sig = provider.sign_typed(&typed_seed, message).await?;
    /// ```
    async fn sign_typed(
        &self,
        seed: &crate::key_ops::TypedSeed,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let secure = SecureSeed::new(*seed.as_bytes());
        match seed.curve() {
            CurveType::Ed25519 => self.sign_ed25519(&secure, message).await,
            CurveType::P256 => self.sign_p256(&secure, message).await,
        }
    }

    /// Verify a signature using a curve and raw public-key bytes. Dispatches
    /// internally; callers never see a curve-specific method.
    ///
    /// Args:
    /// * `curve`: The curve the public key belongs to.
    /// * `pubkey`: Raw public-key bytes (length validated by the curve-specific primitive).
    /// * `message`: Bytes the signature is over.
    /// * `signature`: Signature bytes to verify.
    ///
    /// Usage:
    /// ```ignore
    /// provider.verify_typed(curve, &pk_bytes, msg, &sig).await?;
    /// ```
    async fn verify_typed(
        &self,
        curve: CurveType,
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        match curve {
            CurveType::Ed25519 => self.verify_ed25519(pubkey, message, signature).await,
            CurveType::P256 => self.verify_p256(pubkey, message, signature).await,
        }
    }

    /// Generate a keypair for the requested curve. Returns a curve-tagged
    /// [`crate::key_ops::TypedSeed`] plus raw public-key bytes.
    ///
    /// Args:
    /// * `curve`: Which curve to generate for.
    ///
    /// Usage:
    /// ```ignore
    /// let (typed_seed, pubkey_bytes) = provider.generate_typed_keypair(curve).await?;
    /// ```
    async fn generate_typed_keypair(
        &self,
        curve: CurveType,
    ) -> Result<(crate::key_ops::TypedSeed, Vec<u8>), CryptoError> {
        match curve {
            CurveType::Ed25519 => {
                let (seed, pk) = self.generate_ed25519_keypair().await?;
                Ok((
                    crate::key_ops::TypedSeed::Ed25519(*seed.as_bytes()),
                    pk.to_vec(),
                ))
            }
            CurveType::P256 => {
                let (seed, pk) = self.generate_p256_keypair().await?;
                Ok((crate::key_ops::TypedSeed::P256(*seed.as_bytes()), pk))
            }
        }
    }

    /// Derive the public key from a curve-tagged seed.
    ///
    /// Args:
    /// * `seed`: Typed seed.
    ///
    /// Usage:
    /// ```ignore
    /// let pk_bytes = provider.typed_public_key_from_seed(&typed_seed).await?;
    /// ```
    async fn typed_public_key_from_seed(
        &self,
        seed: &crate::key_ops::TypedSeed,
    ) -> Result<Vec<u8>, CryptoError> {
        let secure = SecureSeed::new(*seed.as_bytes());
        match seed.curve() {
            CurveType::Ed25519 => {
                let pk = self.ed25519_public_key_from_seed(&secure).await?;
                Ok(pk.to_vec())
            }
            CurveType::P256 => self.p256_public_key_from_seed(&secure).await,
        }
    }
}

/// Returns the workspace-configured default crypto provider.
///
/// Selection is compile-time. Today every native build resolves to
/// [`crate::ring_provider::RingCryptoProvider`]. Future FIPS (fn-128.T3) and
/// CNSA (fn-128.T4) features will `cfg`-gate alternate impls here.
///
/// Domain code SHOULD route cryptographic operations through this function
/// rather than constructing `p256::ecdsa::SigningKey` (or equivalent) directly —
/// that way the provider swap is mechanical when FIPS/CNSA land.
///
/// Usage:
/// ```ignore
/// use auths_crypto::{default_provider, CryptoProvider};
///
/// let provider = default_provider();
/// let sig = provider.sign_p256(&seed, msg).await?;
/// ```
#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
pub fn default_provider() -> &'static dyn CryptoProvider {
    &crate::ring_provider::RingCryptoProvider
}

/// Errors from hex seed decoding.
///
/// Usage:
/// ```ignore
/// match decode_seed_hex("bad") {
///     Err(SeedDecodeError::InvalidHex(_)) => { /* not valid hex */ }
///     Err(SeedDecodeError::WrongLength { .. }) => { /* not 32 bytes */ }
///     Ok(seed) => { /* use seed */ }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum SeedDecodeError {
    /// The input string is not valid hexadecimal.
    #[error("invalid hex encoding: {0}")]
    InvalidHex(hex::FromHexError),

    /// The decoded bytes are not exactly 32 bytes.
    #[error("expected {expected} bytes, got {got}")]
    WrongLength {
        /// Expected byte count (always 32).
        expected: usize,
        /// Actual byte count after decoding.
        got: usize,
    },
}

/// Decodes a hex-encoded Ed25519 seed (64 hex chars = 32 bytes) into a [`SecureSeed`].
///
/// Args:
/// * `hex_str`: Hex-encoded seed string (must be exactly 64 characters).
///
/// Usage:
/// ```ignore
/// let seed = decode_seed_hex("abcdef01...")?;
/// ```
pub fn decode_seed_hex(hex_str: &str) -> Result<SecureSeed, SeedDecodeError> {
    let bytes = hex::decode(hex_str).map_err(SeedDecodeError::InvalidHex)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| SeedDecodeError::WrongLength {
            expected: 32,
            got: v.len(),
        })?;
    Ok(SecureSeed::new(arr))
}

/// Ed25519 public key length in bytes.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 signature length in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// ECDSA P-256 compressed public key length in bytes (SEC1: 0x02/0x03 + 32-byte x).
pub const P256_PUBLIC_KEY_LEN: usize = 33;

/// ECDSA P-256 raw r||s signature length in bytes (32 + 32).
pub const P256_SIGNATURE_LEN: usize = 64;

/// Supported elliptic curve types for identity and signing operations.
///
/// P-256 is the default for all operations (identity keys, ephemeral CI keys).
/// Ed25519 is available for compatibility with existing KERI deployments.
///
/// Usage:
/// ```ignore
/// let curve = CurveType::P256; // default
/// let (seed, pubkey) = provider.generate_keypair(curve).await?;
/// ```
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum CurveType {
    /// Ed25519 (RFC 8032). 32-byte keys, 64-byte signatures.
    Ed25519,
    /// ECDSA P-256 / secp256r1. 33-byte compressed keys, 64-byte r||s signatures.
    /// Default for all operations.
    #[default]
    P256,
}

impl std::fmt::Display for CurveType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ed25519 => f.write_str("ed25519"),
            Self::P256 => f.write_str("p256"),
        }
    }
}

impl CurveType {
    /// Returns the expected public key length for this curve.
    pub fn public_key_len(&self) -> usize {
        match self {
            Self::Ed25519 => ED25519_PUBLIC_KEY_LEN,
            Self::P256 => P256_PUBLIC_KEY_LEN,
        }
    }

    /// Returns the expected signature length for this curve.
    pub fn signature_len(&self) -> usize {
        match self {
            Self::Ed25519 => ED25519_SIGNATURE_LEN,
            Self::P256 => P256_SIGNATURE_LEN,
        }
    }
}
