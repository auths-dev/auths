//! Signing key types.

use crate::config::current_algorithm;
use crate::crypto::encryption::{decrypt_bytes, encrypt_bytes};
use crate::crypto::provider_bridge;
use crate::error::AgentError;
use auths_crypto::{CurveType, SecureSeed, TypedSeed};
use auths_verifier::DevicePublicKey;
use ssh_agent_lib::ssh_key::{Algorithm as SshAlgorithm, EcdsaCurve};
use zeroize::Zeroizing;

/// A trait implemented by key types that can sign messages and return their public key.
pub trait SignerKey: Send + Sync + 'static {
    /// Returns the public key bytes of this key.
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Returns the key kind (i.e., SSH algorithm) of this key.
    fn kind(&self) -> SshAlgorithm;

    /// Signs a message and returns the signature bytes.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AgentError>;
}

/// SignerKey implementation backed by a curve-tagged seed.
///
/// carries `DevicePublicKey` instead of bare `[u8; 32]` so callers
/// can't accidentally drop curve information.
pub struct SeedSignerKey {
    seed: SecureSeed,
    public_key: DevicePublicKey,
    curve: CurveType,
}

impl SeedSignerKey {
    /// Create a `SignerKey` from a seed and pre-computed 32-byte Ed25519 pubkey.
    /// Back-compat constructor — prefer [`SeedSignerKey::new_typed`] when curve
    /// is known.
    pub fn new(seed: SecureSeed, public_key: [u8; 32]) -> Self {
        #[allow(clippy::expect_used)] // INVARIANT: Ed25519 pubkey is always 32 bytes
        let dpk = DevicePublicKey::try_new(CurveType::Ed25519, &public_key)
            .expect("Ed25519 public key is always 32 bytes");
        Self {
            seed,
            public_key: dpk,
            curve: CurveType::Ed25519,
        }
    }

    /// Create a curve-tagged `SignerKey` from a seed + typed public key.
    pub fn new_typed(seed: SecureSeed, public_key: DevicePublicKey) -> Self {
        let curve = public_key.curve();
        Self {
            seed,
            public_key,
            curve,
        }
    }

    /// Create a `SignerKey` by deriving the public key from an Ed25519 seed.
    /// Preserved for back-compat; use [`SeedSignerKey::from_typed_seed`] for
    /// curve-aware construction.
    pub fn from_seed(seed: SecureSeed) -> Result<Self, AgentError> {
        let public_key =
            provider_bridge::ed25519_public_key_from_seed_sync(&seed).map_err(|e| {
                AgentError::CryptoError(format!("Failed to derive public key from seed: {}", e))
            })?;
        Ok(Self::new(seed, public_key))
    }

    /// Create a `SignerKey` from a curve-tagged `TypedSeed`.
    pub fn from_typed_seed(seed: TypedSeed) -> Result<Self, AgentError> {
        let curve = seed.curve();
        let pk_bytes = auths_crypto::typed_public_key(&seed)
            .map_err(|e| AgentError::CryptoError(format!("Failed to derive pk: {e}")))?;
        let dpk = DevicePublicKey::try_new(curve, &pk_bytes)
            .map_err(|e| AgentError::CryptoError(format!("Invalid derived pk: {e}")))?;
        Ok(Self {
            seed: seed.to_secure_seed(),
            public_key: dpk,
            curve,
        })
    }

    /// Returns the curve of the underlying signing key.
    pub fn curve(&self) -> CurveType {
        self.curve
    }

    /// Returns a typed view of the public key.
    pub fn typed_public_key(&self) -> &DevicePublicKey {
        &self.public_key
    }
}

impl SignerKey for SeedSignerKey {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    fn kind(&self) -> SshAlgorithm {
        match self.curve {
            CurveType::Ed25519 => SshAlgorithm::Ed25519,
            CurveType::P256 => SshAlgorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AgentError> {
        let typed = match self.curve {
            CurveType::Ed25519 => TypedSeed::Ed25519(*self.seed.as_bytes()),
            CurveType::P256 => TypedSeed::P256(*self.seed.as_bytes()),
        };
        auths_crypto::typed_sign(&typed, message)
            .map_err(|e| AgentError::CryptoError(format!("{} signing failed: {e}", self.curve)))
    }
}

/// Extract a SecureSeed from key bytes in various formats.
///
/// Delegates to [`auths_crypto::parse_key_material`] which detects the curve.
pub fn extract_seed_from_key_bytes(bytes: &[u8]) -> Result<SecureSeed, AgentError> {
    let parsed = auths_crypto::parse_key_material(bytes)
        .map_err(|e| AgentError::KeyDeserializationError(e.to_string()))?;
    Ok(parsed.seed.to_secure_seed())
}

/// Extract a SecureSeed, public key bytes, and curve type from key bytes.
///
/// Delegates to [`auths_crypto::parse_key_material`] which detects the curve
/// and extracts the public key in one pass. The curve is preserved so callers
/// never need to infer it from key length.
pub fn load_seed_and_pubkey(
    bytes: &[u8],
) -> Result<(SecureSeed, Vec<u8>, auths_crypto::CurveType), AgentError> {
    let parsed = auths_crypto::parse_key_material(bytes)
        .map_err(|e| AgentError::KeyDeserializationError(e.to_string()))?;
    let curve = parsed.seed.curve();
    Ok((parsed.seed.to_secure_seed(), parsed.public_key, curve))
}

/// Encrypts a raw serialized keypair using the configured encryption algorithm and passphrase.
pub fn encrypt_keypair(raw: &[u8], passphrase: &str) -> Result<Vec<u8>, AgentError> {
    encrypt_bytes(raw, passphrase, current_algorithm())
}

/// Decrypts a previously encrypted keypair using the configured encryption algorithm and passphrase.
pub fn decrypt_keypair(
    encrypted: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<Vec<u8>>, AgentError> {
    Ok(Zeroizing::new(decrypt_bytes(encrypted, passphrase)?))
}
