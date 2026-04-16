//! Key import and management operations.
//!
//! Provides SDK-level key management functions that wrap `auths-core` crypto
//! primitives. These functions are the canonical entry point for key operations
//! — the CLI is a thin wrapper that reads files and calls these.

use auths_core::crypto::signer::encrypt_keypair;
use auths_core::storage::keychain::{KeyAlias, KeyRole, KeyStorage};
use auths_verifier::IdentityDID;
use thiserror::Error;
use zeroize::Zeroizing;

/// Errors from key import operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KeyImportError {
    /// The seed is not exactly 32 bytes.
    #[error("seed must be exactly 32 bytes, got {0}")]
    InvalidSeedLength(usize),

    /// The alias string is empty.
    #[error("key alias cannot be empty")]
    EmptyAlias,

    /// PKCS#8 DER encoding failed.
    #[error("failed to generate PKCS#8 from seed: {0}")]
    Pkcs8Generation(String),

    /// Encryption of the private key failed.
    #[error("failed to encrypt private key: {0}")]
    Encryption(String),

    /// Storing the encrypted key in the keychain failed.
    #[error("failed to store key in keychain: {0}")]
    KeychainStore(String),
}

/// Result of a successful key import.
#[derive(Debug, Clone)]
pub struct KeyImportResult {
    /// The public key derived from the seed (32 bytes Ed25519, 33 bytes P-256 compressed).
    pub public_key: Vec<u8>,
    /// The curve of the imported key.
    pub curve: auths_crypto::CurveType,
    /// The alias under which the key was stored.
    pub alias: String,
}

/// Imports a signing key from a raw 32-byte seed into the keychain.
///
/// Both Ed25519 and P-256 use 32-byte scalars; the curve tag determines
/// which PKCS#8 shape is emitted and which public key is derived.
///
/// Args:
/// * `seed`: The raw 32-byte signing seed, wrapped in `Zeroizing`.
/// * `curve`: Curve for the imported key (P-256 default per workspace convention).
/// * `passphrase`: The encryption passphrase, wrapped in `Zeroizing`.
/// * `alias`: The local keychain alias for this key.
/// * `controller_did`: The identity DID this key is associated with.
/// * `keychain`: The keychain backend to store the encrypted key.
///
/// Usage:
/// ```ignore
/// let result = import_seed(
///     &seed, CurveType::P256, &passphrase, "my_key",
///     &IdentityDID::new_unchecked("did:keri:EXq5abc"),
///     keychain.as_ref(),
/// )?;
/// ```
pub fn import_seed(
    seed: &Zeroizing<[u8; 32]>,
    curve: auths_crypto::CurveType,
    passphrase: &Zeroizing<String>,
    alias: &str,
    controller_did: &IdentityDID,
    keychain: &dyn KeyStorage,
) -> Result<KeyImportResult, KeyImportError> {
    if alias.trim().is_empty() {
        return Err(KeyImportError::EmptyAlias);
    }

    let typed_seed = match curve {
        auths_crypto::CurveType::Ed25519 => auths_crypto::TypedSeed::Ed25519(**seed),
        auths_crypto::CurveType::P256 => auths_crypto::TypedSeed::P256(**seed),
    };
    let signer = auths_crypto::TypedSignerKey::from_seed(typed_seed)
        .map_err(|e| KeyImportError::Pkcs8Generation(format!("failed to derive keypair: {e}")))?;
    let pkcs8 = signer
        .to_pkcs8()
        .map_err(|e| KeyImportError::Pkcs8Generation(e.to_string()))?;

    let encrypted = encrypt_keypair(pkcs8.as_ref(), passphrase)
        .map_err(|e| KeyImportError::Encryption(e.to_string()))?;

    keychain
        .store_key(
            &KeyAlias::new_unchecked(alias),
            controller_did,
            KeyRole::Primary,
            &encrypted,
        )
        .map_err(|e| KeyImportError::KeychainStore(e.to_string()))?;

    Ok(KeyImportResult {
        public_key: signer.public_key().to_vec(),
        curve,
        alias: alias.to_string(),
    })
}
