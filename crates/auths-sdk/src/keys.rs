//! Key import and management operations.
//!
//! Provides SDK-level key management functions that wrap `auths-core` crypto
//! primitives. These functions are the canonical entry point for key operations
//! — the CLI is a thin wrapper that reads files and calls these.

use auths_core::crypto::signer::encrypt_keypair;
use auths_core::crypto::ssh::build_ed25519_pkcs8_v2_from_seed;
use auths_core::storage::keychain::{KeyAlias, KeyStorage};
use auths_crypto::SecureSeed;
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
    /// The 32-byte Ed25519 public key derived from the seed.
    pub public_key: [u8; 32],
    /// The alias under which the key was stored.
    pub alias: String,
}

/// Imports an Ed25519 key from a raw 32-byte seed into the keychain.
///
/// Generates PKCS#8 v2 DER from the seed, encrypts with the passphrase, and
/// stores in the provided keychain under the given alias associated with the
/// controller DID. No file I/O, no terminal interaction.
///
/// Args:
/// * `seed`: The raw 32-byte Ed25519 seed, wrapped in `Zeroizing`.
/// * `passphrase`: The encryption passphrase, wrapped in `Zeroizing`.
/// * `alias`: The local keychain alias for this key.
/// * `controller_did`: The identity DID this key is associated with.
/// * `keychain`: The keychain backend to store the encrypted key.
///
/// Usage:
/// ```ignore
/// let result = import_seed(
///     &seed, &passphrase, "my_key",
///     &IdentityDID::new("did:keri:EXq5abc"),
///     keychain.as_ref(),
/// )?;
/// ```
pub fn import_seed(
    seed: &Zeroizing<[u8; 32]>,
    passphrase: &Zeroizing<String>,
    alias: &str,
    controller_did: &IdentityDID,
    keychain: &dyn KeyStorage,
) -> Result<KeyImportResult, KeyImportError> {
    if alias.trim().is_empty() {
        return Err(KeyImportError::EmptyAlias);
    }

    let secure_seed = SecureSeed::new(**seed);

    let pkcs8_bytes = build_ed25519_pkcs8_v2_from_seed(&secure_seed)
        .map_err(|e| KeyImportError::Pkcs8Generation(e.to_string()))?;

    let encrypted =
        encrypt_keypair(&pkcs8_bytes, passphrase).map_err(|e| KeyImportError::Encryption(e.to_string()))?;

    keychain
        .store_key(
            &KeyAlias::new_unchecked(alias),
            controller_did,
            &encrypted,
        )
        .map_err(|e| KeyImportError::KeychainStore(e.to_string()))?;

    let public_key = auths_core::crypto::provider_bridge::ed25519_public_key_from_seed_sync(
        &secure_seed,
    )
    .map_err(|e| KeyImportError::Pkcs8Generation(format!("failed to derive public key: {e}")))?;

    Ok(KeyImportResult {
        public_key,
        alias: alias.to_string(),
    })
}
