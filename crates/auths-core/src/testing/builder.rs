//! Fluent builder for creating test identities.
//!
//! This module provides [`TestIdentityBuilder`], a fluent API for setting up
//! test identities with associated devices and capabilities.

use crate::crypto::signer::encrypt_keypair;
use crate::error::AgentError;
use crate::signing::{PassphraseProvider, SecureSigner, StorageSigner};
use crate::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use crate::storage::memory::{MEMORY_KEYCHAIN, MemoryKeychainHandle};

use crate::crypto::provider_bridge;
use hex;
use std::path::PathBuf;
use tempfile::TempDir;
use zeroize::Zeroizing;

/// A test passphrase provider that always returns a fixed passphrase.
///
/// Useful for testing scenarios where passphrase prompting is not needed.
///
/// # Example
///
/// ```rust,ignore
/// use auths_core::testing::TestPassphraseProvider;
/// use auths_core::signing::PassphraseProvider;
///
/// let provider = TestPassphraseProvider::new("test-passphrase");
/// let pass = provider.get_passphrase("any prompt").unwrap();
/// assert_eq!(pass, "test-passphrase");
/// ```
pub struct TestPassphraseProvider {
    passphrase: String,
}

impl TestPassphraseProvider {
    /// Creates a new test passphrase provider with the given passphrase.
    pub fn new(passphrase: impl Into<String>) -> Self {
        Self {
            passphrase: passphrase.into(),
        }
    }
}

impl PassphraseProvider for TestPassphraseProvider {
    fn get_passphrase(&self, _prompt_message: &str) -> Result<Zeroizing<String>, AgentError> {
        Ok(Zeroizing::new(self.passphrase.clone()))
    }
}

/// A test identity with associated resources.
///
/// This struct owns all resources created during test identity setup,
/// including the temporary Git repository and in-memory keychain.
/// Resources are cleaned up when this struct is dropped.
///
/// # Fields
///
/// - `temp_dir` - Temporary directory containing the Git repository
/// - `identity_did` - The DID for this identity
/// - `identity_alias` - Alias used to store the identity key
/// - `device_aliases` - Aliases of linked device keys
/// - `passphrase` - The passphrase used to encrypt keys
pub struct TestIdentity {
    /// Temporary directory containing the test Git repo (cleaned up on drop)
    pub temp_dir: TempDir,

    /// The identity DID (e.g., "did:key:z6Mk...")
    pub identity_did: String,

    /// Alias for the identity key in the keychain
    pub identity_alias: KeyAlias,

    /// Aliases for linked device keys
    pub device_aliases: Vec<String>,

    /// Passphrase used to encrypt all keys
    pub passphrase: String,

    /// Public key bytes of the identity
    pub identity_public_key: Vec<u8>,

    /// Map of device alias to public key bytes
    pub device_public_keys: Vec<(String, Vec<u8>)>,
}

impl TestIdentity {
    /// Returns the path to the temporary Git repository.
    pub fn repo_path(&self) -> PathBuf {
        self.temp_dir.path().to_path_buf()
    }

    /// Creates a SecureSigner for this test identity.
    ///
    /// The signer uses the in-memory keychain with the test keys.
    pub fn signer(&self) -> impl SecureSigner {
        StorageSigner::new(MemoryKeychainHandle)
    }

    /// Creates a passphrase provider for this test identity.
    pub fn passphrase_provider(&self) -> TestPassphraseProvider {
        TestPassphraseProvider::new(&self.passphrase)
    }

    /// Gets the keychain handle for this test identity.
    pub fn keychain(&self) -> Box<dyn KeyStorage + Send + Sync> {
        Box::new(MemoryKeychainHandle)
    }
}

/// Builder for creating test identities with linked devices.
///
/// # Example
///
/// ```rust,ignore
/// use auths_core::testing::TestIdentityBuilder;
///
/// let identity = TestIdentityBuilder::new()
///     .with_alias("test-identity")
///     .with_passphrase("test-pass")
///     .with_device("laptop")
///     .with_device("phone")
///     .build()
///     .expect("Failed to build test identity");
///
/// // Use the identity for testing
/// let signer = identity.signer();
/// let provider = identity.passphrase_provider();
/// ```
pub struct TestIdentityBuilder {
    alias: KeyAlias,
    passphrase: String,
    device_aliases: Vec<String>,
}

impl Default for TestIdentityBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestIdentityBuilder {
    /// Creates a new builder with default settings.
    pub fn new() -> Self {
        Self {
            alias: KeyAlias::new_unchecked("test-identity"),
            passphrase: "Test-P@ss12345".to_string(),
            device_aliases: Vec::new(),
        }
    }

    /// Sets the alias for the identity key.
    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        self.alias = KeyAlias::new_unchecked(alias.into());
        self
    }

    /// Sets the passphrase for encrypting keys.
    pub fn with_passphrase(mut self, passphrase: impl Into<String>) -> Self {
        self.passphrase = passphrase.into();
        self
    }

    /// Adds a device with the given alias.
    pub fn with_device(mut self, device_alias: impl Into<String>) -> Self {
        self.device_aliases.push(device_alias.into());
        self
    }

    /// Builds the test identity.
    ///
    /// This creates:
    /// - A temporary Git repository
    /// - An identity keypair stored in the memory keychain
    /// - Device keypairs for each registered device
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Temporary directory creation fails
    /// - Git repository initialization fails
    /// - Key generation or storage fails
    pub fn build(self) -> Result<TestIdentity, AgentError> {
        // Create temp directory for Git repo
        let temp_dir = TempDir::new().map_err(|e| {
            AgentError::StorageError(format!("Failed to create temp directory: {}", e))
        })?;

        // Initialize Git repo using git CLI (avoids git2 dependency)
        let output = std::process::Command::new("git")
            .args(["init"])
            .current_dir(temp_dir.path())
            .output()
            .map_err(|e| AgentError::GitError(format!("Failed to run git init: {}", e)))?;

        if !output.status.success() {
            return Err(AgentError::GitError(format!(
                "git init failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // Clear the memory keychain for a fresh start
        MEMORY_KEYCHAIN.lock().unwrap().clear_all()?;

        // Generate identity keypair via CryptoProvider
        let (identity_seed, identity_pubkey) = provider_bridge::generate_ed25519_keypair_sync()
            .map_err(|e| AgentError::CryptoError(format!("Failed to generate keypair: {:?}", e)))?;
        let identity_public_key = identity_pubkey.to_vec();

        // Create DID from public key (using simplified test format)
        let did_str = format!("did:key:z6Mk{}", hex::encode(&identity_public_key));
        let did = IdentityDID::new_unchecked(did_str.clone());

        // Build PKCS#8 v2 for storage compatibility, then encrypt
        let identity_pkcs8 =
            auths_crypto::build_ed25519_pkcs8_v2(identity_seed.as_bytes(), &identity_pubkey);
        let encrypted_identity =
            encrypt_keypair(&identity_pkcs8, &self.passphrase).map_err(|e| {
                AgentError::CryptoError(format!("Failed to encrypt identity key: {}", e))
            })?;

        MEMORY_KEYCHAIN.lock().unwrap().store_key(
            &self.alias,
            &did,
            KeyRole::Primary,
            &encrypted_identity,
        )?;

        // Generate and store device keys
        let mut device_public_keys = Vec::new();
        for device_alias in &self.device_aliases {
            let (device_seed, device_pubkey) = provider_bridge::generate_ed25519_keypair_sync()
                .map_err(|e| {
                    AgentError::CryptoError(format!("Failed to generate device keypair: {:?}", e))
                })?;

            let device_pkcs8 =
                auths_crypto::build_ed25519_pkcs8_v2(device_seed.as_bytes(), &device_pubkey);
            let encrypted_device =
                encrypt_keypair(&device_pkcs8, &self.passphrase).map_err(|e| {
                    AgentError::CryptoError(format!("Failed to encrypt device key: {}", e))
                })?;

            MEMORY_KEYCHAIN.lock().unwrap().store_key(
                &KeyAlias::new_unchecked(device_alias),
                &did,
                KeyRole::DelegatedAgent,
                &encrypted_device,
            )?;

            device_public_keys.push((device_alias.clone(), device_pubkey.to_vec()));
        }

        Ok(TestIdentity {
            temp_dir,
            identity_did: did_str,
            identity_alias: self.alias,
            device_aliases: self.device_aliases,
            passphrase: self.passphrase,
            identity_public_key,
            device_public_keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{ED25519, UnparsedPublicKey};

    #[test]
    fn test_builder_creates_identity() {
        let identity = TestIdentityBuilder::new()
            .with_alias("my-identity")
            .with_passphrase("S3cret!Pass99")
            .build()
            .expect("Failed to build identity");

        assert!(identity.identity_did.starts_with("did:key:z6Mk"));
        assert_eq!(identity.identity_alias, "my-identity");
        assert_eq!(identity.passphrase, "S3cret!Pass99");
        assert!(identity.device_aliases.is_empty());
    }

    #[test]
    fn test_builder_creates_devices() {
        let identity = TestIdentityBuilder::new()
            .with_device("laptop")
            .with_device("phone")
            .build()
            .expect("Failed to build identity");

        assert_eq!(identity.device_aliases.len(), 2);
        assert!(identity.device_aliases.contains(&"laptop".to_string()));
        assert!(identity.device_aliases.contains(&"phone".to_string()));
        assert_eq!(identity.device_public_keys.len(), 2);
    }

    #[test]
    fn test_signer_can_sign() {
        let identity = TestIdentityBuilder::new()
            .with_alias("signing-test")
            .build()
            .expect("Failed to build identity");

        let signer = identity.signer();
        let provider = identity.passphrase_provider();

        let message = b"test message";
        let signature = signer
            .sign_with_alias(&identity.identity_alias, &provider, message)
            .expect("Signing failed");

        // Verify the signature
        let public_key = UnparsedPublicKey::new(&ED25519, &identity.identity_public_key);
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_device_signer_can_sign() {
        let identity = TestIdentityBuilder::new()
            .with_device("test-device")
            .build()
            .expect("Failed to build identity");

        let signer = identity.signer();
        let provider = identity.passphrase_provider();

        let message = b"device message";
        let alias = crate::storage::keychain::KeyAlias::new_unchecked("test-device");
        let signature = signer
            .sign_with_alias(&alias, &provider, message)
            .expect("Device signing failed");

        // Verify the signature with device public key
        let (_, device_pubkey) = &identity.device_public_keys[0];
        let public_key = UnparsedPublicKey::new(&ED25519, device_pubkey);
        assert!(public_key.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_repo_path_exists() {
        let identity = TestIdentityBuilder::new()
            .build()
            .expect("Failed to build identity");

        let repo_path = identity.repo_path();
        assert!(repo_path.exists());
        assert!(repo_path.join(".git").exists());
    }

    #[test]
    fn test_passphrase_provider() {
        let provider = TestPassphraseProvider::new("my-secret");
        let result = provider.get_passphrase("Enter passphrase:");
        assert!(result.is_ok());
        assert_eq!(*result.unwrap(), "my-secret");
    }
}
