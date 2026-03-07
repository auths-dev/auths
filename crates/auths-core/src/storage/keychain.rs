//! Keychain abstraction.

use crate::config::EnvironmentConfig;
use crate::error::AgentError;
use crate::paths::auths_home_with_config;
use log::{info, warn};
use std::sync::Arc;

#[cfg(target_os = "ios")]
use super::ios_keychain::IOSKeychain;

#[cfg(target_os = "macos")]
use super::macos_keychain::MacOSKeychain;

#[cfg(all(target_os = "linux", feature = "keychain-linux-secretservice"))]
use super::linux_secret_service::LinuxSecretServiceStorage;

#[cfg(all(target_os = "windows", feature = "keychain-windows"))]
use super::windows_credential::WindowsCredentialStorage;

#[cfg(target_os = "android")]
use super::android_keystore::AndroidKeystoreStorage;

use super::encrypted_file::EncryptedFileStorage;
use super::memory::MemoryKeychainHandle;
use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;
use zeroize::Zeroizing;

/// Service name used for all platform keychains.
/// Used inside cfg-gated blocks (macOS, iOS, Linux, Windows, Android).
#[cfg_attr(
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "android",
        all(target_os = "linux", feature = "keychain-linux-secretservice"),
        all(target_os = "windows", feature = "keychain-windows"),
        test,
    )),
    allow(dead_code)
)]
const SERVICE_NAME: &str = "dev.auths.agent";

// Re-exported from auths-verifier (the leaf dependency shared by all crates).
pub use auths_verifier::IdentityDID;

/// The role a stored key serves within its identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRole {
    /// The identity's current active signing key.
    Primary,
    /// A pre-committed rotation key (not yet active).
    NextRotation,
    /// A key delegated to an autonomous agent.
    DelegatedAgent,
}

impl std::fmt::Display for KeyRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyRole::Primary => write!(f, "primary"),
            KeyRole::NextRotation => write!(f, "next_rotation"),
            KeyRole::DelegatedAgent => write!(f, "delegated_agent"),
        }
    }
}

impl std::str::FromStr for KeyRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "primary" => Ok(KeyRole::Primary),
            "next_rotation" => Ok(KeyRole::NextRotation),
            "delegated_agent" => Ok(KeyRole::DelegatedAgent),
            other => Err(format!("unknown key role: {other}")),
        }
    }
}

/// Validated alias for a stored key.
///
/// Invariants: non-empty and contains no null bytes.
///
/// Usage:
/// ```ignore
/// let alias = KeyAlias::new("my-signing-key")?;
/// keychain.store_key(&alias, &did, &encrypted)?;
/// ```
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
#[repr(transparent)]
pub struct KeyAlias(String);

impl KeyAlias {
    /// Creates a validated `KeyAlias`.
    ///
    /// Rejects empty strings and strings containing null bytes.
    pub fn new<S: Into<String>>(s: S) -> Result<Self, AgentError> {
        let s = s.into();
        if s.is_empty() {
            return Err(AgentError::InvalidInput(
                "key alias must not be empty".into(),
            ));
        }
        if s.contains('\0') {
            return Err(AgentError::InvalidInput(
                "key alias must not contain null bytes".into(),
            ));
        }
        Ok(Self(s))
    }

    /// Wraps a string without validation (for trusted internal paths).
    pub fn new_unchecked<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }

    /// Returns the alias as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes self and returns the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for KeyAlias {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for KeyAlias {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for KeyAlias {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for KeyAlias {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<KeyAlias> for String {
    fn from(alias: KeyAlias) -> String {
        alias.0
    }
}

impl PartialEq<str> for KeyAlias {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for KeyAlias {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for KeyAlias {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

/// Platform-agnostic interface for storing and loading private keys securely.
///
/// All implementors must be Send + Sync for thread-safe access.
pub trait KeyStorage: Send + Sync {
    /// Stores encrypted key data associated with an alias AND an identity DID.
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        role: KeyRole,
        encrypted_key_data: &[u8],
    ) -> Result<(), AgentError>;

    /// Loads the encrypted key data AND the associated identity DID for a given alias.
    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, KeyRole, Vec<u8>), AgentError>;

    /// Deletes a key by its alias.
    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError>;

    /// Lists all aliases stored by this backend for the specific service.
    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError>;

    /// Lists aliases associated ONLY with the given identity DID.
    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError>;

    /// List aliases for an identity filtered by role.
    fn list_aliases_for_identity_with_role(
        &self,
        identity_did: &IdentityDID,
        role: KeyRole,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        let all = self.list_aliases_for_identity(identity_did)?;
        let mut filtered = Vec::new();
        for alias in all {
            if let Ok((_, r, _)) = self.load_key(&alias)
                && r == role
            {
                filtered.push(alias);
            }
        }
        Ok(filtered)
    }

    /// Retrieves the identity DID associated with a given alias.
    fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError>;

    /// Returns the name of the storage backend.
    fn backend_name(&self) -> &'static str;
}

/// Decrypt a stored key and return its Ed25519 public key bytes.
///
/// Loads the encrypted key for `alias`, calls `passphrase_provider` to obtain
/// the decryption passphrase, decrypts the PKCS8 blob, and returns the raw
/// 32-byte public key.
///
/// Args:
/// * `keychain`: The key storage backend holding the encrypted key.
/// * `alias`: Keychain alias of the stored key.
/// * `passphrase_provider`: Provider to obtain the decryption passphrase.
///
/// Usage:
/// ```ignore
/// let pk = extract_public_key_bytes(keychain, "my-key", &provider)?;
/// let device_did = DeviceDID::from_ed25519(pk.as_slice().try_into()?);
/// ```
pub fn extract_public_key_bytes(
    keychain: &dyn KeyStorage,
    alias: &KeyAlias,
    passphrase_provider: &dyn crate::signing::PassphraseProvider,
) -> Result<Vec<u8>, AgentError> {
    use crate::crypto::signer::{decrypt_keypair, load_seed_and_pubkey};

    let (_, _role, encrypted) = keychain.load_key(alias)?;
    let passphrase = passphrase_provider
        .get_passphrase(&format!("Enter passphrase for key '{alias}':"))
        .map_err(|e| AgentError::SigningFailed(e.to_string()))?;
    let pkcs8 = decrypt_keypair(&encrypted, &passphrase)?;
    let (_, pubkey) = load_seed_and_pubkey(&pkcs8)?;
    Ok(pubkey.to_vec())
}

/// Return a boxed `KeyStorage` implementation driven by the supplied `EnvironmentConfig`.
///
/// Uses `config.keychain.backend` to select the backend and `config.keychain.file_path`
/// / `config.keychain.passphrase` for the encrypted-file backend. Falls back to the
/// platform default when no override is specified.
///
/// Args:
/// * `config` - The environment configuration carrying keychain settings and home path.
///
/// Usage:
/// ```ignore
/// let env = EnvironmentConfig::from_env();
/// let keychain = get_platform_keychain_with_config(&env)?;
/// ```
pub fn get_platform_keychain_with_config(
    config: &EnvironmentConfig,
) -> Result<Box<dyn KeyStorage + Send + Sync>, AgentError> {
    if let Some(ref backend) = config.keychain.backend {
        return get_backend_by_name(backend, config);
    }
    get_platform_default(config)
}

/// Return a boxed KeyStorage implementation for the current platform.
///
/// Reads keychain configuration from environment variables via
/// `EnvironmentConfig::from_env()`. Prefer `get_platform_keychain_with_config`
/// for new code to keep env-var reads at the process boundary.
///
/// # Environment Variable Override
///
/// Set `AUTHS_KEYCHAIN_BACKEND` to override the platform default:
/// - `"file"` - Use encrypted file storage at `~/.auths/keys.enc`
/// - `"memory"` - Use in-memory storage (for testing only)
///
/// Invalid values will log a warning and use the platform default.
///
/// # Errors
/// Returns `AgentError` if the platform keychain fails to initialize.
pub fn get_platform_keychain() -> Result<Box<dyn KeyStorage + Send + Sync>, AgentError> {
    get_platform_keychain_with_config(&EnvironmentConfig::from_env())
}

/// Get the platform-default keychain backend.
#[allow(unused_variables, unreachable_code)]
fn get_platform_default(
    config: &EnvironmentConfig,
) -> Result<Box<dyn KeyStorage + Send + Sync>, AgentError> {
    #[cfg(target_os = "ios")]
    {
        return Ok(Box::new(IOSKeychain::new(SERVICE_NAME)));
    }

    #[cfg(target_os = "macos")]
    {
        return Ok(Box::new(MacOSKeychain::new(SERVICE_NAME)));
    }

    #[cfg(all(target_os = "linux", feature = "keychain-linux-secretservice"))]
    {
        // Try Secret Service first, fall back to encrypted file storage
        match LinuxSecretServiceStorage::new(SERVICE_NAME) {
            Ok(storage) => return Ok(Box::new(storage)),
            Err(e) => {
                warn!("Secret Service unavailable ({}), trying file fallback", e);
                #[cfg(feature = "keychain-file-fallback")]
                {
                    return new_encrypted_file_storage(config).map(|s| {
                        let b: Box<dyn KeyStorage + Send + Sync> = Box::new(s);
                        b
                    });
                }
                #[cfg(not(feature = "keychain-file-fallback"))]
                {
                    return Err(e);
                }
            }
        }
    }

    #[cfg(all(target_os = "linux", not(feature = "keychain-linux-secretservice")))]
    {
        // No Secret Service feature, check for file fallback
        #[cfg(feature = "keychain-file-fallback")]
        {
            return new_encrypted_file_storage(config).map(|s| {
                let b: Box<dyn KeyStorage + Send + Sync> = Box::new(s);
                b
            });
        }
    }

    #[cfg(all(target_os = "windows", feature = "keychain-windows"))]
    {
        return Ok(Box::new(WindowsCredentialStorage::new(SERVICE_NAME)?));
    }

    #[cfg(target_os = "android")]
    {
        return Ok(Box::new(AndroidKeystoreStorage::new(SERVICE_NAME)?));
    }

    // Fallback for unsupported platforms or missing features
    #[allow(unused_variables)]
    let _ = config;
    #[allow(unreachable_code)]
    {
        warn!("Using in-memory keychain (not recommended for production)");
        Ok(Box::new(MemoryKeychainHandle))
    }
}

/// Get a keychain backend by name (for environment variable override).
fn get_backend_by_name(
    name: &str,
    config: &EnvironmentConfig,
) -> Result<Box<dyn KeyStorage + Send + Sync>, AgentError> {
    match name.to_lowercase().as_str() {
        "memory" => {
            info!("Using in-memory keychain (AUTHS_KEYCHAIN_BACKEND=memory)");
            Ok(Box::new(MemoryKeychainHandle))
        }
        "file" => {
            info!("Using encrypted file storage (AUTHS_KEYCHAIN_BACKEND=file)");
            let storage = new_encrypted_file_storage(config)?;
            Ok(Box::new(storage))
        }
        #[cfg(feature = "keychain-pkcs11")]
        "hsm" | "pkcs11" => {
            info!("Using PKCS#11 HSM backend (AUTHS_KEYCHAIN_BACKEND={name})");
            let pkcs11_config =
                config
                    .pkcs11
                    .as_ref()
                    .ok_or_else(|| AgentError::BackendInitFailed {
                        backend: "pkcs11",
                        error: "PKCS#11 configuration required (set AUTHS_PKCS11_LIBRARY)".into(),
                    })?;
            let storage = super::pkcs11::Pkcs11KeyRef::new(pkcs11_config)?;
            Ok(Box::new(storage))
        }
        _ => {
            warn!(
                "Unknown keychain backend '{}', using platform default",
                name
            );
            get_platform_default(config)
        }
    }
}

/// Construct an `EncryptedFileStorage` from the provided config.
///
/// Uses `config.keychain.file_path` when set; otherwise resolves the default
/// path from `config.auths_home` (or `~/.auths/keys.enc`).
/// Sets the password from `config.keychain.passphrase` when present.
fn new_encrypted_file_storage(
    config: &EnvironmentConfig,
) -> Result<EncryptedFileStorage, AgentError> {
    let storage = if let Some(ref path) = config.keychain.file_path {
        EncryptedFileStorage::with_path(path.clone())?
    } else {
        let home =
            auths_home_with_config(config).map_err(|e| AgentError::StorageError(e.to_string()))?;
        EncryptedFileStorage::new(&home)?
    };

    if let Some(ref passphrase) = config.keychain.passphrase {
        storage.set_password(Zeroizing::new(passphrase.clone()));
    }

    Ok(storage)
}

/// Creates a PKCS#11-backed [`SecureSigner`](crate::signing::SecureSigner) from the
/// environment config, if the backend is set to `"pkcs11"` or `"hsm"`.
///
/// Returns `None` if the keychain backend is not PKCS#11.
///
/// Args:
/// * `config`: Environment configuration.
///
/// Usage:
/// ```ignore
/// if let Some(signer) = get_pkcs11_signer(&env)? {
///     signer.sign_with_alias(&alias, &provider, message)?;
/// }
/// ```
#[cfg(feature = "keychain-pkcs11")]
pub fn get_pkcs11_signer(
    config: &EnvironmentConfig,
) -> Result<Option<Box<dyn crate::signing::SecureSigner>>, AgentError> {
    let is_pkcs11 = config
        .keychain
        .backend
        .as_deref()
        .map(|b| matches!(b.to_lowercase().as_str(), "hsm" | "pkcs11"))
        .unwrap_or(false);

    if !is_pkcs11 {
        return Ok(None);
    }

    let pkcs11_config = config
        .pkcs11
        .as_ref()
        .ok_or_else(|| AgentError::BackendInitFailed {
            backend: "pkcs11",
            error: "PKCS#11 configuration required (set AUTHS_PKCS11_LIBRARY)".into(),
        })?;

    let signer = super::pkcs11::Pkcs11Signer::new(pkcs11_config)?;
    Ok(Some(Box::new(signer)))
}

impl KeyStorage for Arc<dyn KeyStorage + Send + Sync> {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        role: KeyRole,
        encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        self.as_ref()
            .store_key(alias, identity_did, role, encrypted_key_data)
    }
    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, KeyRole, Vec<u8>), AgentError> {
        self.as_ref().load_key(alias)
    }
    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
        self.as_ref().delete_key(alias)
    }
    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        self.as_ref().list_aliases()
    }
    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        self.as_ref().list_aliases_for_identity(identity_did)
    }
    fn list_aliases_for_identity_with_role(
        &self,
        identity_did: &IdentityDID,
        role: KeyRole,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        self.as_ref()
            .list_aliases_for_identity_with_role(identity_did, role)
    }
    fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        self.as_ref().get_identity_for_alias(alias)
    }
    fn backend_name(&self) -> &'static str {
        self.as_ref().backend_name()
    }
}

impl KeyStorage for Box<dyn KeyStorage + Send + Sync> {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        role: KeyRole,
        encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        self.as_ref()
            .store_key(alias, identity_did, role, encrypted_key_data)
    }
    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, KeyRole, Vec<u8>), AgentError> {
        self.as_ref().load_key(alias)
    }
    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
        self.as_ref().delete_key(alias)
    }
    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        self.as_ref().list_aliases()
    }
    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        self.as_ref().list_aliases_for_identity(identity_did)
    }
    fn list_aliases_for_identity_with_role(
        &self,
        identity_did: &IdentityDID,
        role: KeyRole,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        self.as_ref()
            .list_aliases_for_identity_with_role(identity_did, role)
    }
    fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        self.as_ref().get_identity_for_alias(alias)
    }
    fn backend_name(&self) -> &'static str {
        self.as_ref().backend_name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_name_constant() {
        assert_eq!(SERVICE_NAME, "dev.auths.agent");
    }

    #[test]
    fn test_get_backend_by_name_memory() {
        let env = EnvironmentConfig::default();
        let backend = get_backend_by_name("memory", &env).unwrap();
        assert_eq!(backend.backend_name(), "Memory");
    }

    #[test]
    fn test_get_backend_by_name_case_insensitive() {
        let env = EnvironmentConfig::default();
        let backend = get_backend_by_name("MEMORY", &env).unwrap();
        assert_eq!(backend.backend_name(), "Memory");
    }
}
