//! Encrypted file-based key storage for headless environments.
//!
//! Uses Argon2id for key derivation and XChaCha20-Poly1305 for encryption.
//! Stores keys in `~/.auths/keys.enc` with Unix permissions 0600.

use crate::error::AgentError;
use crate::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use argon2::{Argon2, Version};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// XChaCha20-Poly1305 uses a 192-bit (24-byte) nonce
const XCHACHA_NONCE_LEN: usize = 24;
/// 256-bit key for XChaCha20-Poly1305
const KEY_LEN: usize = 32;
/// Argon2id salt length
const SALT_LEN: usize = 16;

/// File format version for future compatibility
const FILE_FORMAT_VERSION: u32 = 1;

/// Encrypted file format stored on disk
#[derive(Debug, Serialize, Deserialize)]
struct EncryptedFileFormat {
    version: u32,
    salt: String,       // base64 encoded
    nonce: String,      // base64 encoded
    ciphertext: String, // base64 encoded
}

/// Entry in the encrypted key file.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum KeyEntry {
    /// New format: (did, role, encrypted_key_b64)
    WithRole(String, String, String),
    /// Legacy format: (did, encrypted_key_b64) — treated as Primary
    Legacy(String, String),
}

/// Internal key data structure (plaintext, stored in ciphertext)
#[derive(Debug, Serialize, Deserialize, Default)]
struct KeyData {
    /// alias -> key entry
    keys: HashMap<String, KeyEntry>,
}

/// Encrypted file storage for headless Linux environments.
///
/// Stores keys in an encrypted JSON file at `~/.auths/keys.enc`.
/// Uses Argon2id for password-based key derivation and XChaCha20-Poly1305 for encryption.
pub struct EncryptedFileStorage {
    path: PathBuf,
    /// Cached password for the session (zeroized on drop)
    password: Mutex<Option<Zeroizing<String>>>,
}

impl EncryptedFileStorage {
    /// Create a new EncryptedFileStorage with default path (`<home>/keys.enc`).
    ///
    /// Args:
    /// * `home` - The Auths home directory (e.g., from `auths_home_with_config`).
    ///
    /// Usage:
    /// ```ignore
    /// let storage = EncryptedFileStorage::new(home_path)?;
    /// ```
    pub fn new(home: &std::path::Path) -> Result<Self, AgentError> {
        Self::with_path(home.join("keys.enc"))
    }

    /// Create a new EncryptedFileStorage with a custom path
    pub fn with_path(path: PathBuf) -> Result<Self, AgentError> {
        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                AgentError::StorageError(format!(
                    "Failed to create directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }
        Ok(Self {
            path,
            password: Mutex::new(None),
        })
    }

    /// Set the password for this session.
    ///
    /// Takes `Zeroizing<String>` to enforce that callers treat the passphrase
    /// as sensitive material from the point of construction.
    #[allow(clippy::unwrap_used)] // mutex poisoning is fatal by design
    pub fn set_password(&self, password: Zeroizing<String>) {
        let mut guard = self.password.lock().unwrap();
        *guard = Some(password);
    }

    /// Get the cached password set via `set_password`.
    #[allow(clippy::unwrap_used)] // mutex poisoning is fatal by design
    fn get_password(&self) -> Result<Zeroizing<String>, AgentError> {
        self.password
            .lock()
            .unwrap()
            .clone()
            .ok_or(AgentError::MissingPassphrase)
    }

    /// Derive a 256-bit key from password using Argon2id
    fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, AgentError> {
        let params = crate::crypto::encryption::get_kdf_params()?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        argon2
            .hash_password_into(password.as_bytes(), salt, key.as_mut())
            .map_err(|e| AgentError::CryptoError(format!("Argon2 key derivation failed: {}", e)))?;

        Ok(key)
    }

    /// Encrypt data with XChaCha20-Poly1305
    fn encrypt(
        key: &[u8; KEY_LEN],
        data: &[u8],
    ) -> Result<(Vec<u8>, [u8; XCHACHA_NONCE_LEN]), AgentError> {
        let nonce: [u8; XCHACHA_NONCE_LEN] = rand::random();
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| AgentError::CryptoError(format!("Invalid key: {}", e)))?;

        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), data)
            .map_err(|e| AgentError::CryptoError(format!("Encryption failed: {}", e)))?;

        Ok((ciphertext, nonce))
    }

    /// Decrypt data with XChaCha20-Poly1305
    fn decrypt(
        key: &[u8; KEY_LEN],
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AgentError> {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| AgentError::CryptoError(format!("Invalid key: {}", e)))?;

        cipher
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .map_err(|_| AgentError::IncorrectPassphrase)
    }

    /// Read and decrypt the key data from disk
    fn read_data(&self) -> Result<KeyData, AgentError> {
        if !self.path.exists() {
            return Ok(KeyData::default());
        }

        let password = self.get_password()?;

        let mut file = File::open(&self.path).map_err(|e| {
            AgentError::StorageError(format!("Failed to open {}: {}", self.path.display(), e))
        })?;

        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|e| {
            AgentError::StorageError(format!("Failed to read {}: {}", self.path.display(), e))
        })?;

        let encrypted: EncryptedFileFormat = serde_json::from_str(&contents)
            .map_err(|e| AgentError::StorageError(format!("Invalid file format: {}", e)))?;

        if encrypted.version != FILE_FORMAT_VERSION {
            return Err(AgentError::StorageError(format!(
                "Unsupported file format version: {} (expected {})",
                encrypted.version, FILE_FORMAT_VERSION
            )));
        }

        let salt = BASE64
            .decode(&encrypted.salt)
            .map_err(|e| AgentError::StorageError(format!("Invalid salt encoding: {}", e)))?;
        let nonce = BASE64
            .decode(&encrypted.nonce)
            .map_err(|e| AgentError::StorageError(format!("Invalid nonce encoding: {}", e)))?;
        let ciphertext = BASE64
            .decode(&encrypted.ciphertext)
            .map_err(|e| AgentError::StorageError(format!("Invalid ciphertext encoding: {}", e)))?;

        let key = Self::derive_key(&password, &salt)?;
        let plaintext = Self::decrypt(&key, &nonce, &ciphertext)?;

        let data: KeyData = serde_json::from_slice(&plaintext)
            .map_err(|e| AgentError::StorageError(format!("Failed to parse key data: {}", e)))?;

        Ok(data)
    }

    /// Encrypt and write key data to disk
    fn write_data(&self, data: &KeyData) -> Result<(), AgentError> {
        let password = self.get_password()?;

        let plaintext = serde_json::to_vec(data).map_err(|e| {
            AgentError::StorageError(format!("Failed to serialize key data: {}", e))
        })?;

        let salt: [u8; SALT_LEN] = rand::random();
        let key = Self::derive_key(&password, &salt)?;
        let (ciphertext, nonce) = Self::encrypt(&key, &plaintext)?;

        let encrypted = EncryptedFileFormat {
            version: FILE_FORMAT_VERSION,
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(&ciphertext),
        };

        let contents = serde_json::to_string_pretty(&encrypted).map_err(|e| {
            AgentError::StorageError(format!("Failed to serialize encrypted data: {}", e))
        })?;

        // Write to a temp file first, then rename for atomicity
        let temp_path = self.path.with_extension("tmp");

        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&temp_path)
                .map_err(|e| {
                    AgentError::StorageError(format!(
                        "Failed to create temp file {}: {}",
                        temp_path.display(),
                        e
                    ))
                })?;

            // Set file permissions to 0600 on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o600);
                file.set_permissions(perms).map_err(|e| {
                    AgentError::StorageError(format!("Failed to set file permissions: {}", e))
                })?;
            }

            file.write_all(contents.as_bytes()).map_err(|e| {
                AgentError::StorageError(format!(
                    "Failed to write to {}: {}",
                    temp_path.display(),
                    e
                ))
            })?;

            file.sync_all()
                .map_err(|e| AgentError::StorageError(format!("Failed to sync file: {}", e)))?;
        }

        // Atomic rename
        fs::rename(&temp_path, &self.path).map_err(|e| {
            AgentError::StorageError(format!(
                "Failed to rename {} to {}: {}",
                temp_path.display(),
                self.path.display(),
                e
            ))
        })?;

        Ok(())
    }
}

impl KeyStorage for EncryptedFileStorage {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        role: KeyRole,
        encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        let mut data = self.read_data()?;
        data.keys.insert(
            alias.as_str().to_string(),
            KeyEntry::WithRole(
                identity_did.as_str().to_string(),
                role.to_string(),
                BASE64.encode(encrypted_key_data),
            ),
        );
        self.write_data(&data)
    }

    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, KeyRole, Vec<u8>), AgentError> {
        let data = self.read_data()?;
        let entry = data
            .keys
            .get(alias.as_str())
            .ok_or(AgentError::KeyNotFound)?;
        match entry {
            KeyEntry::WithRole(did, role_str, b64) => {
                let role = role_str.parse::<KeyRole>().unwrap_or(KeyRole::Primary);
                let key_bytes = BASE64.decode(b64).map_err(|e| {
                    AgentError::StorageError(format!("Invalid key encoding: {}", e))
                })?;
                Ok((IdentityDID::new_unchecked(did.clone()), role, key_bytes))
            }
            KeyEntry::Legacy(did, b64) => {
                let key_bytes = BASE64.decode(b64).map_err(|e| {
                    AgentError::StorageError(format!("Invalid key encoding: {}", e))
                })?;
                Ok((
                    IdentityDID::new_unchecked(did.clone()),
                    KeyRole::Primary,
                    key_bytes,
                ))
            }
        }
    }

    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
        let mut data = self.read_data()?;
        data.keys.remove(alias.as_str());
        self.write_data(&data)
    }

    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        let data = self.read_data()?;
        Ok(data
            .keys
            .keys()
            .map(|k| KeyAlias::new_unchecked(k.clone()))
            .collect())
    }

    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        let data = self.read_data()?;
        let aliases = data
            .keys
            .iter()
            .filter_map(|(alias, entry)| {
                let did_str = match entry {
                    KeyEntry::WithRole(did, _, _) | KeyEntry::Legacy(did, _) => did,
                };
                if did_str == identity_did.as_str() {
                    Some(KeyAlias::new_unchecked(alias.clone()))
                } else {
                    None
                }
            })
            .collect();
        Ok(aliases)
    }

    fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        let data = self.read_data()?;
        data.keys
            .get(alias.as_str())
            .map(|entry| {
                let did_str = match entry {
                    KeyEntry::WithRole(did, _, _) | KeyEntry::Legacy(did, _) => did,
                };
                IdentityDID::new_unchecked(did_str.clone())
            })
            .ok_or(AgentError::KeyNotFound)
    }

    fn backend_name(&self) -> &'static str {
        "encrypted-file"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_storage() -> (EncryptedFileStorage, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let storage = EncryptedFileStorage::new(temp_dir.path()).unwrap();
        storage.set_password(Zeroizing::new("test_password".to_string()));
        (storage, temp_dir)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = "test_password";
        let salt: [u8; SALT_LEN] = rand::random();
        let data = b"test data for encryption";

        let key = EncryptedFileStorage::derive_key(password, &salt).unwrap();
        let (ciphertext, nonce) = EncryptedFileStorage::encrypt(&key, data).unwrap();
        let decrypted = EncryptedFileStorage::decrypt(&key, &nonce, &ciphertext).unwrap();

        assert_eq!(data.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_password_fails() {
        let salt: [u8; SALT_LEN] = rand::random();
        let data = b"test data";

        let key1 = EncryptedFileStorage::derive_key("password1", &salt).unwrap();
        let (ciphertext, nonce) = EncryptedFileStorage::encrypt(&key1, data).unwrap();

        let key2 = EncryptedFileStorage::derive_key("password2", &salt).unwrap();
        let result = EncryptedFileStorage::decrypt(&key2, &nonce, &ciphertext);

        assert!(matches!(result, Err(AgentError::IncorrectPassphrase)));
    }

    #[test]
    fn test_store_and_load_key() {
        let (storage, _temp) = create_test_storage();
        let alias = KeyAlias::new("test-alias").unwrap();
        let identity_did = IdentityDID::new("did:keri:test123");
        let encrypted_data = b"encrypted_key_bytes";

        storage
            .store_key(&alias, &identity_did, KeyRole::Primary, encrypted_data)
            .unwrap();

        let (loaded_did, loaded_role, loaded_data) = storage.load_key(&alias).unwrap();
        assert_eq!(loaded_did, identity_did);
        assert_eq!(loaded_role, KeyRole::Primary);
        assert_eq!(loaded_data, encrypted_data);
    }

    #[test]
    fn test_list_aliases() {
        let (storage, _temp) = create_test_storage();
        let did = IdentityDID::new("did:keri:test");

        storage
            .store_key(
                &KeyAlias::new("alias1").unwrap(),
                &did,
                KeyRole::Primary,
                b"data1",
            )
            .unwrap();
        storage
            .store_key(
                &KeyAlias::new("alias2").unwrap(),
                &did,
                KeyRole::Primary,
                b"data2",
            )
            .unwrap();

        let mut aliases = storage.list_aliases().unwrap();
        aliases.sort();
        assert_eq!(
            aliases,
            vec![
                KeyAlias::new_unchecked("alias1"),
                KeyAlias::new_unchecked("alias2")
            ]
        );
    }

    #[test]
    fn test_list_aliases_for_identity() {
        let (storage, _temp) = create_test_storage();
        let did1 = IdentityDID::new("did:keri:one");
        let did2 = IdentityDID::new("did:keri:two");

        storage
            .store_key(
                &KeyAlias::new("a1").unwrap(),
                &did1,
                KeyRole::Primary,
                b"data1",
            )
            .unwrap();
        storage
            .store_key(
                &KeyAlias::new("a2").unwrap(),
                &did1,
                KeyRole::Primary,
                b"data2",
            )
            .unwrap();
        storage
            .store_key(
                &KeyAlias::new("b1").unwrap(),
                &did2,
                KeyRole::Primary,
                b"data3",
            )
            .unwrap();

        let mut aliases = storage.list_aliases_for_identity(&did1).unwrap();
        aliases.sort();
        assert_eq!(
            aliases,
            vec![KeyAlias::new_unchecked("a1"), KeyAlias::new_unchecked("a2")]
        );
    }

    #[test]
    fn test_delete_key() {
        let (storage, _temp) = create_test_storage();
        let did = IdentityDID::new("did:keri:test");
        let alias = KeyAlias::new("alias").unwrap();

        storage
            .store_key(&alias, &did, KeyRole::Primary, b"data")
            .unwrap();
        assert!(storage.load_key(&alias).is_ok());

        storage.delete_key(&alias).unwrap();
        assert!(matches!(
            storage.load_key(&alias),
            Err(AgentError::KeyNotFound)
        ));
    }

    #[test]
    fn test_get_identity_for_alias() {
        let (storage, _temp) = create_test_storage();
        let did = IdentityDID::new("did:keri:test123");
        let alias = KeyAlias::new("alias").unwrap();

        storage
            .store_key(&alias, &did, KeyRole::Primary, b"data")
            .unwrap();

        let loaded_did = storage.get_identity_for_alias(&alias).unwrap();
        assert_eq!(loaded_did, did);
    }

    #[test]
    fn test_backend_name() {
        let (storage, _temp) = create_test_storage();
        assert_eq!(storage.backend_name(), "encrypted-file");
    }

    #[test]
    fn test_file_format_version() {
        let (storage, _temp) = create_test_storage();
        let did = IdentityDID::new("did:keri:test");

        storage
            .store_key(
                &KeyAlias::new("alias").unwrap(),
                &did,
                KeyRole::Primary,
                b"data",
            )
            .unwrap();

        // Read the raw file and verify format
        let contents = fs::read_to_string(&storage.path).unwrap();
        let encrypted: EncryptedFileFormat = serde_json::from_str(&contents).unwrap();

        assert_eq!(encrypted.version, FILE_FORMAT_VERSION);
        assert!(!encrypted.salt.is_empty());
        assert!(!encrypted.nonce.is_empty());
        assert!(!encrypted.ciphertext.is_empty());
    }

    #[test]
    fn test_missing_password_error() {
        let temp_dir = TempDir::new().unwrap();
        let storage = EncryptedFileStorage::new(temp_dir.path()).unwrap();
        let did = IdentityDID::new_unchecked("did:test".to_string());
        let result = storage.store_key(
            &KeyAlias::new("alias").unwrap(),
            &did,
            KeyRole::Primary,
            b"data",
        );
        assert!(matches!(result, Err(AgentError::MissingPassphrase)));
    }

    #[test]
    fn test_key_not_found() {
        let (storage, _temp) = create_test_storage();

        let result = storage.load_key(&KeyAlias::new("nonexistent").unwrap());
        assert!(matches!(result, Err(AgentError::KeyNotFound)));
    }

    #[test]
    fn test_legacy_key_data_migration() {
        // Simulate old format: (did, b64_key) without role
        let old_json = r#"{"keys":{"my-key":["did:keri:Eabc","dGVzdA=="]}}"#;
        let data: KeyData = serde_json::from_str(old_json).unwrap();
        let entry = data.keys.get("my-key").unwrap();
        match entry {
            KeyEntry::Legacy(did, _b64) => assert_eq!(did, "did:keri:Eabc"),
            KeyEntry::WithRole(..) => panic!("should deserialize as Legacy"),
        }
    }

    #[test]
    fn test_new_key_data_format() {
        let new_json = r#"{"keys":{"my-key":["did:keri:Eabc","primary","dGVzdA=="]}}"#;
        let data: KeyData = serde_json::from_str(new_json).unwrap();
        let entry = data.keys.get("my-key").unwrap();
        match entry {
            KeyEntry::WithRole(did, role, _b64) => {
                assert_eq!(did, "did:keri:Eabc");
                assert_eq!(role, "primary");
            }
            KeyEntry::Legacy(..) => panic!("should deserialize as WithRole"),
        }
    }
}
