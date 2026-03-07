//! Windows Credential Manager key storage.
//!
//! Stores keys in Windows Credential Manager using the PasswordVault API.
//! Since PasswordVault has limited enumeration support, we maintain a
//! separate JSON file to track stored aliases.
//!
//! Only available on Windows with the `keychain-windows` feature.

use crate::error::AgentError;
use crate::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use windows::Security::Credentials::{PasswordCredential, PasswordVault};
use windows::core::HSTRING;

/// Maximum credential size in bytes (Windows Credential Manager limit)
const MAX_CREDENTIAL_SIZE: usize = 2048;

/// Alias index file name
const ALIAS_INDEX_FILE: &str = "auths-aliases.json";

/// Windows Credential Manager storage backend.
///
/// Uses the PasswordVault API to store encrypted key data as credentials.
/// Maintains a local JSON file to track aliases since Windows doesn't
/// provide good enumeration APIs.
pub struct WindowsCredentialStorage {
    service_name: String,
    alias_index_path: PathBuf,
}

/// Entry in the alias index, supporting backward-compatible migration.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
#[serde(untagged)]
enum AliasEntry {
    /// New format: (identity_did, role)
    WithRole(String, String),
    /// Legacy format: just identity_did — treated as Primary
    Legacy(String),
}

impl AliasEntry {
    fn did(&self) -> &str {
        match self {
            AliasEntry::WithRole(did, _) | AliasEntry::Legacy(did) => did,
        }
    }

    fn role(&self) -> KeyRole {
        match self {
            AliasEntry::WithRole(_, role_str) => {
                role_str.parse::<KeyRole>().unwrap_or(KeyRole::Primary)
            }
            AliasEntry::Legacy(_) => KeyRole::Primary,
        }
    }
}

/// Index of stored aliases, mapping alias -> alias entry
#[derive(serde::Serialize, serde::Deserialize, Default)]
struct AliasIndex {
    aliases: HashMap<String, AliasEntry>,
}

impl WindowsCredentialStorage {
    /// Create a new WindowsCredentialStorage with the given service name.
    ///
    /// # Arguments
    /// * `service_name` - Application identifier used as part of the credential resource name
    ///
    /// # Errors
    /// Returns `AgentError::BackendInitFailed` if the PasswordVault cannot be initialized.
    pub fn new(service_name: &str) -> Result<Self, AgentError> {
        // Verify we can access the PasswordVault
        let _ = PasswordVault::new().map_err(|e| AgentError::BackendInitFailed {
            backend: "windows-credential-manager",
            error: format!("Failed to initialize PasswordVault: {}", e),
        })?;

        // Get the data directory for the alias index
        let data_dir = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("auths");

        // Ensure directory exists
        if !data_dir.exists() {
            fs::create_dir_all(&data_dir).map_err(|e| AgentError::BackendInitFailed {
                backend: "windows-credential-manager",
                error: format!("Failed to create data directory: {}", e),
            })?;
        }

        let alias_index_path = data_dir.join(ALIAS_INDEX_FILE);

        Ok(Self {
            service_name: service_name.to_string(),
            alias_index_path,
        })
    }

    /// Build the resource name for a credential.
    /// Format: "service_name:alias"
    fn resource_name(&self, alias: &str) -> String {
        format!("{}:{}", self.service_name, alias)
    }

    /// Load the alias index from disk.
    fn load_index(&self) -> AliasIndex {
        if let Ok(data) = fs::read_to_string(&self.alias_index_path) {
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            AliasIndex::default()
        }
    }

    /// Save the alias index to disk.
    fn save_index(&self, index: &AliasIndex) -> Result<(), AgentError> {
        let data = serde_json::to_string_pretty(index).map_err(|e| {
            AgentError::StorageError(format!("Failed to serialize alias index: {}", e))
        })?;
        fs::write(&self.alias_index_path, data)
            .map_err(|e| AgentError::StorageError(format!("Failed to write alias index: {}", e)))?;
        Ok(())
    }

    /// Convert a Windows error to AgentError.
    fn convert_error(e: windows::core::Error, context: &str) -> AgentError {
        let code = e.code().0 as u32;
        // ELEMENT_NOT_FOUND = 0x80070490
        if code == 0x80070490 {
            AgentError::KeyNotFound
        } else {
            AgentError::StorageError(format!("{}: {} (code: 0x{:08X})", context, e, code))
        }
    }
}

impl KeyStorage for WindowsCredentialStorage {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        role: KeyRole,
        encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        let alias = alias.as_str();
        // Check size limit
        if encrypted_key_data.len() > MAX_CREDENTIAL_SIZE {
            return Err(AgentError::CredentialTooLarge {
                max_bytes: MAX_CREDENTIAL_SIZE,
                actual_bytes: encrypted_key_data.len(),
            });
        }

        let vault = PasswordVault::new().map_err(|e| AgentError::BackendInitFailed {
            backend: "windows-credential-manager",
            error: format!("Failed to initialize PasswordVault: {}", e),
        })?;

        let resource = self.resource_name(alias);
        let resource_hstring = HSTRING::from(&resource);
        let username_hstring = HSTRING::from(identity_did.as_str());
        let password_hstring = HSTRING::from(BASE64.encode(encrypted_key_data));

        // Try to remove existing credential first (ignore errors)
        if let Ok(existing) = vault.Retrieve(&resource_hstring, &username_hstring) {
            let _ = vault.Remove(&existing);
        }

        // Create and add the new credential
        let cred = PasswordCredential::CreatePasswordCredential(
            &resource_hstring,
            &username_hstring,
            &password_hstring,
        )
        .map_err(|e| Self::convert_error(e, "Failed to create credential"))?;

        vault
            .Add(&cred)
            .map_err(|e| Self::convert_error(e, "Failed to add credential"))?;

        // Update alias index
        let mut index = self.load_index();
        index.aliases.insert(
            alias.to_string(),
            AliasEntry::WithRole(identity_did.as_str().to_string(), role.to_string()),
        );
        self.save_index(&index)?;

        Ok(())
    }

    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, KeyRole, Vec<u8>), AgentError> {
        let alias = alias.as_str();
        let vault = PasswordVault::new().map_err(|e| AgentError::BackendInitFailed {
            backend: "windows-credential-manager",
            error: format!("Failed to initialize PasswordVault: {}", e),
        })?;

        // Get the identity_did and role from our index
        let index = self.load_index();
        let entry = index.aliases.get(alias).ok_or(AgentError::KeyNotFound)?;
        let identity_did = entry.did().to_string();
        let role = entry.role();

        let resource = self.resource_name(alias);
        let resource_hstring = HSTRING::from(&resource);
        let username_hstring = HSTRING::from(&identity_did);

        // Retrieve the credential
        let cred = vault
            .Retrieve(&resource_hstring, &username_hstring)
            .map_err(|e| Self::convert_error(e, "Failed to retrieve credential"))?;

        // Retrieve the password (which triggers loading the actual password value)
        cred.RetrievePassword()
            .map_err(|e| Self::convert_error(e, "Failed to retrieve password"))?;

        let password = cred
            .Password()
            .map_err(|e| Self::convert_error(e, "Failed to get password"))?
            .to_string();

        let key_data = BASE64
            .decode(&password)
            .map_err(|e| AgentError::StorageError(format!("Invalid key encoding: {}", e)))?;

        Ok((IdentityDID::new_unchecked(identity_did), role, key_data))
    }

    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
        let alias = alias.as_str();
        let vault = PasswordVault::new().map_err(|e| AgentError::BackendInitFailed {
            backend: "windows-credential-manager",
            error: format!("Failed to initialize PasswordVault: {}", e),
        })?;

        // Get the identity_did from our index
        let mut index = self.load_index();
        if let Some(entry) = index.aliases.get(alias).cloned() {
            let identity_did = entry.did().to_string();
            let resource = self.resource_name(alias);
            let resource_hstring = HSTRING::from(&resource);
            let username_hstring = HSTRING::from(&identity_did);

            // Try to remove the credential
            if let Ok(cred) = vault.Retrieve(&resource_hstring, &username_hstring) {
                let _ = vault.Remove(&cred);
            }
        }

        // Remove from index regardless
        index.aliases.remove(alias);
        self.save_index(&index)?;

        Ok(())
    }

    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        let index = self.load_index();
        Ok(index
            .aliases
            .keys()
            .map(|s| KeyAlias::new_unchecked(s.clone()))
            .collect())
    }

    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        let index = self.load_index();
        Ok(index
            .aliases
            .iter()
            .filter(|(_, entry)| entry.did() == identity_did.as_str())
            .map(|(alias, _)| KeyAlias::new_unchecked(alias.clone()))
            .collect())
    }

    fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        let alias = alias.as_str();
        let index = self.load_index();
        index
            .aliases
            .get(alias)
            .map(|entry| IdentityDID::new_unchecked(entry.did().to_string()))
            .ok_or(AgentError::KeyNotFound)
    }

    fn backend_name(&self) -> &'static str {
        "windows-credential-manager"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_name() {
        let storage = WindowsCredentialStorage {
            service_name: "dev.auths.agent".to_string(),
            alias_index_path: PathBuf::from("test.json"),
        };
        assert_eq!(storage.resource_name("my-key"), "dev.auths.agent:my-key");
    }

    #[test]
    fn test_backend_name() {
        let storage = WindowsCredentialStorage {
            service_name: "test".to_string(),
            alias_index_path: PathBuf::from("test.json"),
        };
        assert_eq!(storage.backend_name(), "windows-credential-manager");
    }

    #[test]
    fn test_size_limit_constant() {
        assert_eq!(MAX_CREDENTIAL_SIZE, 2048);
    }
}
