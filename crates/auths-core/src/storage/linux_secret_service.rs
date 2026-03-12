//! Linux Secret Service key storage using D-Bus.
//!
//! Stores keys in GNOME Keyring, KWallet, or KeePassXC via the
//! freedesktop.org Secret Service API.
//!
//! Only available on Linux with the `keychain-linux-secretservice` feature.

use crate::error::AgentError;
use crate::storage::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use secret_service::{EncryptionType, SecretService};
use std::collections::HashMap;

/// Service attribute key for identifying our application
const ATTR_SERVICE: &str = "service";
/// Attribute key for the key alias
const ATTR_ALIAS: &str = "alias";
/// Attribute key for the identity DID
const ATTR_IDENTITY: &str = "identity";
/// Attribute key for the key role
const ATTR_ROLE: &str = "role";

/// Linux Secret Service storage backend.
///
/// Uses D-Bus to communicate with a Secret Service provider (GNOME Keyring,
/// KWallet, or KeePassXC).
pub struct LinuxSecretServiceStorage {
    service_name: String,
}

impl LinuxSecretServiceStorage {
    /// Create a new LinuxSecretServiceStorage with the given service name.
    ///
    /// # Arguments
    /// * `service_name` - Application identifier used as an attribute on stored secrets
    ///
    /// # Errors
    /// Returns `AgentError::BackendUnavailable` if the Secret Service is not reachable.
    pub fn new(service_name: &str) -> Result<Self, AgentError> {
        // Verify we can connect to the Secret Service
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                SecretService::connect(EncryptionType::Dh)
                    .await
                    .map_err(|e| AgentError::BackendUnavailable {
                        backend: "linux-secret-service",
                        reason: format!("Failed to connect to Secret Service: {}", e),
                    })?;
                Ok::<_, AgentError>(())
            })
        })?;

        Ok(Self {
            service_name: service_name.to_string(),
        })
    }

    /// Check if the Secret Service is available on this system.
    ///
    /// Returns `true` if we can connect to the Secret Service via D-Bus.
    pub fn is_available() -> bool {
        // Try to get a handle to the current tokio runtime
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return false;
        };

        std::thread::scope(|s| {
            s.spawn(|| {
                handle.block_on(async { SecretService::connect(EncryptionType::Dh).await.is_ok() })
            })
            .join()
            .unwrap_or(false)
        })
    }

    /// Get the default collection, handling locked state.
    async fn get_collection<'a>(
        &self,
        ss: &'a SecretService<'a>,
    ) -> Result<secret_service::Collection<'a>, AgentError> {
        let collection =
            ss.get_default_collection()
                .await
                .map_err(|e| AgentError::BackendInitFailed {
                    backend: "linux-secret-service",
                    error: format!("Failed to get default collection: {}", e),
                })?;

        // Check if collection is locked
        if collection.is_locked().await.unwrap_or(true) {
            return Err(AgentError::StorageLocked);
        }

        Ok(collection)
    }
}

impl KeyStorage for LinuxSecretServiceStorage {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        role: KeyRole,
        encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        let service_name = self.service_name.clone();
        let alias = alias.as_str().to_string();
        let identity_did = identity_did.as_str().to_string();
        let role_str = role.to_string();
        let data_b64 = BASE64.encode(encrypted_key_data);

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let ss = SecretService::connect(EncryptionType::Dh)
                    .await
                    .map_err(|e| AgentError::BackendUnavailable {
                        backend: "linux-secret-service",
                        reason: format!("Failed to connect: {}", e),
                    })?;

                let collection = self.get_collection(&ss).await?;

                // Store the identity DID and role in the secret value, along with the key data
                // Format: "did|role|base64_key_data" (legacy: "did|base64_key_data")
                let secret_value = format!("{}|{}|{}", identity_did, role_str, data_b64);

                let mut attrs = HashMap::new();
                attrs.insert(ATTR_SERVICE, service_name.as_str());
                attrs.insert(ATTR_ALIAS, alias.as_str());
                attrs.insert(ATTR_IDENTITY, identity_did.as_str());
                attrs.insert(ATTR_ROLE, role_str.as_str());

                // Delete any existing item with this alias first
                let search_attrs: HashMap<&str, &str> = [
                    (ATTR_SERVICE, service_name.as_str()),
                    (ATTR_ALIAS, alias.as_str()),
                ]
                .into_iter()
                .collect();

                if let Ok(items) = ss.search_items(search_attrs.clone()).await {
                    for item in items.unlocked {
                        let _ = item.delete().await;
                    }
                }

                // Create the new item
                let label = format!("Auths key: {}", alias);
                collection
                    .create_item(
                        &label,
                        attrs,
                        secret_value.as_bytes(),
                        true, // replace if exists
                        "text/plain",
                    )
                    .await
                    .map_err(|e| AgentError::StorageError(format!("Failed to store key: {}", e)))?;

                Ok(())
            })
        })
    }

    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, KeyRole, Vec<u8>), AgentError> {
        let service_name = self.service_name.clone();
        let alias = alias.as_str().to_string();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let ss = SecretService::connect(EncryptionType::Dh)
                    .await
                    .map_err(|e| AgentError::BackendUnavailable {
                        backend: "linux-secret-service",
                        reason: format!("Failed to connect: {}", e),
                    })?;

                let attrs: HashMap<&str, &str> = [
                    (ATTR_SERVICE, service_name.as_str()),
                    (ATTR_ALIAS, alias.as_str()),
                ]
                .into_iter()
                .collect();

                let items = ss.search_items(attrs).await.map_err(|e| {
                    AgentError::StorageError(format!("Failed to search items: {}", e))
                })?;

                let item = items
                    .unlocked
                    .into_iter()
                    .next()
                    .ok_or(AgentError::KeyNotFound)?;

                let secret = item.get_secret().await.map_err(|e| {
                    if e.to_string().contains("locked") {
                        AgentError::StorageLocked
                    } else {
                        AgentError::StorageError(format!("Failed to get secret: {}", e))
                    }
                })?;

                let secret_str = String::from_utf8(secret).map_err(|e| {
                    AgentError::StorageError(format!("Invalid secret encoding: {}", e))
                })?;

                // Parse "did|role|base64_key_data" (new) or "did|base64_key_data" (legacy)
                let parts: Vec<&str> = secret_str.splitn(3, '|').collect();
                let (identity_did, role, key_b64) = match parts.len() {
                    3 => {
                        let role = parts[1].parse::<KeyRole>().unwrap_or(KeyRole::Primary);
                        (
                            #[allow(clippy::disallowed_methods)]
                            // INVARIANT: DID was stored by this keychain impl, already validated on write
                            IdentityDID::new_unchecked(parts[0].to_string()),
                            role,
                            parts[2],
                        )
                    }
                    2 => {
                        // Legacy format: did|base64_key_data
                        (
                            #[allow(clippy::disallowed_methods)]
                            // INVARIANT: DID was stored by this keychain impl, already validated on write
                            IdentityDID::new_unchecked(parts[0].to_string()),
                            KeyRole::Primary,
                            parts[1],
                        )
                    }
                    _ => {
                        return Err(AgentError::StorageError(
                            "Invalid secret format".to_string(),
                        ));
                    }
                };
                let key_data = BASE64.decode(key_b64).map_err(|e| {
                    AgentError::StorageError(format!("Invalid key encoding: {}", e))
                })?;

                Ok((identity_did, role, key_data))
            })
        })
    }

    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
        let service_name = self.service_name.clone();
        let alias = alias.as_str().to_string();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let ss = SecretService::connect(EncryptionType::Dh)
                    .await
                    .map_err(|e| AgentError::BackendUnavailable {
                        backend: "linux-secret-service",
                        reason: format!("Failed to connect: {}", e),
                    })?;

                let attrs: HashMap<&str, &str> = [
                    (ATTR_SERVICE, service_name.as_str()),
                    (ATTR_ALIAS, alias.as_str()),
                ]
                .into_iter()
                .collect();

                let items = ss.search_items(attrs).await.map_err(|e| {
                    AgentError::StorageError(format!("Failed to search items: {}", e))
                })?;

                for item in items.unlocked {
                    item.delete().await.map_err(|e| {
                        AgentError::StorageError(format!("Failed to delete item: {}", e))
                    })?;
                }

                Ok(())
            })
        })
    }

    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        let service_name = self.service_name.clone();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let ss = SecretService::connect(EncryptionType::Dh)
                    .await
                    .map_err(|e| AgentError::BackendUnavailable {
                        backend: "linux-secret-service",
                        reason: format!("Failed to connect: {}", e),
                    })?;

                let attrs: HashMap<&str, &str> = [(ATTR_SERVICE, service_name.as_str())]
                    .into_iter()
                    .collect();

                let items = ss.search_items(attrs).await.map_err(|e| {
                    AgentError::StorageError(format!("Failed to search items: {}", e))
                })?;

                let mut aliases = Vec::new();
                for item in items.unlocked {
                    if let Ok(item_attrs) = item.get_attributes().await
                        && let Some(alias) = item_attrs.get(ATTR_ALIAS)
                    {
                        aliases.push(KeyAlias::new_unchecked(alias.clone()));
                    }
                }

                Ok(aliases)
            })
        })
    }

    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        let service_name = self.service_name.clone();
        let identity_did = identity_did.as_str().to_string();

        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                let ss = SecretService::connect(EncryptionType::Dh)
                    .await
                    .map_err(|e| AgentError::BackendUnavailable {
                        backend: "linux-secret-service",
                        reason: format!("Failed to connect: {}", e),
                    })?;

                let attrs: HashMap<&str, &str> = [
                    (ATTR_SERVICE, service_name.as_str()),
                    (ATTR_IDENTITY, identity_did.as_str()),
                ]
                .into_iter()
                .collect();

                let items = ss.search_items(attrs).await.map_err(|e| {
                    AgentError::StorageError(format!("Failed to search items: {}", e))
                })?;

                let mut aliases = Vec::new();
                for item in items.unlocked {
                    if let Ok(item_attrs) = item.get_attributes().await
                        && let Some(alias) = item_attrs.get(ATTR_ALIAS)
                    {
                        aliases.push(KeyAlias::new_unchecked(alias.clone()));
                    }
                }

                Ok(aliases)
            })
        })
    }

    fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        let (identity_did, _role, _) = self.load_key(alias)?;
        Ok(identity_did)
    }

    fn backend_name(&self) -> &'static str {
        "linux-secret-service"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backend_name() {
        let storage = LinuxSecretServiceStorage {
            service_name: "test".to_string(),
        };
        assert_eq!(storage.backend_name(), "linux-secret-service");
    }
}
