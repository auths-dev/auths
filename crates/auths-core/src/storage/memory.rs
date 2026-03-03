//! In-memory key storage for testing.

// Defauly memory fallback for non-iOS and non-macOS devices
use crate::error::AgentError;
use crate::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// An in-memory key storage implementation for fallback or testing.
#[derive(Default)]
pub struct MemoryStorage {
    /// Internal mapping of alias -> (identity_did, encrypted_key_bytes)
    data: HashMap<String, (IdentityDID, Vec<u8>)>,
}

impl std::fmt::Debug for MemoryStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryStorage")
            .field("key_count", &self.data.len())
            .finish()
    }
}

/// Global singleton memory store.
pub static MEMORY_KEYCHAIN: Lazy<Mutex<MemoryStorage>> =
    Lazy::new(|| Mutex::new(MemoryStorage::default()));

/// A handle that interacts with the global in-memory keychain.
/// Safe to use in tests or fallback environments.
#[derive(Debug, Clone, Copy)]
pub struct MemoryKeychainHandle;

impl MemoryStorage {
    /// Stores a key under the given alias.
    pub fn store_key(
        &mut self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        self.data.insert(
            alias.as_str().to_string(),
            (identity_did.clone(), encrypted_key_data.to_vec()),
        );
        Ok(())
    }

    /// Loads the key data for the given alias.
    pub fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, Vec<u8>), AgentError> {
        self.data
            .get(alias.as_str())
            .cloned()
            .ok_or(AgentError::KeyNotFound)
    }

    /// Deletes the key stored under the given alias.
    pub fn delete_key(&mut self, alias: &KeyAlias) -> Result<(), AgentError> {
        self.data.remove(alias.as_str());
        Ok(())
    }

    /// Lists all stored aliases.
    pub fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        Ok(self
            .data
            .keys()
            .map(|k| KeyAlias::new_unchecked(k.clone()))
            .collect())
    }

    /// Lists aliases associated with a specific identity.
    pub fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        let aliases = self
            .data
            .iter()
            .filter_map(|(alias, (did, _))| {
                if did == identity_did {
                    Some(KeyAlias::new_unchecked(alias.clone()))
                } else {
                    None
                }
            })
            .collect();
        Ok(aliases)
    }

    /// Returns the identity DID associated with the given alias.
    pub fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        self.data
            .get(alias.as_str())
            .map(|(did, _)| did.clone())
            .ok_or(AgentError::KeyNotFound)
    }

    /// Removes all stored keys.
    pub fn clear_all(&mut self) -> Result<(), AgentError> {
        self.data.clear();
        Ok(())
    }

    /// Returns the storage backend name.
    pub fn backend_name(&self) -> &'static str {
        "Memory"
    }
}

impl KeyStorage for MemoryKeychainHandle {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        MEMORY_KEYCHAIN
            .lock()
            .unwrap()
            .store_key(alias, identity_did, encrypted_key_data)
    }

    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, Vec<u8>), AgentError> {
        MEMORY_KEYCHAIN.lock().unwrap().load_key(alias)
    }

    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
        MEMORY_KEYCHAIN.lock().unwrap().delete_key(alias)
    }

    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        MEMORY_KEYCHAIN.lock().unwrap().list_aliases()
    }

    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        MEMORY_KEYCHAIN
            .lock()
            .unwrap()
            .list_aliases_for_identity(identity_did)
    }

    fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        MEMORY_KEYCHAIN
            .lock()
            .unwrap()
            .get_identity_for_alias(alias)
    }

    fn backend_name(&self) -> &'static str {
        "Memory"
    }
}

/// A per-instance in-memory keychain that does NOT share the global singleton.
///
/// Args:
/// * (none — carries its own `Arc<Mutex<MemoryStorage>>`)
///
/// Usage:
/// ```rust,ignore
/// let kc = IsolatedKeychainHandle::new();
/// kc.store_key(&alias, &did, &data)?;
/// ```
#[derive(Debug, Clone)]
pub struct IsolatedKeychainHandle {
    store: Arc<Mutex<MemoryStorage>>,
}

impl IsolatedKeychainHandle {
    /// Creates a fresh, empty isolated keychain.
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(MemoryStorage::default())),
        }
    }
}

impl Default for IsolatedKeychainHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStorage for IsolatedKeychainHandle {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        self.store
            .lock()
            .unwrap()
            .store_key(alias, identity_did, encrypted_key_data)
    }

    fn load_key(&self, alias: &KeyAlias) -> Result<(IdentityDID, Vec<u8>), AgentError> {
        self.store.lock().unwrap().load_key(alias)
    }

    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
        self.store.lock().unwrap().delete_key(alias)
    }

    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        self.store.lock().unwrap().list_aliases()
    }

    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        self.store
            .lock()
            .unwrap()
            .list_aliases_for_identity(identity_did)
    }

    fn get_identity_for_alias(&self, alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        self.store.lock().unwrap().get_identity_for_alias(alias)
    }

    fn backend_name(&self) -> &'static str {
        "IsolatedMemory"
    }
}

/// Returns a cleared memory keychain handle, used in tests.
#[cfg(any(test, feature = "test-utils"))]
pub fn get_test_memory_keychain() -> Box<dyn KeyStorage + Send + Sync> {
    MEMORY_KEYCHAIN.lock().unwrap().clear_all().ok();
    Box::new(MemoryKeychainHandle)
}
