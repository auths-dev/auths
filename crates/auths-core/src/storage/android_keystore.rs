//! Android Keystore storage backend (stub implementation).
//!
//! This module provides a placeholder for Android Keystore integration.
//! Full implementation requires a JNI bridge to `java.security.KeyStore`
//! with biometric binding support.
//!
//! Only available on Android targets.

use crate::error::AgentError;
use crate::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};

/// Android Keystore storage backend (stub implementation).
///
/// This is a placeholder that returns `BackendUnavailable` for all operations.
/// Full implementation requires:
///
/// - JNI bridge to `java.security.KeyStore`
/// - Key generation with `PURPOSE_SIGN` and `ALGORITHM_EC`
/// - Biometric binding via `setUserAuthenticationRequired(true)`
/// - Ed25519 support (with P-256 fallback and conversion layer)
///
pub struct AndroidKeystoreStorage {
    #[allow(dead_code)] // stub platform impl — field required for API parity
    service_name: String,
}

impl AndroidKeystoreStorage {
    /// Create a new AndroidKeystoreStorage.
    ///
    /// # Errors
    /// Always returns `AgentError::BackendUnavailable` as this is a stub implementation.
    pub fn new(service_name: &str) -> Result<Self, AgentError> {
        // Return a partially constructed instance - actual operations will fail
        // This allows the type to be used in platform dispatch without immediate failure
        Ok(Self {
            service_name: service_name.to_string(),
        })
    }

    /// Error message for stub methods.
    fn stub_error() -> AgentError {
        AgentError::BackendUnavailable {
            backend: "android-keystore",
            reason: "Android Keystore requires JNI bridge (not yet implemented)".to_string(),
        }
    }
}

impl KeyStorage for AndroidKeystoreStorage {
    fn store_key(
        &self,
        _alias: &KeyAlias,
        _identity_did: &IdentityDID,
        _encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        Err(Self::stub_error())
    }

    fn load_key(&self, _alias: &KeyAlias) -> Result<(IdentityDID, Vec<u8>), AgentError> {
        Err(Self::stub_error())
    }

    fn delete_key(&self, _alias: &KeyAlias) -> Result<(), AgentError> {
        Err(Self::stub_error())
    }

    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        Err(Self::stub_error())
    }

    fn list_aliases_for_identity(
        &self,
        _identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        Err(Self::stub_error())
    }

    fn get_identity_for_alias(&self, _alias: &KeyAlias) -> Result<IdentityDID, AgentError> {
        Err(Self::stub_error())
    }

    fn backend_name(&self) -> &'static str {
        "android-keystore"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_succeeds() {
        let storage = AndroidKeystoreStorage::new("test.service");
        assert!(storage.is_ok());
    }

    #[test]
    fn test_backend_name() {
        let storage = AndroidKeystoreStorage::new("test").unwrap();
        assert_eq!(storage.backend_name(), "android-keystore");
    }

    #[test]
    fn test_store_key_returns_unavailable() {
        let storage = AndroidKeystoreStorage::new("test").unwrap();
        let did = IdentityDID::new("did:keri:test");
        let alias = KeyAlias::new("alias");
        let result = storage.store_key(&alias, &did, b"data");
        assert!(matches!(result, Err(AgentError::BackendUnavailable { .. })));
    }

    #[test]
    fn test_load_key_returns_unavailable() {
        let storage = AndroidKeystoreStorage::new("test").unwrap();
        let alias = KeyAlias::new("alias");
        let result = storage.load_key(&alias);
        assert!(matches!(result, Err(AgentError::BackendUnavailable { .. })));
    }

    #[test]
    fn test_delete_key_returns_unavailable() {
        let storage = AndroidKeystoreStorage::new("test").unwrap();
        let alias = KeyAlias::new("alias");
        let result = storage.delete_key(&alias);
        assert!(matches!(result, Err(AgentError::BackendUnavailable { .. })));
    }

    #[test]
    fn test_list_aliases_returns_unavailable() {
        let storage = AndroidKeystoreStorage::new("test").unwrap();
        let result = storage.list_aliases();
        assert!(matches!(result, Err(AgentError::BackendUnavailable { .. })));
    }

    #[test]
    fn test_list_aliases_for_identity_returns_unavailable() {
        let storage = AndroidKeystoreStorage::new("test").unwrap();
        let did = IdentityDID::new("did:keri:test");
        let result = storage.list_aliases_for_identity(&did);
        assert!(matches!(result, Err(AgentError::BackendUnavailable { .. })));
    }

    #[test]
    fn test_get_identity_for_alias_returns_unavailable() {
        let storage = AndroidKeystoreStorage::new("test").unwrap();
        let alias = KeyAlias::new("alias");
        let result = storage.get_identity_for_alias(&alias);
        assert!(matches!(result, Err(AgentError::BackendUnavailable { .. })));
    }
}
