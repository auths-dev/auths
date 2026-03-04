use std::sync::Mutex;

use auths_core::storage::keychain::IdentityDID;

use crate::error::StorageError;
use crate::identity::helpers::ManagedIdentity;
use crate::storage::identity::IdentityStorage;

/// In-memory `IdentityStorage` for use in tests.
pub struct FakeIdentityStorage {
    state: Mutex<Option<(String, Option<serde_json::Value>)>>,
}

impl FakeIdentityStorage {
    /// Create an empty `FakeIdentityStorage`.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }
}

impl Default for FakeIdentityStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityStorage for FakeIdentityStorage {
    fn create_identity(
        &self,
        controller_did: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), StorageError> {
        *self.state.lock().unwrap() = Some((controller_did.to_string(), metadata));
        Ok(())
    }

    fn load_identity(&self) -> Result<ManagedIdentity, StorageError> {
        let guard = self.state.lock().unwrap();
        let (did, metadata) = guard
            .as_ref()
            .ok_or_else(|| StorageError::NotFound("no identity stored".into()))?;

        Ok(ManagedIdentity {
            controller_did: IdentityDID::new_unchecked(did.clone()),
            storage_id: "fake".to_string(),
            metadata: metadata.clone(),
        })
    }

    fn get_identity_ref(&self) -> Result<String, StorageError> {
        Ok("refs/auths/identity".to_string())
    }
}
