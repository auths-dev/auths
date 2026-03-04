use auths_core::storage::keychain::IdentityDID;
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ManagedIdentity {
    pub controller_did: IdentityDID,
    pub storage_id: String,
    pub metadata: Option<Value>,
}
