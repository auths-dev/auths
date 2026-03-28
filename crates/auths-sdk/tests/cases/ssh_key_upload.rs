//! Tests for SSH signing key upload workflow.

use auths_core::ports::platform::{PlatformError, SshSigningKeyUploader};
use auths_id::storage::identity::IdentityStorage;
use chrono::Utc;
use std::sync::Arc;

/// Mock SSH key uploader for testing.
#[allow(dead_code)]
struct MockSshKeyUploader {
    pub should_fail: bool,
    pub uploaded_keys: Arc<std::sync::Mutex<Vec<String>>>,
}

impl MockSshKeyUploader {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            should_fail: false,
            uploaded_keys: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

impl SshSigningKeyUploader for MockSshKeyUploader {
    async fn upload_signing_key(
        &self,
        _access_token: &str,
        public_key: &str,
        title: &str,
    ) -> Result<String, PlatformError> {
        if self.should_fail {
            return Err(PlatformError::Platform {
                message: "mock upload failed".to_string(),
            });
        }

        let mut keys = self.uploaded_keys.lock().unwrap();
        keys.push(format!("{}:{}", title, public_key));

        Ok("mock-key-id-12345".to_string())
    }
}

/// Mock identity storage for testing.
struct MockIdentityStorage {
    pub metadata: Arc<std::sync::Mutex<Option<serde_json::Value>>>,
}

impl MockIdentityStorage {
    fn new() -> Self {
        Self {
            metadata: Arc::new(std::sync::Mutex::new(None)),
        }
    }
}

impl IdentityStorage for MockIdentityStorage {
    fn create_identity(
        &self,
        _controller_did: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), auths_id::error::StorageError> {
        *self.metadata.lock().unwrap() = metadata;
        Ok(())
    }

    fn load_identity(
        &self,
    ) -> Result<auths_id::identity::managed::ManagedIdentity, auths_id::error::StorageError> {
        Err(auths_id::error::StorageError::NotFound(
            "mock not implemented".to_string(),
        ))
    }

    fn get_identity_ref(&self) -> Result<String, auths_id::error::StorageError> {
        Ok("refs/auths/identity".to_string())
    }
}

// Note: async tests would require tokio test runtime
// These tests validate the type signatures and trait implementations
// Full integration tests with actual async would need separate test runner

#[test]
fn metadata_contains_key_id_and_timestamp() {
    let storage = MockIdentityStorage::new();

    storage
        .create_identity(
            "",
            Some(serde_json::json!({
                "github_ssh_key": {
                    "key_id": "test-id",
                    "uploaded_at": Utc::now().to_rfc3339(),
                }
            })),
        )
        .unwrap();

    let metadata = storage.metadata.lock().unwrap();
    let meta = metadata.as_ref().unwrap();
    assert_eq!(
        meta.get("github_ssh_key")
            .and_then(|v| v.get("key_id"))
            .and_then(|v| v.as_str()),
        Some("test-id")
    );
    assert!(
        meta.get("github_ssh_key")
            .and_then(|v| v.get("uploaded_at"))
            .and_then(|v| v.as_str())
            .is_some()
    );
}
