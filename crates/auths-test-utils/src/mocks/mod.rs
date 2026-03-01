//! mockall-generated mocks for key port traits.
//!
//! Use these for targeted unit tests that only need one or two behaviors mocked.
//! Reserve [`crate::fakes`] full-state implementations for integration-boundary
//! contract tests.
//!
//! Usage:
//! ```ignore
//! use auths_test_utils::mocks::MockIdentityStorage;
//!
//! let mut mock = MockIdentityStorage::new();
//! mock.expect_load_identity()
//!     .returning(|| Ok(ManagedIdentity { .. }));
//! ```

use auths_id::identity::helpers::ManagedIdentity;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;
use auths_verifier::core::Attestation;
use auths_verifier::types::DeviceDID;
use mockall::mock;

mock! {
    /// Mock for [`IdentityStorage`] — use for single-behavior unit tests.
    pub IdentityStorage {}

    impl IdentityStorage for IdentityStorage {
        fn create_identity(
            &self,
            controller_did: &str,
            metadata: Option<serde_json::Value>,
        ) -> Result<(), anyhow::Error>;

        fn load_identity(&self) -> Result<ManagedIdentity, anyhow::Error>;

        fn get_identity_ref(&self) -> Result<String, anyhow::Error>;
    }
}

mock! {
    /// Mock for [`AttestationSource`] — use for single-behavior unit tests.
    pub AttestationSource {}

    impl AttestationSource for AttestationSource {
        fn load_attestations_for_device(
            &self,
            device_did: &DeviceDID,
        ) -> Result<Vec<Attestation>, anyhow::Error>;

        fn load_all_attestations(&self) -> Result<Vec<Attestation>, anyhow::Error>;

        fn load_all_attestations_paginated(
            &self,
            limit: usize,
            offset: usize,
        ) -> Result<Vec<Attestation>, anyhow::Error>;

        fn discover_device_dids(&self) -> Result<Vec<DeviceDID>, anyhow::Error>;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_core::storage::keychain::IdentityDID;

    #[test]
    fn mock_identity_storage_load_returns_configured_value() {
        let mut mock = MockIdentityStorage::new();
        mock.expect_load_identity().returning(|| {
            Ok(ManagedIdentity {
                controller_did: IdentityDID::new_unchecked("did:keri:Etest".to_string()),
                storage_id: "test-repo".to_string(),
                metadata: None,
            })
        });

        let result = mock.load_identity().unwrap();
        assert_eq!(result.controller_did, "did:keri:Etest");
    }

    #[test]
    fn mock_identity_storage_create_succeeds() {
        let mut mock = MockIdentityStorage::new();
        mock.expect_create_identity().returning(|_, _| Ok(()));

        assert!(mock.create_identity("did:keri:Etest", None).is_ok());
    }

    #[test]
    fn mock_attestation_source_returns_empty_list() {
        let mut mock = MockAttestationSource::new();
        mock.expect_load_all_attestations().returning(|| Ok(vec![]));

        let attestations = mock.load_all_attestations().unwrap();
        assert!(attestations.is_empty());
    }
}
