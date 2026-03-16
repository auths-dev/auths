//! Fake namespace verifier for testing SDK workflows.

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use url::Url;

use auths_core::ports::namespace::{
    Ecosystem, NamespaceOwnershipProof, NamespaceVerifier, NamespaceVerifyError, PackageName,
    PlatformContext, VerificationChallenge, VerificationMethod, VerificationToken,
};
use auths_verifier::CanonicalDid;

/// Configurable fake verifier for testing namespace verification workflows.
pub struct FakeNamespaceVerifier {
    /// The ecosystem this fake handles.
    pub ecosystem: Ecosystem,
    /// Whether `verify()` should succeed.
    pub should_verify: bool,
    /// Instructions text returned by `initiate()`.
    pub challenge_instructions: String,
}

impl FakeNamespaceVerifier {
    /// Create a fake that always succeeds verification.
    pub fn succeeding(ecosystem: Ecosystem) -> Self {
        Self {
            ecosystem,
            should_verify: true,
            challenge_instructions: "Test: complete the verification".to_string(),
        }
    }

    /// Create a fake that always fails verification.
    pub fn failing(ecosystem: Ecosystem) -> Self {
        Self {
            ecosystem,
            should_verify: false,
            challenge_instructions: "Test: this will fail".to_string(),
        }
    }
}

#[async_trait]
impl NamespaceVerifier for FakeNamespaceVerifier {
    fn ecosystem(&self) -> Ecosystem {
        self.ecosystem
    }

    async fn initiate(
        &self,
        now: DateTime<Utc>,
        package_name: &PackageName,
        did: &CanonicalDid,
        _platform: &PlatformContext,
    ) -> Result<VerificationChallenge, NamespaceVerifyError> {
        // INVARIANT: test token is always valid
        #[allow(clippy::expect_used)]
        let token =
            VerificationToken::parse("auths-verify-deadbeef01234567").expect("test token is valid");

        Ok(VerificationChallenge {
            ecosystem: self.ecosystem,
            package_name: package_name.clone(),
            did: did.clone(),
            token,
            instructions: self.challenge_instructions.clone(),
            expires_at: now + Duration::hours(1),
        })
    }

    async fn verify(
        &self,
        now: DateTime<Utc>,
        package_name: &PackageName,
        _did: &CanonicalDid,
        _platform: &PlatformContext,
        _challenge: &VerificationChallenge,
    ) -> Result<NamespaceOwnershipProof, NamespaceVerifyError> {
        if self.should_verify {
            // INVARIANT: hardcoded test URL is valid
            #[allow(clippy::expect_used)]
            let proof_url =
                Url::parse("https://test.example.com/proof").expect("test URL is valid");

            Ok(NamespaceOwnershipProof {
                ecosystem: self.ecosystem,
                package_name: package_name.clone(),
                proof_url,
                method: VerificationMethod::ApiOwnership,
                verified_at: now,
            })
        } else {
            Err(NamespaceVerifyError::OwnershipNotConfirmed {
                ecosystem: self.ecosystem,
                package_name: package_name.as_str().to_string(),
            })
        }
    }
}
