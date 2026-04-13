//! Dependency-injected [`Verifier`] for attestation and chain verification.

use std::sync::Arc;

use auths_crypto::CryptoProvider;

use crate::clock::ClockProvider;
use crate::core::{Attestation, Capability, DevicePublicKey, VerifiedAttestation};
use crate::error::AttestationError;
use crate::types::{DeviceDID, VerificationReport};
use crate::verify;
use crate::witness::WitnessVerifyConfig;

/// Dependency-injected verifier for attestation and chain verification.
///
/// Uses `Arc<dyn CryptoProvider>` and `Arc<dyn ClockProvider>` for
/// lifetime-free sharing across async tasks and web server handler state.
///
/// Usage:
/// ```ignore
/// use std::sync::Arc;
/// use auths_verifier::{Verifier, SystemClock};
/// use auths_crypto::RingCryptoProvider;
///
/// let verifier = Verifier::native();
/// let result = verifier.verify_with_keys(&att, &pk).await;
/// ```
#[derive(Clone)]
pub struct Verifier {
    provider: Arc<dyn CryptoProvider>,
    clock: Arc<dyn ClockProvider>,
}

impl Verifier {
    /// Create a `Verifier` with the given crypto provider and clock.
    ///
    /// Args:
    /// * `provider`: Ed25519 crypto backend.
    /// * `clock`: Clock provider for expiry checks.
    pub fn new(provider: Arc<dyn CryptoProvider>, clock: Arc<dyn ClockProvider>) -> Self {
        Self { provider, clock }
    }

    /// Create a `Verifier` using the native Ring crypto provider and system clock.
    #[cfg(feature = "native")]
    pub fn native() -> Self {
        Self {
            provider: Arc::new(auths_crypto::RingCryptoProvider),
            clock: Arc::new(crate::clock::SystemClock),
        }
    }

    /// Verify an attestation's signatures against the issuer's public key.
    ///
    /// Args:
    /// * `att`: The attestation to verify.
    /// * `issuer_pk`: Typed issuer public key (Ed25519 or P-256).
    pub async fn verify_with_keys(
        &self,
        att: &Attestation,
        issuer_pk: &DevicePublicKey,
    ) -> Result<VerifiedAttestation, AttestationError> {
        verify::verify_with_keys_at(
            att,
            issuer_pk,
            self.clock.now(),
            true,
            self.provider.as_ref(),
        )
        .await?;
        Ok(VerifiedAttestation::from_verified(att.clone()))
    }

    /// Verify an attestation and check that it grants a required capability.
    ///
    /// Args:
    /// * `att`: The attestation to verify.
    /// * `required`: The capability that must be present.
    /// * `issuer_pk`: Typed issuer public key (Ed25519 or P-256).
    pub async fn verify_with_capability(
        &self,
        att: &Attestation,
        required: &Capability,
        issuer_pk: &DevicePublicKey,
    ) -> Result<VerifiedAttestation, AttestationError> {
        let verified = self.verify_with_keys(att, issuer_pk).await?;
        if !att.capabilities.contains(required) {
            return Err(AttestationError::MissingCapability {
                required: required.clone(),
                available: att.capabilities.clone(),
            });
        }
        Ok(verified)
    }

    /// Verify an attestation against a specific point in time (skips clock-skew check).
    ///
    /// Args:
    /// * `att`: The attestation to verify.
    /// * `issuer_pk`: Typed issuer public key (Ed25519 or P-256).
    /// * `at`: The reference timestamp for expiry evaluation.
    pub async fn verify_at_time(
        &self,
        att: &Attestation,
        issuer_pk: &DevicePublicKey,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Result<VerifiedAttestation, AttestationError> {
        verify::verify_with_keys_at(att, issuer_pk, at, false, self.provider.as_ref()).await?;
        Ok(VerifiedAttestation::from_verified(att.clone()))
    }

    /// Verify an ordered attestation chain starting from a known root public key.
    ///
    /// Args:
    /// * `attestations`: Ordered attestation chain (root first).
    /// * `root_pk`: Typed root identity public key (Ed25519 or P-256).
    pub async fn verify_chain(
        &self,
        attestations: &[Attestation],
        root_pk: &DevicePublicKey,
    ) -> Result<VerificationReport, AttestationError> {
        verify::verify_chain_inner(
            attestations,
            root_pk,
            self.provider.as_ref(),
            self.clock.now(),
        )
        .await
    }

    /// Verify a chain and assert that all attestations share a required capability.
    ///
    /// Args:
    /// * `attestations`: Ordered attestation chain (root first).
    /// * `required`: The capability that must appear in every link.
    /// * `root_pk`: Typed root identity public key (Ed25519 or P-256).
    pub async fn verify_chain_with_capability(
        &self,
        attestations: &[Attestation],
        required: &Capability,
        root_pk: &DevicePublicKey,
    ) -> Result<VerificationReport, AttestationError> {
        let report = self.verify_chain(attestations, root_pk).await?;
        if !report.is_valid() {
            return Ok(report);
        }
        if attestations.is_empty() {
            return Ok(report);
        }

        use std::collections::HashSet;
        let mut effective: HashSet<Capability> =
            attestations[0].capabilities.iter().cloned().collect();
        for att in attestations.iter().skip(1) {
            let att_caps: HashSet<Capability> = att.capabilities.iter().cloned().collect();
            effective = effective.intersection(&att_caps).cloned().collect();
        }
        if !effective.contains(required) {
            return Err(AttestationError::MissingCapability {
                required: required.clone(),
                available: effective.into_iter().collect(),
            });
        }
        Ok(report)
    }

    /// Verify a chain and additionally validate witness receipts against a quorum threshold.
    ///
    /// Args:
    /// * `attestations`: Ordered attestation chain (root first).
    /// * `root_pk`: Typed root identity public key (Ed25519 or P-256).
    /// * `witness_config`: Witness receipts and quorum threshold to validate.
    pub async fn verify_chain_with_witnesses(
        &self,
        attestations: &[Attestation],
        root_pk: &DevicePublicKey,
        witness_config: &WitnessVerifyConfig<'_>,
    ) -> Result<VerificationReport, AttestationError> {
        let mut report = self.verify_chain(attestations, root_pk).await?;
        if !report.is_valid() {
            return Ok(report);
        }

        let quorum =
            crate::witness::verify_witness_receipts(witness_config, self.provider.as_ref()).await;
        if quorum.verified < quorum.required {
            report.status = crate::types::VerificationStatus::InsufficientWitnesses {
                required: quorum.required,
                verified: quorum.verified,
            };
            report.warnings.push(format!(
                "Witness quorum not met: {}/{} verified",
                quorum.verified, quorum.required
            ));
        }
        report.witness_quorum = Some(quorum);
        Ok(report)
    }

    /// Verify that a specific device is authorized under a given identity.
    ///
    /// Args:
    /// * `identity_did`: The DID of the authorizing identity.
    /// * `device_did`: The device DID to check authorization for.
    /// * `attestations`: Pool of attestations to search.
    /// * `identity_pk`: Typed identity public key (Ed25519 or P-256).
    pub async fn verify_device_authorization(
        &self,
        identity_did: &str,
        device_did: &DeviceDID,
        attestations: &[Attestation],
        identity_pk: &DevicePublicKey,
    ) -> Result<VerificationReport, AttestationError> {
        verify::verify_device_authorization_inner(
            identity_did,
            device_did,
            attestations,
            identity_pk,
            self.provider.as_ref(),
            self.clock.now(),
        )
        .await
    }
}
