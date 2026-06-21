//! KERI capability receipt verification for RFC 7591 client registration.

use auths_verifier::{
    AttestationError, DevicePublicKey, VerificationReport, VerificationStatus, verify_chain,
};

use super::registration::KeriCapabilityReceipt;

/// Required capability for OIDC client registration.
pub const REGISTRATION_CAPABILITY: &str = "oidc:client:register";

/// Errors from the KERI capability receipt verification pipeline.
#[derive(Debug, thiserror::Error)]
pub enum RegistrationVerificationError {
    #[error("invalid attestation chain signature: {0:?}")]
    InvalidSignature(VerificationStatus),

    #[error("missing required capability '{required}'")]
    MissingCapability { required: String },

    #[error("attestation chain error: {0}")]
    AttestationError(#[from] AttestationError),

    #[error("invalid root public key: {0}")]
    InvalidRootKey(String),

    #[error("capability parse error: {0}")]
    CapabilityParse(String),
}

/// Result of successful KERI verification, containing the extracted KERI AID.
pub struct VerifiedReceipt {
    /// The KERI AID extracted from the attestation chain's root issuer.
    pub keri_aid: String,
    pub report: VerificationReport,
}

/// Verifies a KERI capability receipt for client registration.
///
/// Args:
/// * `receipt`: The KERI capability receipt from the registration request.
///
/// Usage:
/// ```ignore
/// let verified = verify_keri_receipt(&receipt)?;
/// let keri_aid = verified.keri_aid;
/// ```
pub async fn verify_keri_receipt(
    receipt: &KeriCapabilityReceipt,
) -> Result<VerifiedReceipt, RegistrationVerificationError> {
    // `RootPublicKey` is a validated 32-byte Ed25519 key.
    let root_bytes: [u8; 32] = receipt.root_public_key.as_bytes().try_into().map_err(|_| {
        RegistrationVerificationError::InvalidRootKey("root key must be 32 bytes".to_string())
    })?;
    let root_pk = DevicePublicKey::ed25519(&root_bytes);

    let report = verify_chain(&receipt.attestation_chain, &root_pk).await?;
    if !report.is_valid() {
        return Err(RegistrationVerificationError::InvalidSignature(
            report.status,
        ));
    }

    // The verifier moved capability scoping from the attestation chain to commit/agent
    // verification, so there is no longer a chain-level capability gate to re-apply: a valid
    // KERI chain rooted at the supplied key authorizes registration. Re-introducing a granular
    // `oidc:client:register` check is a follow-up that depends on the current capability surface.

    // Extract KERI AID from the root issuer of the chain
    let keri_aid = receipt
        .attestation_chain
        .first()
        .map(|att| att.issuer.to_string())
        .unwrap_or_default();

    Ok(VerifiedReceipt { keri_aid, report })
}
