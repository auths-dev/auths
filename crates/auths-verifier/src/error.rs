//! Error types for attestation and verification operations.

use crate::core::Capability;
use thiserror::Error;

pub use auths_crypto::AuthsErrorInfo;

/// Errors returned by attestation signing, verification, and related operations.
#[derive(Error, Debug)]
pub enum AttestationError {
    /// Issuer's Ed25519 signature did not verify.
    #[error("Issuer signature verification failed: {0}")]
    IssuerSignatureFailed(String),

    /// Device's Ed25519 signature did not verify.
    #[error("Device signature verification failed: {0}")]
    DeviceSignatureFailed(String),

    /// Attestation has passed its expiry timestamp.
    #[error("Attestation expired on {at}")]
    AttestationExpired {
        /// RFC 3339 formatted expiry timestamp.
        at: String,
    },

    /// Attestation was explicitly revoked.
    #[error("Attestation revoked")]
    AttestationRevoked,

    /// Attestation timestamp is in the future (clock skew).
    #[error("Attestation timestamp {at} is in the future")]
    TimestampInFuture {
        /// RFC 3339 formatted timestamp.
        at: String,
    },

    /// The attestation does not grant the required capability.
    #[error("Missing required capability: required {required:?}, available {available:?}")]
    MissingCapability {
        /// The capability that was required.
        required: Capability,
        /// The capabilities present in the attestation.
        available: Vec<Capability>,
    },

    /// Signing the attestation data failed.
    #[error("Signing failed: {0}")]
    SigningError(String),

    /// DID resolution failed.
    #[error("DID resolution failed: {0}")]
    DidResolutionError(String),

    /// JSON serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Caller provided invalid input data.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// A cryptographic primitive (key parsing, hashing) failed.
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// The JSON input exceeds the allowed size limit.
    #[error("Input too large: {0}")]
    InputTooLarge(String),

    /// An unexpected internal error occurred.
    #[error("Internal error: {0}")]
    InternalError(String),

    /// Organizational attestation signature verification failed.
    #[error("Organizational Attestation verification failed: {0}")]
    OrgVerificationFailed(String),

    /// The organizational attestation has expired.
    #[error("Organizational Attestation expired")]
    OrgAttestationExpired,

    /// DID resolution for the organization failed.
    #[error("Organizational DID resolution failed: {0}")]
    OrgDidResolutionFailed(String),

    /// The identity bundle is older than its declared maximum age.
    #[error("Bundle is {age_secs}s old (max {max_secs}s). Refresh with: auths id export-bundle")]
    BundleExpired {
        /// Actual bundle age in seconds.
        age_secs: u64,
        /// Maximum permitted age in seconds.
        max_secs: u64,
    },

    /// The attestation timestamp is older than the caller-specified maximum age.
    #[error("Attestation is {age_secs}s old (max {max_secs}s)")]
    AttestationTooOld {
        /// Actual attestation age in seconds.
        age_secs: u64,
        /// Maximum permitted age in seconds.
        max_secs: u64,
    },
}

impl AuthsErrorInfo for AttestationError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::IssuerSignatureFailed(_) => "AUTHS_ISSUER_SIG_FAILED",
            Self::DeviceSignatureFailed(_) => "AUTHS_DEVICE_SIG_FAILED",
            Self::AttestationExpired { .. } => "AUTHS_ATTESTATION_EXPIRED",
            Self::AttestationRevoked => "AUTHS_ATTESTATION_REVOKED",
            Self::TimestampInFuture { .. } => "AUTHS_TIMESTAMP_IN_FUTURE",
            Self::MissingCapability { .. } => "AUTHS_MISSING_CAPABILITY",
            Self::SigningError(_) => "AUTHS_SIGNING_ERROR",
            Self::DidResolutionError(_) => "AUTHS_DID_RESOLUTION_ERROR",
            Self::SerializationError(_) => "AUTHS_SERIALIZATION_ERROR",
            Self::InputTooLarge(_) => "AUTHS_INPUT_TOO_LARGE",
            Self::InvalidInput(_) => "AUTHS_INVALID_INPUT",
            Self::CryptoError(_) => "AUTHS_CRYPTO_ERROR",
            Self::InternalError(_) => "AUTHS_INTERNAL_ERROR",
            Self::OrgVerificationFailed(_) => "AUTHS_ORG_VERIFICATION_FAILED",
            Self::OrgAttestationExpired => "AUTHS_ORG_ATTESTATION_EXPIRED",
            Self::OrgDidResolutionFailed(_) => "AUTHS_ORG_DID_RESOLUTION_FAILED",
            Self::BundleExpired { .. } => "AUTHS_BUNDLE_EXPIRED",
            Self::AttestationTooOld { .. } => "AUTHS_ATTESTATION_TOO_OLD",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::IssuerSignatureFailed(_) => {
                Some("Verify the attestation was signed with the correct issuer key")
            }
            Self::DeviceSignatureFailed(_) => Some("Verify the device key matches the attestation"),
            Self::AttestationExpired { .. } => Some("Request a new attestation from the issuer"),
            Self::AttestationRevoked => {
                Some("This device has been revoked; contact the identity admin")
            }
            Self::TimestampInFuture { .. } => Some("Check system clock synchronization"),
            Self::MissingCapability { .. } => {
                Some("Request an attestation with the required capability")
            }
            Self::DidResolutionError(_) => Some("Check that the DID is valid and resolvable"),
            Self::OrgVerificationFailed(_) => {
                Some("Verify organizational identity is properly configured")
            }
            Self::OrgAttestationExpired => {
                Some("Request a new organizational attestation from the admin")
            }
            Self::OrgDidResolutionFailed(_) => {
                Some("Check that the organization's DID is correctly configured")
            }
            // These typically don't have actionable suggestions
            Self::InputTooLarge(_) => {
                Some("Reduce the size of the JSON input or split into smaller batches")
            }
            Self::BundleExpired { .. } => Some(
                "Re-export the bundle: auths id export-bundle --alias <ALIAS> --output bundle.json --max-age-secs <SECS>",
            ),
            Self::AttestationTooOld { .. } => {
                Some("Request a fresh attestation or increase the max_age threshold")
            }
            Self::SigningError(_)
            | Self::SerializationError(_)
            | Self::InvalidInput(_)
            | Self::CryptoError(_)
            | Self::InternalError(_) => None,
        }
    }
}
