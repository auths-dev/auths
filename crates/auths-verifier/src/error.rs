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
            Self::IssuerSignatureFailed(_) => "AUTHS-E2001",
            Self::DeviceSignatureFailed(_) => "AUTHS-E2002",
            Self::AttestationExpired { .. } => "AUTHS-E2003",
            Self::AttestationRevoked => "AUTHS-E2004",
            Self::TimestampInFuture { .. } => "AUTHS-E2005",
            Self::MissingCapability { .. } => "AUTHS-E2006",
            Self::SigningError(_) => "AUTHS-E2007",
            Self::DidResolutionError(_) => "AUTHS-E2008",
            Self::SerializationError(_) => "AUTHS-E2009",
            Self::InputTooLarge(_) => "AUTHS-E2010",
            Self::InvalidInput(_) => "AUTHS-E2011",
            Self::CryptoError(_) => "AUTHS-E2012",
            Self::InternalError(_) => "AUTHS-E2013",
            Self::OrgVerificationFailed(_) => "AUTHS-E2014",
            Self::OrgAttestationExpired => "AUTHS-E2015",
            Self::OrgDidResolutionFailed(_) => "AUTHS-E2016",
            Self::BundleExpired { .. } => "AUTHS-E2017",
            Self::AttestationTooOld { .. } => "AUTHS-E2018",
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
            Self::SigningError(_) => {
                Some("The cryptographic signing operation failed; verify key material is valid")
            }
            Self::SerializationError(_) => {
                Some("Failed to serialize/deserialize attestation data; check JSON format")
            }
            Self::InvalidInput(_) => {
                Some("Check the input parameters and ensure they match the expected format")
            }
            Self::CryptoError(_) => {
                Some("A cryptographic operation failed; verify key material is valid")
            }
            Self::InternalError(_) => {
                Some("An unexpected internal error occurred; please report this issue")
            }
        }
    }
}
