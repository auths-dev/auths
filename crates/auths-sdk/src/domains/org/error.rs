use auths_core::error::AuthsErrorInfo;
use thiserror::Error;

/// Errors from organization member management workflows.
///
/// Usage:
/// ```ignore
/// match result {
///     Err(OrgError::AdminNotFound { .. }) => { /* 403 Forbidden */ }
///     Err(OrgError::MemberNotFound { .. }) => { /* 404 Not Found */ }
///     Err(e) => return Err(e.into()),
///     Ok(att) => { /* proceed */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OrgError {
    /// No admin matching the given public key was found in the organization.
    #[error("no admin with the given public key found in organization '{org}'")]
    AdminNotFound {
        /// The organization identifier.
        org: String,
    },

    /// The specified member was not found in the organization.
    #[error("member '{did}' not found in organization '{org}'")]
    MemberNotFound {
        /// The organization identifier.
        org: String,
        /// The DID of the member that was not found.
        did: String,
    },

    /// The member has already been revoked.
    #[error("member '{did}' is already revoked")]
    AlreadyRevoked {
        /// The DID of the already-revoked member.
        did: String,
    },

    /// The capability string could not be parsed.
    #[error("invalid capability '{cap}': {reason}")]
    InvalidCapability {
        /// The invalid capability string.
        cap: String,
        /// The reason parsing failed.
        reason: String,
    },

    /// The organization DID is malformed.
    #[error("invalid organization DID: {0}")]
    InvalidDid(String),

    /// The hex-encoded public key is invalid.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// A signing operation failed while creating or revoking an attestation.
    #[error("signing error: {0}")]
    Signing(String),

    /// The identity could not be loaded from storage.
    #[error("identity error: {0}")]
    Identity(String),

    /// A key storage operation failed.
    #[error("key storage error: {0}")]
    KeyStorage(String),

    /// A storage operation failed.
    #[error("storage error: {0}")]
    Storage(#[source] auths_id::storage::registry::backend::RegistryError),

    /// KEL anchoring failed.
    #[error("anchor error: {0}")]
    Anchor(#[from] auths_id::keri::AnchorError),
}

impl AuthsErrorInfo for OrgError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::AdminNotFound { .. } => "AUTHS-E5601",
            Self::MemberNotFound { .. } => "AUTHS-E5602",
            Self::AlreadyRevoked { .. } => "AUTHS-E5603",
            Self::InvalidCapability { .. } => "AUTHS-E5604",
            Self::InvalidDid(_) => "AUTHS-E5605",
            Self::InvalidPublicKey(_) => "AUTHS-E5606",
            Self::Signing(_) => "AUTHS-E5607",
            Self::Identity(_) => "AUTHS-E5608",
            Self::KeyStorage(_) => "AUTHS-E5609",
            Self::Storage(_) => "AUTHS-E5610",
            Self::Anchor(_) => "AUTHS-E5611",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::AdminNotFound { .. } => {
                Some("Verify you are using the correct admin key for this organization")
            }
            Self::MemberNotFound { .. } => {
                Some("Run `auths org list-members` to see current members")
            }
            Self::AlreadyRevoked { .. } => {
                Some("This member has already been revoked from the organization")
            }
            Self::InvalidCapability { .. } => {
                Some("Use a valid capability (e.g., 'sign_commit', 'manage_members', 'admin')")
            }
            Self::InvalidDid(_) => Some("Organization DIDs must be valid did:keri identifiers"),
            Self::InvalidPublicKey(_) => Some("Public keys must be hex-encoded Ed25519 keys"),
            Self::Signing(_) => {
                Some("The signing operation failed; check your key access with `auths key list`")
            }
            Self::Identity(_) => {
                Some("Failed to load identity; run `auths id show` to check identity status")
            }
            Self::KeyStorage(_) => {
                Some("Failed to access key storage; run `auths doctor` to diagnose")
            }
            Self::Storage(_) => {
                Some("Failed to access organization storage; check repository permissions")
            }
            Self::Anchor(_) => Some("KEL anchoring failed; check identity and registry state"),
        }
    }
}
