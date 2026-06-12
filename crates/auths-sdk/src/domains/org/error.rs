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

    /// The organization's controller threshold is `kt≥2` (multi-signature).
    /// KERI-native member delegation currently anchors single-author (`kt=1`)
    /// interaction events only; multi-sig org anchoring is a tracked follow-up.
    #[error(
        "organization '{org}' uses a multi-signature controller (kt≥2); KERI-native member delegation requires a single-signature (kt=1) org"
    )]
    OrgThresholdDelegationUnsupported {
        /// The organization identifier.
        org: String,
    },

    /// A key already exists under the requested member alias — minting a member
    /// there would clobber an existing delegated key. Choose a fresh alias.
    #[error("a member key already exists under alias '{alias}'")]
    MemberKeyExists {
        /// The keychain alias already in use.
        alias: String,
    },

    /// The supplied member identity is not a delegated identifier of this org —
    /// its delegated inception (`dip`) does not name the org as delegator, so the
    /// org cannot off-board it. Fail closed.
    #[error("member '{did}' is not a delegated identifier of organization '{org}'")]
    MemberNotDelegable {
        /// The member's `did:keri:`.
        did: String,
        /// The organization identifier.
        org: String,
    },

    /// A cryptographic operation failed (e.g. resolving the org key's curve).
    #[error("crypto error: {0}")]
    CryptoError(#[source] auths_core::AgentError),

    /// Authoring or anchoring the member's delegated identifier failed.
    #[error("member delegation failed: {0}")]
    Delegation(#[source] auths_id::error::InitError),

    /// An identity already exists where the org would be created — refusing to
    /// clobber it.
    #[error("an identity already exists at {location}; refusing to create an organization over it")]
    IdentityExists {
        /// Where the existing identity was found (repository path or registry).
        location: String,
    },

    /// Initializing the organization's KERI identity failed.
    #[error("failed to initialize organization identity: {0}")]
    IdentityInit(#[source] auths_id::error::InitError),

    /// Creating the organization's admin self-attestation failed.
    #[error("failed to create admin attestation: {0}")]
    Attestation(#[source] auths_verifier::error::AttestationError),

    /// An air-gapped bundle failed offline verification (tampered event, missing
    /// member KEL, missing delegation seal, or an invalid off-boarding record).
    /// The fail-closed detail is the typed [`auths_verifier::org_bundle::OrgBundleError`].
    #[error(transparent)]
    Bundle(#[from] auths_verifier::org_bundle::OrgBundleError),

    /// The supplied org policy did not parse or compile (invalid JSON, an invalid
    /// DID/capability/glob, or it exceeds the policy size/complexity bounds). A
    /// policy that does not compile is never anchored — fail closed.
    #[error("invalid org policy: {reason}")]
    PolicyCompile {
        /// The compile/parse failure(s).
        reason: String,
    },

    /// The org KEL anchors a policy hash but its content-addressed blob is missing —
    /// the policy cannot be loaded, so authority cannot be evaluated. Fail closed.
    #[error("org policy blob for hash '{hash}' is missing from storage")]
    PolicyBlobMissing {
        /// The policy source-hash anchored on the org KEL.
        hash: String,
    },

    /// The loaded policy blob does not hash to the value the org KEL committed — the
    /// blob was tampered with after anchoring. Fail closed.
    #[error(
        "org policy integrity failure: KEL committed hash '{expected}' but the stored blob hashes to '{actual}'"
    )]
    PolicyIntegrity {
        /// The hash anchored on the org KEL.
        expected: String,
        /// The recomputed hash of the stored blob.
        actual: String,
    },

    /// A delegation chain walk followed a `di` link back to an identifier already on
    /// the chain — a cyclic/malformed delegation. Fail closed (no infinite loop).
    #[error("delegation chain cycle detected at '{did}'")]
    ChainCycle {
        /// The identifier the cycle returned to.
        did: String,
    },

    /// A delegation chain exceeds the maximum hop depth the walker will follow.
    #[error("delegation chain exceeds the maximum depth of {max} hops")]
    ChainTooDeep {
        /// The maximum number of hops allowed.
        max: u32,
    },

    /// A delegation chain names a delegator/identifier whose KEL is absent from
    /// storage — the chain cannot be reconstructed. Fail closed.
    #[error("delegation chain is broken: no KEL found for '{did}'")]
    ChainBrokenHop {
        /// The identifier whose KEL is missing.
        did: String,
    },
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
            Self::OrgThresholdDelegationUnsupported { .. } => "AUTHS-E5612",
            Self::MemberKeyExists { .. } => "AUTHS-E5613",
            Self::MemberNotDelegable { .. } => "AUTHS-E5618",
            Self::CryptoError(e) => e.error_code(),
            Self::Delegation(_) => "AUTHS-E5614",
            Self::IdentityExists { .. } => "AUTHS-E5615",
            Self::IdentityInit(_) => "AUTHS-E5616",
            Self::Attestation(_) => "AUTHS-E5617",
            Self::Bundle(e) => e.error_code(),
            Self::PolicyCompile { .. } => "AUTHS-E5622",
            Self::PolicyBlobMissing { .. } => "AUTHS-E5623",
            Self::PolicyIntegrity { .. } => "AUTHS-E5624",
            Self::ChainCycle { .. } => "AUTHS-E5625",
            Self::ChainTooDeep { .. } => "AUTHS-E5626",
            Self::ChainBrokenHop { .. } => "AUTHS-E5627",
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
            Self::OrgThresholdDelegationUnsupported { .. } => Some(
                "Multi-signature org anchoring is not yet supported; use a single-signature (kt=1) org",
            ),
            Self::MemberKeyExists { .. } => Some(
                "Choose a different member alias; run `auths org list-members` to see existing members",
            ),
            Self::MemberNotDelegable { .. } => Some(
                "The member must first incept a delegated identity naming this org as delegator (pairing) before it can be off-boarded",
            ),
            Self::CryptoError(e) => e.suggestion(),
            Self::Delegation(_) => Some(
                "The member delegation could not be authored or anchored; check the org identity",
            ),
            Self::IdentityExists { .. } => Some(
                "An identity already exists here; use a fresh repository path to create a new organization",
            ),
            Self::IdentityInit(_) => {
                Some("Failed to initialize the org identity; check key access and repository state")
            }
            Self::Attestation(_) => Some(
                "Failed to sign the admin attestation; check your key access with `auths key list`",
            ),
            Self::Bundle(e) => e.suggestion(),
            Self::PolicyCompile { .. } => Some(
                "Fix the policy JSON (a serialized `Expr`); see `auths org policy show` for the current policy",
            ),
            Self::PolicyBlobMissing { .. } => {
                Some("The policy blob is missing; re-anchor it with `auths org policy set`")
            }
            Self::PolicyIntegrity { .. } => Some(
                "The stored policy was modified after anchoring; re-anchor a trusted policy with `auths org policy set`",
            ),
            Self::ChainCycle { .. } => {
                Some("The delegation chain is malformed (a cycle); inspect the identifiers' KELs")
            }
            Self::ChainTooDeep { .. } => {
                Some("The delegation chain is too deep; reduce delegation nesting")
            }
            Self::ChainBrokenHop { .. } => Some(
                "A KEL in the delegation chain is missing; ensure all delegators' KELs are present",
            ),
        }
    }
}
