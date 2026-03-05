//! Org membership validation and listing API.
//!
//! This module provides types and utilities for validating and filtering org members.
//! It replaces filename-based enumeration with validation-aware APIs that:
//! - Parse and validate JSON attestations, not just filenames
//! - Compute revoked/expired/invalid status in one pass
//! - Provide clear contracts for why entries are invalid
//!
//! ## Domain Types (Sans-IO)
//!
//! All types in this module are **pure domain types** with no I/O:
//! - `MemberFilter`: Time is injected via `now: Option<DateTime<Utc>>` (never uses `Utc::now()`)
//! - `MemberStatus`, `MemberStatusKind`: Pure enums
//! - `MemberView`, `OrgMemberEntry`: Pure data structures
//! - `compute_status()`: Pure function taking `now` as parameter
//!
//! ## Structural Invariants (checked during visit)
//!
//! These are **hard errors** that make an entry Invalid:
//! - JSON must parse
//! - `attestation.subject` must match filename DID
//! - `attestation.issuer` must match expected org issuer (`did:keri:{org}`)
//!
//! ## Runtime Status (computed from valid attestations)
//!
//! - Active: not revoked, not expired
//! - Revoked: `att.is_revoked()` (i.e. `revoked_at` is `Some`)
//! - Expired: `att.expires_at <= now`

use std::collections::HashSet;

use auths_core::storage::keychain::IdentityDID;
use auths_verifier::core::{Attestation, Capability, ResourceId, Role};
use auths_verifier::types::DeviceDID;
use chrono::{DateTime, Utc};

/// Filter for querying org members.
#[derive(Debug, Clone)]
pub struct MemberFilter {
    /// Which statuses to include (default: {Active})
    pub include_statuses: HashSet<MemberStatusKind>,
    /// Optional role whitelist - include if member.role is in set
    pub roles_any: Option<HashSet<Role>>,
    /// Include if intersection(member_caps, filter_caps) non-empty
    pub capabilities_any: Option<HashSet<Capability>>,
    /// Include only if filter_caps ⊆ member_caps
    pub capabilities_all: Option<HashSet<Capability>>,
    /// Injectable timestamp for deterministic tests
    pub now: Option<DateTime<Utc>>,
}

// Manual Default: derive(Default) would give empty HashSet = no members
impl Default for MemberFilter {
    fn default() -> Self {
        let mut include_statuses = HashSet::new();
        include_statuses.insert(MemberStatusKind::Active);
        Self {
            include_statuses,
            roles_any: None,
            capabilities_any: None,
            capabilities_all: None,
            now: None,
        }
    }
}

/// Coarse status for filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemberStatusKind {
    Active,
    Revoked,
    Expired,
    Invalid,
}

impl MemberStatusKind {
    /// Rank for deterministic sorting (lower = first)
    pub fn rank(self) -> u8 {
        match self {
            MemberStatusKind::Active => 0,
            MemberStatusKind::Revoked => 1,
            MemberStatusKind::Expired => 2,
            MemberStatusKind::Invalid => 3,
        }
    }
}

/// Detailed status for UI/debugging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberStatus {
    Active,
    Revoked,
    Expired { expires_at: DateTime<Utc> },
    Invalid { reason: MemberInvalidReason },
}

impl MemberStatus {
    pub fn kind(&self) -> MemberStatusKind {
        match self {
            MemberStatus::Active => MemberStatusKind::Active,
            MemberStatus::Revoked => MemberStatusKind::Revoked,
            MemberStatus::Expired { .. } => MemberStatusKind::Expired,
            MemberStatus::Invalid { .. } => MemberStatusKind::Invalid,
        }
    }
}

/// Why a member entry is invalid (structural corruption).
///
/// These are **hard errors** representing structural corruption, not soft warnings.
/// An entry with any of these reasons should be treated as if it doesn't exist
/// for authorization purposes.
///
/// # Protocol Invariants
///
/// - **Subject Integrity**: `attestation.subject` must match the filename DID
/// - **Issuer Integrity**: `attestation.issuer` must match `did:keri:{org}`
///
/// Violating these indicates either data corruption or an attack attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberInvalidReason {
    /// JSON could not be parsed.
    JsonParseError(String),

    /// The attestation's subject DID doesn't match the filename DID.
    ///
    /// This is a **structural integrity violation**. The filename determines
    /// which device/member this attestation is for, and the attestation's
    /// subject field must match.
    SubjectMismatch {
        filename_did: DeviceDID,
        attestation_subject: DeviceDID,
    },

    /// The attestation's issuer DID doesn't match the expected org issuer.
    ///
    /// This is a **structural integrity violation**. Org member attestations
    /// must be issued by `did:keri:{org}`. An attestation with a different
    /// issuer doesn't prove membership in this org.
    IssuerMismatch {
        expected_issuer: IdentityDID,
        actual_issuer: IdentityDID,
    },

    /// Other validation errors (e.g., file read errors).
    Other(String),
}

/// Low-level entry for visit_org_member_attestations.
pub struct OrgMemberEntry {
    pub org: IdentityDID,
    pub did: DeviceDID,
    pub filename: String,
    pub attestation: Result<Attestation, MemberInvalidReason>,
}

/// High-level view for UI/CLI.
///
/// # Status Computation
///
/// For valid attestations, `status` is set to `Active` by the backend.
/// The backend does NOT compute revoked/expired status (that's policy).
///
/// To compute actual status, use:
/// ```ignore
/// let status = if view.revoked_at.is_some() {
///     MemberStatus::Revoked
/// } else if view.expires_at.map(|e| e <= now).unwrap_or(false) {
///     MemberStatus::Expired { expires_at: view.expires_at.unwrap() }
/// } else {
///     MemberStatus::Active
/// };
/// ```
///
/// Or use `compute_status()` from this module with the raw attestation.
#[derive(Debug, Clone)]
pub struct MemberView {
    pub did: DeviceDID,
    /// Status: Active for valid attestations, Invalid for structural errors.
    /// Note: Backend does NOT compute Revoked/Expired - use `revoked_at` and
    /// `expires_at` fields to compute these statuses in the policy layer.
    pub status: MemberStatus,
    pub role: Option<Role>,
    pub capabilities: Vec<Capability>,
    pub issuer: IdentityDID,
    pub rid: ResourceId,
    /// Timestamp when the attestation was revoked (`None` if not revoked).
    pub revoked_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub timestamp: Option<DateTime<Utc>>,
    /// Original filename for debugging invalid entries
    pub source_filename: String,
}

/// Compute status from attestation. Uses <= for expiry boundary.
pub fn compute_status(att: &Attestation, now: DateTime<Utc>) -> MemberStatus {
    if att.is_revoked() {
        MemberStatus::Revoked
    } else if let Some(expires_at) = att.expires_at {
        if expires_at <= now {
            MemberStatus::Expired { expires_at }
        } else {
            MemberStatus::Active
        }
    } else {
        MemberStatus::Active
    }
}

/// Convert a Capability to its canonical string representation.
///
/// This delegates to `Capability::to_string()` which is the authoritative
/// string form. Used for both filtering and display.
pub fn capability_to_string(cap: &auths_verifier::core::Capability) -> String {
    cap.to_string()
}

/// Get capability strings from an attestation as a HashSet (for filtering).
pub fn attestation_capability_strings(att: &Attestation) -> HashSet<String> {
    att.capabilities.iter().map(capability_to_string).collect()
}

/// Get capability strings from an attestation as a Vec (for display).
pub fn attestation_capability_vec(att: &Attestation) -> Vec<String> {
    att.capabilities.iter().map(capability_to_string).collect()
}

/// Compute the expected issuer DID for an org.
pub fn expected_org_issuer(org: &str) -> String {
    format!("did:keri:{}", org)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use auths_verifier::core::{Ed25519PublicKey, Ed25519Signature};

    #[test]
    fn member_filter_defaults_to_active_only() {
        let filter = MemberFilter::default();
        assert!(filter.include_statuses.contains(&MemberStatusKind::Active));
        assert_eq!(filter.include_statuses.len(), 1);
    }

    #[test]
    fn member_status_kind_rank_is_correct() {
        assert!(MemberStatusKind::Active.rank() < MemberStatusKind::Revoked.rank());
        assert!(MemberStatusKind::Revoked.rank() < MemberStatusKind::Expired.rank());
        assert!(MemberStatusKind::Expired.rank() < MemberStatusKind::Invalid.rank());
    }

    #[test]
    fn member_status_kind_returns_correct_kind() {
        assert_eq!(MemberStatus::Active.kind(), MemberStatusKind::Active);
        assert_eq!(MemberStatus::Revoked.kind(), MemberStatusKind::Revoked);
        assert_eq!(
            MemberStatus::Expired {
                expires_at: Utc::now()
            }
            .kind(),
            MemberStatusKind::Expired
        );
        assert_eq!(
            MemberStatus::Invalid {
                reason: MemberInvalidReason::Other("test".into())
            }
            .kind(),
            MemberStatusKind::Invalid
        );
    }

    #[test]
    fn compute_status_active() {
        let att = Attestation {
            version: 1,
            rid: "test".into(),
            issuer: IdentityDID::new("did:key:issuer"),
            subject: DeviceDID::new("did:key:subject"),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
        };
        let now = Utc::now();
        assert_eq!(compute_status(&att, now), MemberStatus::Active);
    }

    #[test]
    fn compute_status_revoked() {
        let att = Attestation {
            version: 1,
            rid: "test".into(),
            issuer: IdentityDID::new("did:key:issuer"),
            subject: DeviceDID::new("did:key:subject"),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: Some(Utc::now()),
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
        };
        let now = Utc::now();
        assert_eq!(compute_status(&att, now), MemberStatus::Revoked);
    }

    #[test]
    fn compute_status_expired() {
        let past = Utc::now() - chrono::Duration::hours(1);
        let att = Attestation {
            version: 1,
            rid: "test".into(),
            issuer: IdentityDID::new("did:key:issuer"),
            subject: DeviceDID::new("did:key:subject"),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: Some(past),
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
        };
        let now = Utc::now();
        assert!(matches!(
            compute_status(&att, now),
            MemberStatus::Expired { .. }
        ));
    }

    #[test]
    fn compute_status_not_expired_yet() {
        let future = Utc::now() + chrono::Duration::hours(1);
        let att = Attestation {
            version: 1,
            rid: "test".into(),
            issuer: IdentityDID::new("did:key:issuer"),
            subject: DeviceDID::new("did:key:subject"),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: Some(future),
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
        };
        let now = Utc::now();
        assert_eq!(compute_status(&att, now), MemberStatus::Active);
    }

    #[test]
    fn compute_status_expired_at_boundary() {
        let now = Utc::now();
        let att = Attestation {
            version: 1,
            rid: "test".into(),
            issuer: IdentityDID::new("did:key:issuer"),
            subject: DeviceDID::new("did:key:subject"),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: Some(now), // Exactly at boundary
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
        };
        // Uses <= for expiry, so exactly at boundary = expired
        assert!(matches!(
            compute_status(&att, now),
            MemberStatus::Expired { .. }
        ));
    }

    #[test]
    fn capability_to_string_works() {
        assert_eq!(
            capability_to_string(&Capability::sign_commit()),
            "sign_commit"
        );
        assert_eq!(
            capability_to_string(&Capability::sign_release()),
            "sign_release"
        );
        assert_eq!(
            capability_to_string(&Capability::manage_members()),
            "manage_members"
        );
        assert_eq!(
            capability_to_string(&Capability::parse("acme:deploy").unwrap()),
            "acme:deploy"
        );
    }

    #[test]
    fn expected_org_issuer_formats_correctly() {
        assert_eq!(
            expected_org_issuer("EOrg1234567890"),
            "did:keri:EOrg1234567890"
        );
    }

    #[test]
    fn attestation_capability_vec_matches_set() {
        let att = Attestation {
            version: 1,
            rid: "test".into(),
            issuer: IdentityDID::new("did:key:issuer"),
            subject: DeviceDID::new("did:key:subject"),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![Capability::sign_commit(), Capability::sign_release()],
            delegated_by: None,
            signer_type: None,
        };

        let vec = attestation_capability_vec(&att);
        let set = attestation_capability_strings(&att);

        // Same elements
        assert_eq!(vec.len(), set.len());
        for cap in &vec {
            assert!(set.contains(cap));
        }
    }
}
