//! Registry backend trait and error types.
//!
//! # Architecture: Cache/Index, Not Source of Truth
//!
//! The registry is an **indexed materialized view** for performance:
//!
//! - **Identity KEL (Key Event Log)** = source of truth
//!   - Events in `v1/identities/<shard>/<prefix>/events/` are canonical
//!   - All other state is derived from the KEL
//!
//! - **Registry** = cached index for O(1) lookups
//!   - `state.json`, `tip.json` are performance caches
//!   - Can be rebuilt from KEL at any time
//!   - NOT authoritative for trust or authorization decisions
//!
//! - **Backend validates structure, not trust**
//!   - Backends may validate JSON structure, SAID integrity
//!   - Backends may NOT decide trust, authorization, or expiry
//!   - Policy engine (separate layer) handles authorization
//!
//! This separation ensures backends remain testable, replaceable, and
//! free from policy coupling.
//!
//! # Overwrite Semantics
//!
//! Different data types have different overwrite semantics:
//!
//! | Data Type | Semantic | Behavior |
//! |-----------|----------|----------|
//! | KEL Events | **Append-only** | Once written, immutable. `append_event()` refuses overwrites. |
//! | Device Attestations | **Latest-view** | `store_attestation()` overwrites existing. History in `attestation_history/`. |
//! | Org Member Attestations | **Latest-view** | `store_org_member()` overwrites existing for same member DID. |
//!
//! The "latest-view" pattern means the current file represents only the latest state.
//! Historical data is preserved separately for audit purposes.

use std::collections::HashSet;
use std::ops::ControlFlow;
use std::sync::Arc;

use auths_core::storage::keychain::IdentityDID;
use auths_verifier::core::{Attestation, Capability};
use auths_verifier::types::DeviceDID;
use thiserror::Error;

use crate::keri::Prefix;
use crate::keri::event::Event;
use crate::keri::state::KeyState;

use super::org_member::{MemberFilter, MemberStatus, MemberView, OrgMemberEntry};
use super::schemas::{RegistryMetadata, TipInfo};

/// Specific reasons a tenant ID is rejected.
///
/// `PathTraversal` is intentionally absent: the strict allowlist
/// (`[a-z0-9_-]`) makes traversal components unexpressible.
/// If the allowed charset expands (e.g. to include `.`), reintroduce
/// an explicit traversal check before adding it to the allowlist.
#[derive(Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum TenantIdError {
    /// ID is empty or exceeds 64 characters.
    #[error("must be 1–64 characters (got {0})")]
    InvalidLength(usize),

    /// ID contains a character outside `[a-z0-9_-]`.
    /// Carries the first offending character for precise error messages.
    #[error("contains disallowed character {0:?} (only [a-z0-9_-] allowed)")]
    InvalidCharacter(char),

    /// ID matches a reserved route segment or system name.
    #[error("'{0}' is reserved")]
    Reserved(String),
}

impl auths_core::error::AuthsErrorInfo for TenantIdError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidLength(_) => "AUTHS-E4851",
            Self::InvalidCharacter(_) => "AUTHS-E4852",
            Self::Reserved(_) => "AUTHS-E4853",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::InvalidLength(_) => Some("Tenant ID must be between 1 and 64 characters"),
            Self::InvalidCharacter(_) => {
                Some("Only lowercase letters, digits, hyphens, and underscores are allowed")
            }
            Self::Reserved(_) => Some("Choose a different tenant ID; this name is reserved"),
        }
    }
}

/// A tenant identifier that has been normalized (lowercased) and validated.
///
/// Construct via [`ValidatedTenantId::new`] which enforces:
/// - Length 1–64 characters
/// - Only `[a-z0-9_-]` characters (input is lowercased before checking)
/// - Not a reserved name (`admin`, `health`, `metrics`)
///
/// Passing this type through boundaries guarantees the ID is safe for
/// filesystem paths without further checking.
///
/// Usage:
/// ```ignore
/// let tid = ValidatedTenantId::new("Acme")?;
/// assert_eq!(tid.as_str(), "acme");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidatedTenantId(String);

/// Reserved names that collide with current or planned API route segments.
const RESERVED_TENANT_IDS: &[&str] = &["admin", "health", "metrics"];

impl ValidatedTenantId {
    /// Normalize and validate a raw tenant identifier.
    ///
    /// Input is lowercased, then checked against the validation rules.
    pub fn new(raw: impl Into<String>) -> Result<Self, RegistryError> {
        let normalized = raw.into().to_lowercase();
        validate_tenant_id_inner(&normalized)?;
        Ok(Self(normalized))
    }

    /// Returns the canonical (lowercase) tenant ID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ValidatedTenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ValidatedTenantId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<ValidatedTenantId> for String {
    fn from(tid: ValidatedTenantId) -> Self {
        tid.0
    }
}

fn validate_tenant_id_inner(tenant_id: &str) -> Result<(), RegistryError> {
    let len = tenant_id.len();
    if len == 0 || len > 64 {
        return Err(RegistryError::InvalidTenantId {
            tenant_id: tenant_id.into(),
            kind: TenantIdError::InvalidLength(len),
        });
    }
    if let Some(bad_char) = tenant_id
        .chars()
        .find(|c| !matches!(c, 'a'..='z' | '0'..='9' | '-' | '_'))
    {
        return Err(RegistryError::InvalidTenantId {
            tenant_id: tenant_id.into(),
            kind: TenantIdError::InvalidCharacter(bad_char),
        });
    }
    if RESERVED_TENANT_IDS.contains(&tenant_id) {
        return Err(RegistryError::InvalidTenantId {
            tenant_id: tenant_id.into(),
            kind: TenantIdError::Reserved(tenant_id.into()),
        });
    }
    Ok(())
}

/// Errors that can occur during registry operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// Storage backend operation failed
    #[error("Storage error: {0}")]
    Storage(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Invalid KERI prefix format
    #[error("Invalid prefix '{prefix}': {reason}")]
    InvalidPrefix { prefix: String, reason: String },

    /// Invalid device DID format
    #[error("Invalid device DID '{did}': {reason}")]
    InvalidDeviceDid { did: String, reason: String },

    /// Event already exists at this sequence number
    #[error("Event already exists: {prefix} seq {seq}")]
    EventExists { prefix: String, seq: u64 },

    /// Sequence number gap detected
    #[error("Sequence gap for {prefix}: expected {expected}, got {got}")]
    SequenceGap {
        prefix: String,
        expected: u64,
        got: u64,
    },

    /// Entity not found
    #[error("Not found: {entity_type} '{id}'")]
    NotFound { entity_type: String, id: String },

    /// JSON serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Concurrent modification detected (CAS failure)
    #[error("Concurrent modification: {0}")]
    ConcurrentModification(String),

    /// SAID (Self-Addressing Identifier) mismatch (computed != stored)
    #[error("SAID mismatch: expected {expected}, got {actual}")]
    SaidMismatch { expected: String, actual: String },

    /// Invalid event structure (cannot compute SAID)
    #[error("Invalid event: {reason}")]
    InvalidEvent { reason: String },

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Invalid tenant ID
    #[error("invalid tenant ID '{tenant_id}': {kind}")]
    InvalidTenantId {
        tenant_id: String,
        kind: TenantIdError,
    },

    /// Attestation validation error
    #[error("Attestation error: {0}")]
    Attestation(String),

    /// Stale or replayed attestation rejected
    #[error("Stale attestation: {0}")]
    StaleAttestation(String),

    /// Method is not yet implemented by this backend.
    #[error("Not implemented: {method}")]
    NotImplemented {
        /// Name of the unimplemented method.
        method: &'static str,
    },

    /// A batch operation failed validation at a specific event index.
    #[error("Batch validation failed at index {index}: {source}")]
    BatchValidationFailed {
        /// Zero-based index of the failing event in the batch.
        index: usize,
        /// The underlying validation error.
        source: Box<RegistryError>,
    },
}

impl auths_core::error::AuthsErrorInfo for RegistryError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Storage(_) => "AUTHS-E4861",
            Self::InvalidPrefix { .. } => "AUTHS-E4862",
            Self::InvalidDeviceDid { .. } => "AUTHS-E4863",
            Self::EventExists { .. } => "AUTHS-E4864",
            Self::SequenceGap { .. } => "AUTHS-E4865",
            Self::NotFound { .. } => "AUTHS-E4866",
            Self::Serialization(_) => "AUTHS-E4867",
            Self::ConcurrentModification(_) => "AUTHS-E4868",
            Self::SaidMismatch { .. } => "AUTHS-E4869",
            Self::InvalidEvent { .. } => "AUTHS-E4870",
            Self::Io(_) => "AUTHS-E4871",
            Self::Internal(_) => "AUTHS-E4872",
            Self::InvalidTenantId { .. } => "AUTHS-E4873",
            Self::Attestation(_) => "AUTHS-E4874",
            Self::StaleAttestation(_) => "AUTHS-E4875",
            Self::NotImplemented { .. } => "AUTHS-E4876",
            Self::BatchValidationFailed { .. } => "AUTHS-E4877",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::Storage(_) => Some("Check storage backend connectivity"),
            Self::InvalidPrefix { .. } => Some("KERI prefixes must start with 'E' (Blake3 SAID)"),
            Self::InvalidDeviceDid { .. } => Some("Device DIDs must be in 'did:key:z...' format"),
            Self::EventExists { .. } => Some("This event has already been appended to the KEL"),
            Self::SequenceGap { .. } => Some("Events must be appended in strict sequence order"),
            Self::NotFound { .. } => None,
            Self::Serialization(_) => None,
            Self::ConcurrentModification(_) => {
                Some("Retry the operation; another process modified the registry")
            }
            Self::SaidMismatch { .. } => Some("The event content does not match its declared SAID"),
            Self::InvalidEvent { .. } => None,
            Self::Io(_) => Some("Check file permissions and disk space"),
            Self::Internal(_) => None,
            Self::InvalidTenantId { .. } => None,
            Self::Attestation(_) => None,
            Self::StaleAttestation(_) => {
                Some("The attestation has been superseded by a newer version")
            }
            Self::NotImplemented { .. } => {
                Some("This operation is not supported by the current backend")
            }
            Self::BatchValidationFailed { .. } => None,
        }
    }
}

impl RegistryError {
    /// Create a storage error from any error type.
    ///
    /// Use this to wrap backend-specific errors (e.g., git2::Error) in the
    /// generic Storage variant.
    pub fn storage<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Storage(Box::new(err))
    }

    /// Create a not-found error for an identity.
    pub fn identity_not_found(prefix: &Prefix) -> Self {
        Self::NotFound {
            entity_type: "identity".into(),
            id: prefix.as_str().into(),
        }
    }

    /// Create a not-found error for an event.
    pub fn event_not_found(prefix: &Prefix, seq: u64) -> Self {
        Self::NotFound {
            entity_type: "event".into(),
            id: format!("{} seq {}", prefix.as_str(), seq),
        }
    }

    /// Create a not-found error for a device.
    pub fn device_not_found(did: &str) -> Self {
        Self::NotFound {
            entity_type: "device".into(),
            id: did.into(),
        }
    }

    /// Create a not-found error for an org.
    pub fn org_not_found(org: &str) -> Self {
        Self::NotFound {
            entity_type: "org".into(),
            id: org.into(),
        }
    }
}

/// Trait for registry storage backends.
///
/// This trait defines operations for storing and retrieving:
/// - KERI events and key states
/// - Device attestations
/// - Organization memberships
///
/// Implementations must be thread-safe (`Send + Sync`).
///
/// # FROZEN SURFACE
///
/// This trait's method set is frozen. Do not add new methods without:
/// 1. Documented justification in a doc comment
/// 2. Review confirming the method is required for registry operations
///
/// The registry is a cache/index, not a source of truth. New methods should
/// only be added if they are essential for indexing or retrieval operations.
pub trait RegistryBackend: Send + Sync {
    // =========================================================================
    // KEL Operations
    // =========================================================================

    /// Append an event to an identity's KEL.
    ///
    /// # Semantics: Append-Only
    ///
    /// Events are **append-only** - once written, they are immutable.
    /// This function **refuses to overwrite** existing events.
    ///
    /// # Constraints (enforced by implementation)
    ///
    /// - Refuses if event file already exists (append-only, no rewrites)
    /// - Refuses if seq != tip.sequence + 1 (except seq 0 for inception)
    /// - Validates event.said() matches content hash expectations
    ///
    /// Also writes state.json with updated KeyState after each append.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The KERI identifier prefix
    /// * `event` - The event to append
    fn append_event(&self, prefix: &Prefix, event: &Event) -> Result<(), RegistryError>;

    /// Get a single event by sequence number (random access).
    ///
    /// # Arguments
    ///
    /// * `prefix` - The KERI identifier prefix
    /// * `seq` - The sequence number of the event
    fn get_event(&self, prefix: &Prefix, seq: u64) -> Result<Event, RegistryError>;

    /// Visit events starting from a sequence (streaming via visitor pattern).
    ///
    /// Calls `visitor` for each event. Return `ControlFlow::Break(())` to stop early.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The KERI identifier prefix
    /// * `from_seq` - Start reading from this sequence number
    /// * `visitor` - Callback invoked for each event
    fn visit_events(
        &self,
        prefix: &Prefix,
        from_seq: u64,
        visitor: &mut dyn FnMut(&Event) -> ControlFlow<()>,
    ) -> Result<(), RegistryError>;

    /// Get tip info without reading events.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The KERI identifier prefix
    fn get_tip(&self, prefix: &Prefix) -> Result<TipInfo, RegistryError>;

    /// Get key state.
    ///
    /// First tries state.json (verified against tip.said).
    /// Falls back to full KEL replay if state.json missing or stale.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The KERI identifier prefix
    fn get_key_state(&self, prefix: &Prefix) -> Result<KeyState, RegistryError>;

    /// Write a pre-computed `KeyState` directly into the registry tree.
    ///
    /// # When to Use
    ///
    /// This is for the archival worker's write-through path: the worker
    /// receives a `KeyState` from the mpsc channel (which was already
    /// validated and written to Redis Tier 0) and needs to persist it
    /// to Git Tier 1 without re-running KEL validation.
    ///
    /// This is **not** the append path for new KERI events. Use `append_event`
    /// for that. This method only updates `state.json` — it does not append
    /// any event blob or update `tip.json`. This is valid because the caller
    /// received the `KeyState` from a successful `append_event` call.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The KERI identifier prefix
    /// * `state` - The pre-validated `KeyState` to persist
    fn write_key_state(&self, prefix: &Prefix, state: &KeyState) -> Result<(), RegistryError>;

    /// Visit all identity prefixes (streaming for tooling/export).
    ///
    /// Calls `visitor` for each identity prefix. Return `ControlFlow::Break(())` to stop early.
    fn visit_identities(
        &self,
        visitor: &mut dyn FnMut(&str) -> ControlFlow<()>,
    ) -> Result<(), RegistryError>;

    // =========================================================================
    // Attestation Operations
    // =========================================================================

    /// Store a device attestation.
    ///
    /// # Semantics: Latest-View (overwrites)
    ///
    /// Attestations use **latest-view** semantics - the current file represents
    /// the latest state only. This function **overwrites any existing attestation**
    /// for the same device DID.
    ///
    /// Historical attestations are preserved in `attestation_history/` via
    /// `visit_attestation_history`.
    ///
    /// # Arguments
    ///
    /// * `attestation` - The attestation to store
    fn store_attestation(&self, attestation: &Attestation) -> Result<(), RegistryError>;

    /// Load an attestation for a device.
    ///
    /// Returns `None` if no attestation exists for the device.
    ///
    /// # Arguments
    ///
    /// * `did` - The device DID
    fn load_attestation(&self, did: &DeviceDID) -> Result<Option<Attestation>, RegistryError>;

    /// Visit attestation history for a device (append-only audit trail).
    ///
    /// Iterates historical attestations in chronological order (oldest first).
    /// Each entry represents a point-in-time snapshot of the device's attestation.
    ///
    /// # Arguments
    ///
    /// * `did` - The device DID
    /// * `visitor` - Callback invoked for each historical attestation
    fn visit_attestation_history(
        &self,
        did: &DeviceDID,
        visitor: &mut dyn FnMut(&Attestation) -> ControlFlow<()>,
    ) -> Result<(), RegistryError>;

    /// Visit all device DIDs in the registry.
    ///
    /// Calls `visitor` for each device DID. Return `ControlFlow::Break(())` to stop early.
    fn visit_devices(
        &self,
        visitor: &mut dyn FnMut(&DeviceDID) -> ControlFlow<()>,
    ) -> Result<(), RegistryError>;

    // =========================================================================
    // Org Operations
    // =========================================================================

    /// Store an org member attestation.
    ///
    /// # Semantics: Latest-View (overwrites)
    ///
    /// Member attestations use **latest-view** semantics - the current file represents
    /// the latest state only. This function **overwrites any existing attestation**
    /// for the same member DID within the org.
    ///
    /// # Arguments
    ///
    /// * `org` - The org DID prefix
    /// * `member` - The member's attestation
    fn store_org_member(&self, org: &str, member: &Attestation) -> Result<(), RegistryError>;

    /// Visit all members of an org (low-level, validation-aware).
    ///
    /// Iterates all member entries with their validation status.
    /// Even invalid entries call visitor (for audit/tooling).
    ///
    /// # Arguments
    ///
    /// * `org` - The org DID prefix
    /// * `visitor` - Callback invoked for each member entry
    fn visit_org_member_attestations(
        &self,
        org: &str,
        visitor: &mut dyn FnMut(&OrgMemberEntry) -> ControlFlow<()>,
    ) -> Result<(), RegistryError>;

    /// List org members with filtering (high-level API).
    ///
    /// Returns validated, filtered member views sorted deterministically by DID.
    ///
    /// # No Policy Decisions
    ///
    /// This method does NOT compute revoked/expired status. All valid attestations
    /// are returned with `status: Active`. Use the `revoked_at` and `expires_at` fields
    /// to compute actual status in your policy layer:
    ///
    /// ```ignore
    /// let actual_status = compute_status_from_view(&view, now);
    /// ```
    ///
    /// The `include_statuses` filter is ignored (status filtering is policy).
    ///
    /// # Arguments
    ///
    /// * `org` - The org DID prefix
    /// * `filter` - Filter criteria for members (role, capabilities)
    fn list_org_members(
        &self,
        org: &str,
        filter: &MemberFilter,
    ) -> Result<Vec<MemberView>, RegistryError> {
        let mut members = Vec::new();

        self.visit_org_member_attestations(org, &mut |entry| {
            let (status, att_opt, revoked_at) = match &entry.attestation {
                Ok(att) => (MemberStatus::Active, Some(att), att.revoked_at),
                Err(reason) => (
                    MemberStatus::Invalid {
                        reason: reason.clone(),
                    },
                    None,
                    None,
                ),
            };

            // For valid attestations, apply data filters (role, capabilities)
            // Note: Status filtering removed - that's policy layer responsibility
            if let Some(att) = att_opt {
                // Role filter: include if member.role is in set
                if let Some(ref roles) = filter.roles_any {
                    match &att.role {
                        Some(role) if roles.contains(role) => {}
                        _ => return ControlFlow::Continue(()),
                    }
                }

                // Capabilities any: intersection non-empty
                let member_caps: HashSet<&Capability> = att.capabilities.iter().collect();
                if let Some(ref caps_any) = filter.capabilities_any
                    && !member_caps.iter().any(|c| caps_any.contains(*c))
                {
                    return ControlFlow::Continue(());
                }

                // Capabilities all: filter_caps ⊆ member_caps
                if let Some(ref caps_all) = filter.capabilities_all
                    && !caps_all.iter().all(|c| member_caps.contains(c))
                {
                    return ControlFlow::Continue(());
                }

                members.push(MemberView {
                    did: entry.did.clone(),
                    status,
                    role: att.role,
                    capabilities: att.capabilities.clone(),
                    issuer: IdentityDID::new_unchecked(att.issuer.as_str()),
                    rid: att.rid.clone(),
                    revoked_at,
                    expires_at: att.expires_at,
                    timestamp: att.timestamp,
                    source_filename: entry.filename.clone(),
                });
            } else {
                log::warn!(
                    "Skipping invalid member entry '{}' (failed to parse attestation)",
                    entry.filename
                );
            }

            ControlFlow::Continue(())
        })?;

        // Sort deterministically by DID only (status not computed here)
        members.sort_by(|a, b| a.did.to_string().cmp(&b.did.to_string()));

        Ok(members)
    }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    /// Initialize the registry if it has not been set up yet.
    ///
    /// Creates the initial registry structure (e.g., first Git commit, database
    /// schema). Returns `true` if initialization was performed, `false` if the
    /// registry was already initialized.
    ///
    /// Usage:
    /// ```ignore
    /// let was_initialized = backend.init_if_needed()?;
    /// ```
    fn init_if_needed(&self) -> Result<bool, RegistryError>;

    // =========================================================================
    // Metadata
    // =========================================================================

    /// Get registry metadata.
    fn metadata(&self) -> Result<RegistryMetadata, RegistryError>;

    // =========================================================================
    // Fast-path operations (index-accelerated)
    // =========================================================================

    /// List org members using the SQLite index when available.
    ///
    /// # Justification for addition to frozen surface
    ///
    /// This is a performance optimization of the existing `list_org_members` method,
    /// not a new capability. The default implementation delegates to `list_org_members`
    /// (O(n) Git scan). Backends with an index override this for O(1) SQLite lookup.
    ///
    /// # Filter limitations
    ///
    /// The index stores only DID, rid, issuer, revoked_at, and expires_at.
    /// If the filter includes `roles_any`, `capabilities_any`, or `capabilities_all`,
    /// the implementation falls back to the Git scan (those fields require the full
    /// attestation blob). Status filtering is always deferred to the policy layer.
    ///
    /// # Arguments
    ///
    /// * `org` - The org DID prefix
    /// * `filter` - Filter criteria for members
    fn list_org_members_fast(
        &self,
        org: &str,
        filter: &MemberFilter,
    ) -> Result<Vec<MemberView>, RegistryError> {
        self.list_org_members(org, filter)
    }
}

/// Blanket impl so `Arc<dyn RegistryBackend + Send + Sync>` can be used directly
/// as a `RegistryBackend` at call sites (e.g., tests, extractors).
impl<T: RegistryBackend + ?Sized> RegistryBackend for Arc<T> {
    fn append_event(&self, prefix: &Prefix, event: &Event) -> Result<(), RegistryError> {
        (**self).append_event(prefix, event)
    }

    fn get_event(&self, prefix: &Prefix, seq: u64) -> Result<Event, RegistryError> {
        (**self).get_event(prefix, seq)
    }

    fn visit_events(
        &self,
        prefix: &Prefix,
        from_seq: u64,
        visitor: &mut dyn FnMut(&Event) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        (**self).visit_events(prefix, from_seq, visitor)
    }

    fn get_tip(&self, prefix: &Prefix) -> Result<TipInfo, RegistryError> {
        (**self).get_tip(prefix)
    }

    fn get_key_state(&self, prefix: &Prefix) -> Result<KeyState, RegistryError> {
        (**self).get_key_state(prefix)
    }

    fn write_key_state(&self, prefix: &Prefix, state: &KeyState) -> Result<(), RegistryError> {
        (**self).write_key_state(prefix, state)
    }

    fn visit_identities(
        &self,
        visitor: &mut dyn FnMut(&str) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        (**self).visit_identities(visitor)
    }

    fn store_attestation(&self, attestation: &Attestation) -> Result<(), RegistryError> {
        (**self).store_attestation(attestation)
    }

    fn load_attestation(&self, did: &DeviceDID) -> Result<Option<Attestation>, RegistryError> {
        (**self).load_attestation(did)
    }

    fn visit_attestation_history(
        &self,
        did: &DeviceDID,
        visitor: &mut dyn FnMut(&Attestation) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        (**self).visit_attestation_history(did, visitor)
    }

    fn visit_devices(
        &self,
        visitor: &mut dyn FnMut(&DeviceDID) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        (**self).visit_devices(visitor)
    }

    fn store_org_member(&self, org: &str, member: &Attestation) -> Result<(), RegistryError> {
        (**self).store_org_member(org, member)
    }

    fn visit_org_member_attestations(
        &self,
        org: &str,
        visitor: &mut dyn FnMut(&OrgMemberEntry) -> ControlFlow<()>,
    ) -> Result<(), RegistryError> {
        (**self).visit_org_member_attestations(org, visitor)
    }

    fn init_if_needed(&self) -> Result<bool, RegistryError> {
        (**self).init_if_needed()
    }

    fn metadata(&self) -> Result<RegistryMetadata, RegistryError> {
        (**self).metadata()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_identity_not_found() {
        let prefix = Prefix::new_unchecked("ETest123".to_string());
        let err = RegistryError::identity_not_found(&prefix);
        assert!(err.to_string().contains("identity"));
        assert!(err.to_string().contains("ETest123"));
    }

    #[test]
    fn error_event_not_found() {
        let prefix = Prefix::new_unchecked("ETest123".to_string());
        let err = RegistryError::event_not_found(&prefix, 5);
        assert!(err.to_string().contains("event"));
        assert!(err.to_string().contains("seq 5"));
    }

    #[test]
    fn error_device_not_found() {
        let err = RegistryError::device_not_found("did:key:test");
        assert!(err.to_string().contains("device"));
        assert!(err.to_string().contains("did:key:test"));
    }

    #[test]
    fn error_sequence_gap() {
        let err = RegistryError::SequenceGap {
            prefix: "ETest".into(),
            expected: 5,
            got: 7,
        };
        assert!(err.to_string().contains("expected 5"));
        assert!(err.to_string().contains("got 7"));
    }

    #[test]
    fn error_concurrent_modification() {
        let err = RegistryError::ConcurrentModification("Registry was modified".into());
        assert!(err.to_string().contains("Concurrent"));
        assert!(err.to_string().contains("modified"));
    }

    #[test]
    fn validated_tenant_id_normalizes_to_lowercase() {
        let tid = ValidatedTenantId::new("ACME").unwrap();
        assert_eq!(tid.as_str(), "acme");
    }

    #[test]
    fn validated_tenant_id_rejects_empty() {
        assert!(ValidatedTenantId::new("").is_err());
    }

    #[test]
    fn validated_tenant_id_rejects_reserved() {
        assert!(ValidatedTenantId::new("admin").is_err());
    }

    #[test]
    fn validated_tenant_id_rejects_bad_chars() {
        assert!(ValidatedTenantId::new("acme/sub").is_err());
        assert!(ValidatedTenantId::new("../escape").is_err());
    }

    #[test]
    fn validated_tenant_id_accepts_valid() {
        let tid = ValidatedTenantId::new("my-tenant_123").unwrap();
        assert_eq!(tid.as_str(), "my-tenant_123");
    }

    #[test]
    fn validated_tenant_id_display() {
        let tid = ValidatedTenantId::new("acme").unwrap();
        assert_eq!(format!("{}", tid), "acme");
    }

    #[test]
    fn validated_tenant_id_into_string() {
        let tid = ValidatedTenantId::new("acme").unwrap();
        let s: String = tid.into();
        assert_eq!(s, "acme");
    }
}
