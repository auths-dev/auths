//! KERI (Key Event Receipt Infrastructure) implementation.
//!
//! This module provides core KERI types and operations for identity management:
//!
//! - **Events**: Inception (icp), Rotation (rot), Interaction (ixn)
//! - **KeyState**: Current cryptographic state derived from KEL replay
//! - **Seals**: Anchored data references in events
//!
//! # Core Scope
//!
//! **If it's not here, it's not core.**
//!
//! This module defines the fundamental KERI protocol logic. Everything else
//! (storage, transport, UI) is an adapter that consumes this core.
//!
//! ## Domain Types (Sans-IO)
//!
//! The following types are **pure domain types** with no I/O dependencies:
//!
//! | Type | Location | Notes |
//! |------|----------|-------|
//! | `Event`, `IcpEvent`, `RotEvent`, `IxnEvent` | `auths-id::keri::event` | Serde-only, no git2/fs/net |
//! | `KeyState` | `auths-id::keri::state` | Serde-only, no git2/fs/net |
//! | `Attestation`, `Capability` | `auths-verifier::core` | Serde + chrono types (no `Utc::now()`) |
//! | `MemberStatus`, `MemberFilter`, `MemberView` | `auths-id::storage::registry::org_member` | Time injected via `now` param |
//!
//! **Key invariants:**
//! - All `DateTime<Utc>` values are passed in (injected), never generated via `Utc::now()`
//! - No direct filesystem, git, or network operations in these types
//! - Types use only serde for serialization (deterministic, portable)
//!
//! ## Core Entrypoints (Pure Functions)
//!
//! The following are the **pure function entrypoints** with no side effects:
//!
//! | Function | Module | Description |
//! |----------|--------|-------------|
//! | [`validate_kel`] / [`replay_kel`] | `keri::validate` | Replays events to compute `KeyState` (`apply_event_chain`) |
//! | [`compute_status`](crate::storage::registry::org_member::compute_status) | `storage::registry::org_member` | Computes member status from attestation |
//! | `evaluate_policy` | `policy` | Evaluates authorization decision |
//!
//! These functions are suitable for property-based testing and are independent
//! of storage backends.
//!
//! ## Protocol Invariants
//!
//! These invariants are **non-negotiable** and enforced at the core level:
//!
//! ### 1. Identity KEL is Append-Only
//!
//! - Once an event is committed, it cannot be modified
//! - Sequence numbers are monotonically increasing (0, 1, 2, ...)
//! - Each event's SAID must match its content hash (self-addressing)
//! - Violating these produces [`ValidationError::InvalidSequence`] or [`ValidationError::InvalidSaid`]
//!
//! **Tests:** `rejects_broken_sequence`, `rejects_invalid_said` in [`validate`] module
//!
//! ### 2. Device/Org Attestations are Derived State
//!
//! - Attestations are NOT the source of truth for identity
//! - They are derived from the KEL and anchored via seals
//! - Attestations can be regenerated from the KEL
//! - Storage backends may cache attestations, but the KEL is authoritative
//!
//! ### 3. Issuer + Subject Mismatches are Structural Invalidity
//!
//! When loading attestations:
//! - Subject DID must match the filename DID → [`MemberInvalidReason::SubjectMismatch`](crate::storage::registry::org_member::MemberInvalidReason::SubjectMismatch)
//! - Issuer DID must match the org DID → [`MemberInvalidReason::IssuerMismatch`](crate::storage::registry::org_member::MemberInvalidReason::IssuerMismatch)
//!
//! These are **hard errors** (structural corruption), not soft warnings.
//!
//! **Tests:** `visit_org_member_attestations_detects_subject_mismatch`,
//! `visit_org_member_attestations_detects_issuer_mismatch` in `packed` module
//!
//! ## Event Types
//!
//! | Type | Purpose |
//! |------|---------|
//! | `icp` | Creates identity, commits to first rotation key |
//! | `rot` | Rotates to pre-committed key, establishes new commitment |
//! | `ixn` | Anchors data (attestations) without key rotation |
//!
//! ## Not Implemented (Out of Scope)
//!
//! - Delegation events (dip/drt)
//! - Threshold multi-sig
//! - CESR encoding (using JSON)
//!
//! ## Witness Support
//!
//! Witness infrastructure is available via the `auths_core::witness` module:
//! - `Receipt`: Witness receipt for event acknowledgment
//! - `ReceiptCollector`: Collects receipts from k-of-n witnesses
//! - `DuplicityDetector`: Detects split-view attacks
//!
//! Receipt storage is available via `auths_id::storage::receipts`.

#[cfg(feature = "git-storage")]
pub mod anchor;
#[allow(clippy::disallowed_methods, clippy::disallowed_types)]
// INVARIANT: file-based KEL cache — entire module is an I/O adapter
pub mod cache;
pub mod event;
#[cfg(feature = "git-storage")]
pub mod inception;
#[cfg(feature = "git-storage")]
pub mod incremental;
#[cfg(feature = "git-storage")]
pub mod kel;
#[cfg(feature = "git-storage")]
pub mod resolve;
#[cfg(feature = "git-storage")]
pub mod rotation;
pub mod seal;
pub mod state;
pub mod types;
pub mod validate;
#[cfg(feature = "witness-client")]
pub mod witness_integration;

#[cfg(feature = "git-storage")]
pub use anchor::{
    AnchorError, AnchorVerification, anchor_attestation, anchor_data, anchor_idp_binding,
    find_anchor_event, verify_anchor, verify_anchor_by_digest, verify_attestation_anchor_by_issuer,
};
pub use auths_keri::KERI_VERSION_PREFIX;
pub use event::{
    CesrKey, ConfigTrait, Event, EventReceipts, IcpEvent, IxnEvent, KeriSequence, RotEvent,
    Threshold, VersionString,
};
#[cfg(feature = "git-storage")]
pub use inception::{
    InceptionError, InceptionResult, create_keri_identity, create_keri_identity_with_backend,
    create_keri_identity_with_curve, did_to_prefix, prefix_to_did,
};
#[cfg(feature = "git-storage")]
pub use kel::{GitKel, KelError};
#[cfg(feature = "git-storage")]
pub use resolve::{
    DidKeriResolution, ResolveError, parse_did_keri, resolve_did_keri, resolve_did_keri_at_sequence,
};
#[cfg(feature = "git-storage")]
pub use rotation::{
    RotationError, RotationResult, abandon_identity, get_key_state, get_key_state_with_backend,
    rotate_keys, rotate_keys_with_backend,
};
pub use seal::{Seal, SealType};
pub use state::KeyState;
pub use types::{KeriTypeError, Prefix, Said, prefix_from_did};
pub use validate::{
    ValidationError, compute_event_said, finalize_icp_event, replay_kel, serialize_for_signing,
    validate_for_append, validate_kel, verify_event_crypto, verify_event_said,
};
