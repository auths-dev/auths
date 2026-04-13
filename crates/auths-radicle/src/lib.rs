// crate-level allow during curve-agnostic refactor.
#![allow(clippy::disallowed_methods)]

//! Radicle protocol integration for Auths.
//!
//! This crate provides the adapter layer between Radicle and Auths, enabling:
//! - Identity resolution from Radicle repositories
//! - Mapping Radicle device keys to Auths DeviceDIDs
//! - Policy-based commit verification
//!
//! # Architecture
//!
//! This adapter follows the "zero new crypto" principle:
//! - Radicle handles all cryptographic signature verification
//! - Auths provides authorization through its policy engine
//! - This adapter bridges the two without introducing new signature formats
//!
//! # Hard Constraints
//!
//! All Radicle-specific logic is consolidated in this crate:
//! - `auths-core` has zero Radicle dependencies
//! - `auths-id` has zero Radicle dependencies
//! - Only this crate imports Radicle/heartwood types
//!
//! # Feature Flags
//!
//! - `std` (default): Enables Git storage, `chrono`, identity resolution, full bridge.
//! - `wasm`: Enables `wasm-bindgen` for WASM targets. Core types (`VerifyResult`,
//!   `RadAttestation`, `RadCanonicalPayload`, bridge enums) are always available.

pub mod attestation;
pub mod bridge;
pub mod refs;

#[cfg(feature = "std")]
pub mod identity;
#[cfg(feature = "std")]
pub mod storage;
#[cfg(feature = "std")]
pub mod verify;

// WASM-safe re-exports (always available)
pub use attestation::{
    AttestationConversionError, RadAttestation, RadAttestationError, RadCanonicalPayload,
};
pub use bridge::{
    BridgeError, EnforcementMode, QuarantineReason, RadicleAuthsBridge, RejectReason, SignerInput,
    Timestamp, VerifyReason, VerifyRequest, VerifyResult, WarnReason,
};

// std-only re-exports
#[cfg(feature = "std")]
pub use identity::{
    IdentityError, RadicleIdentity, RadicleIdentityDocument, RadicleIdentityResolver,
};
#[cfg(feature = "std")]
pub use radicle_core::identity::{Did, DidError};
#[cfg(feature = "std")]
pub use verify::{
    AuthsStorage, DefaultBridge, IdentityDid, decision_to_verify_result, meets_threshold,
    verify_multiple_signers,
};
