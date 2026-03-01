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

pub mod attestation;
pub mod bridge;
pub mod identity;
pub mod refs;
pub mod storage;
pub mod verify;

pub use attestation::{RadAttestation, RadAttestationError, RadCanonicalPayload};
pub use bridge::{
    BridgeError, EnforcementMode, RadicleAuthsBridge, SignerInput, VerifyRequest, VerifyResult,
};
pub use identity::{
    IdentityError, RadicleIdentity, RadicleIdentityDocument, RadicleIdentityResolver,
};
pub use verify::{
    AuthsStorage, DefaultBridge, decision_to_verify_result, meets_threshold,
    verify_multiple_signers,
};
