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
//! # Features
//!
//! - `heartwood` - Enable direct integration with Radicle's heartwood crates.
//!   When disabled, the bridge uses generic byte-based APIs.

pub mod bridge;
pub mod identity;
pub mod verify;

pub use bridge::{BridgeError, RadicleAuthsBridge, VerifyResult};
pub use identity::{RadicleIdentity, RadicleIdentityDocument, RadicleIdentityResolver};
pub use verify::{
    AuthsStorage, DefaultBridge, decision_to_verify_result, meets_threshold,
    verify_multiple_signers,
};
