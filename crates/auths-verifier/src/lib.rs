#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    clippy::dbg_macro
)]
#![deny(clippy::disallowed_methods)]
#![deny(rustdoc::broken_intra_doc_links)]
#![warn(clippy::too_many_lines, clippy::cognitive_complexity)]
#![warn(missing_docs)]
//! # auths-verifier
//!
//! Attestation verification library for Auths.
//!
//! This crate provides signature and chain verification without requiring
//! access to private keys or platform keychains. It's designed to be:
//! - **Lightweight** — minimal dependencies
//! - **Cross-platform** — works on any target including WASM
//! - **FFI-friendly** — C-compatible interface available
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use auths_verifier::{verify_chain, VerificationStatus};
//!
//! let report = verify_chain(&attestations)?;
//!
//! match report.status {
//!     VerificationStatus::Valid => println!("Chain verified!"),
//!     VerificationStatus::Expired { at } => println!("Expired at {}", at),
//!     VerificationStatus::InvalidSignature { step } => {
//!         println!("Bad signature at step {}", step);
//!     }
//!     _ => println!("Verification failed"),
//! }
//! ```
//!
//! ## With Capability Checking
//!
//! ```rust,ignore
//! use auths_verifier::{verify_with_capability, Capability};
//!
//! // Verify device has sign-commit permission
//! let report = verify_with_capability(&chain, Capability::SignCommit)?;
//! ```
//!
//! ## Feature Flags
//!
//! - `wasm` — Enable WASM bindings via wasm-bindgen

pub mod action;
pub mod clock;
pub mod commit;
pub mod commit_error;
pub mod core;
pub mod error;
/// C-compatible FFI bindings for attestation and chain verification.
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod keri;
pub mod ssh_sig;
pub mod types;
pub mod verifier;
pub mod verify;
/// WASM bindings for browser and edge-runtime verification.
#[cfg(feature = "wasm")]
pub mod wasm;
pub mod witness;

// Re-export verification types for convenience
pub use types::{ChainLink, DeviceDID, IdentityDID, VerificationReport, VerificationStatus};

// Re-export action envelope
pub use action::ActionEnvelope;

// Re-export core types
pub use core::{
    Capability, CapabilityError, Ed25519KeyError, Ed25519PublicKey, Ed25519Signature,
    IdentityBundle, MAX_ATTESTATION_JSON_SIZE, MAX_JSON_BATCH_SIZE, ResourceId, Role,
    RoleParseError, SignatureLengthError, ThresholdPolicy, VerifiedAttestation,
};

// Re-export error types
pub use commit_error::CommitVerificationError;
pub use error::{AttestationError, AuthsErrorInfo};

// Re-export Verifier struct
pub use verifier::Verifier;

// Re-export verification functions (native-only, async)
#[cfg(feature = "native")]
pub use verify::{
    verify_at_time, verify_chain, verify_chain_with_capability, verify_chain_with_witnesses,
    verify_device_authorization, verify_with_capability, verify_with_keys,
};

// Re-export sync utility functions (always available)
pub use verify::{
    DeviceLinkVerification, compute_attestation_seal_digest, did_to_ed25519, is_device_listed,
    verify_device_link,
};

// Re-export witness types
pub use witness::{WitnessQuorum, WitnessReceipt, WitnessReceiptResult, WitnessVerifyConfig};

// Re-export KERI verification types (key parsing lives in auths-crypto)
pub use keri::{
    IcpEvent as KeriIcpEvent, IxnEvent as KeriIxnEvent, KeriEvent, KeriKeyState, KeriTypeError,
    KeriVerifyError, Prefix, RotEvent as KeriRotEvent, Said, Seal as KeriSeal, compute_said,
    find_seal_in_kel, parse_kel_json, verify_kel,
};

// Re-export commit verification types
pub use commit::VerifiedCommit;
pub use ssh_sig::SshSigEnvelope;

// Re-export crypto provider trait for downstream consumers
pub use auths_crypto::CryptoProvider;

// Re-export clock types for downstream consumers (auths-core re-exports from here)
pub use clock::{ClockProvider, SystemClock};

/// Test utilities for auths-verifier consumers (behind `test-utils` feature).
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn fixed_ts() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap()
    }

    #[test]
    fn verification_report_is_valid_returns_true_for_valid_status() {
        let report = VerificationReport::valid(vec![]);
        assert!(report.is_valid());
    }

    #[test]
    fn verification_report_is_valid_returns_false_for_expired_status() {
        let report =
            VerificationReport::with_status(VerificationStatus::Expired { at: fixed_ts() }, vec![]);
        assert!(!report.is_valid());
    }

    #[test]
    fn verification_report_is_valid_returns_false_for_revoked_status() {
        let report = VerificationReport::with_status(
            VerificationStatus::Revoked {
                at: Some(fixed_ts()),
            },
            vec![],
        );
        assert!(!report.is_valid());
    }

    #[test]
    fn verification_report_is_valid_returns_false_for_invalid_signature() {
        let report = VerificationReport::with_status(
            VerificationStatus::InvalidSignature { step: 0 },
            vec![],
        );
        assert!(!report.is_valid());
    }

    #[test]
    fn verification_report_is_valid_returns_false_for_broken_chain() {
        let report = VerificationReport::with_status(
            VerificationStatus::BrokenChain {
                missing_link: "test".to_string(),
            },
            vec![],
        );
        assert!(!report.is_valid());
    }

    #[test]
    fn verification_report_serializes_to_expected_json() {
        let chain = vec![
            ChainLink::valid(
                "did:key:issuer1".to_string(),
                "did:key:subject1".to_string(),
            ),
            ChainLink::invalid(
                "did:key:issuer2".to_string(),
                "did:key:subject2".to_string(),
                "signature mismatch".to_string(),
            ),
        ];

        let report = VerificationReport {
            status: VerificationStatus::InvalidSignature { step: 1 },
            chain,
            warnings: vec!["Key expires soon".to_string()],
            witness_quorum: None,
        };

        let json = serde_json::to_string(&report).expect("serialization failed");

        // Verify structure
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse failed");

        // Check status has "type" tag
        assert_eq!(parsed["status"]["type"], "InvalidSignature");
        assert_eq!(parsed["status"]["step"], 1);

        // Check chain structure
        assert_eq!(parsed["chain"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["chain"][0]["issuer"], "did:key:issuer1");
        assert_eq!(parsed["chain"][0]["valid"], true);
        assert_eq!(parsed["chain"][1]["valid"], false);
        assert_eq!(parsed["chain"][1]["error"], "signature mismatch");

        // Check warnings
        assert_eq!(parsed["warnings"][0], "Key expires soon");
    }

    #[test]
    fn verification_status_valid_serializes_correctly() {
        let status = VerificationStatus::Valid;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#"{"type":"Valid"}"#);
    }

    #[test]
    fn verification_status_expired_serializes_with_timestamp() {
        let status = VerificationStatus::Expired {
            at: chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "Expired");
        assert_eq!(parsed["at"], "2024-01-01T00:00:00Z");
    }

    #[test]
    fn verification_status_revoked_serializes_with_optional_timestamp() {
        // With timestamp
        let status = VerificationStatus::Revoked {
            at: Some(
                chrono::DateTime::parse_from_rfc3339("2024-06-15T12:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
            ),
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "Revoked");
        assert_eq!(parsed["at"], "2024-06-15T12:00:00Z");

        // Without timestamp
        let status = VerificationStatus::Revoked { at: None };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "Revoked");
        assert!(parsed["at"].is_null());
    }

    #[test]
    fn chain_link_helpers_work() {
        let valid = ChainLink::valid("issuer".to_string(), "subject".to_string());
        assert!(valid.valid);
        assert!(valid.error.is_none());

        let invalid = ChainLink::invalid(
            "issuer".to_string(),
            "subject".to_string(),
            "error".to_string(),
        );
        assert!(!invalid.valid);
        assert_eq!(invalid.error, Some("error".to_string()));
    }
}
