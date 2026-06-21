// crate-level allow during curve-agnostic refactor.
#![allow(clippy::disallowed_methods)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    clippy::dbg_macro
)]
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
//! ## Authority via Credentials
//!
//! The verifier checks **authenticity** only — signatures, chain linkage, expiry,
//! and witness quorum. Capability/role **authority** is no longer read from the
//! attestation; it flows exclusively through a holder-verified ACDC credential
//! presentation (see `auths_id::policy::context_from_credential`).
//!
//! ## Feature Flags
//!
//! - `wasm` — Enable WASM bindings via wasm-bindgen

pub mod action;
/// Legible "what you are authorizing" summary derived from the bytes being signed.
pub mod authorization_summary;
pub mod clock;
pub mod commit;
/// Stateless commit verification against an identity bundle (CLI + WASM).
pub mod commit_bundle;
pub mod commit_error;
pub mod commit_kel;
/// The single cross-boundary verify contract (JSON request → tagged verdict).
pub mod contract;
pub mod core;
pub mod credential;
pub mod duplicity;
pub mod error;
/// Offline verification of compliance evidence packs.
pub mod evidence_pack;
/// C-compatible FFI bindings for attestation and chain verification.
#[cfg(feature = "ffi")]
pub mod ffi;
/// Freshness verdict model (ADR 009): bounded freshness, verifier-set policy.
pub mod freshness;
/// OIDC-subject policy and the verify-time join for keyless CI signing.
pub mod oidc_policy;
/// Offline verification of air-gapped org provenance bundles.
pub mod org_bundle;
pub mod presentation;
mod software_verify;
pub mod ssh_sig;
/// Transparency-log verification primitives (Merkle proofs, checkpoints).
pub mod tlog;
pub mod types;
pub mod verifier;
pub mod verify;
/// WASM bindings for browser and edge-runtime verification.
#[cfg(feature = "wasm")]
pub mod wasm;
pub mod witness;

// Re-export verification types for convenience
pub use types::{
    AssuranceLevel, AssuranceLevelParseError, CanonicalDid, ChainLink, DidConversionError,
    DidParseError, IdentityDID, VerificationReport, VerificationStatus, signer_hex_to_did,
    validate_did,
};

// Re-export action envelope
pub use action::ActionEnvelope;

// Re-export the legible authorization summary (signing-consent surface)
pub use authorization_summary::AuthorizationSummary;

// Re-export core types
pub use core::{
    ATTESTATION_VERSION, Attestation, Capability, CapabilityError, CommitOid, CommitOidError,
    DevicePublicKey, EcdsaP256Error, EcdsaP256PublicKey, EcdsaP256Signature, Ed25519KeyError,
    Ed25519PublicKey, Ed25519Signature, IdentityBundle, InvalidKeyError, MAX_ATTESTATION_JSON_SIZE,
    MAX_JSON_BATCH_SIZE, OidcBinding, PolicyId, PublicKeyDecodeError, PublicKeyHex,
    PublicKeyHexError, ResourceId, Role, RoleParseError, SignatureAlgorithm, SignatureLengthError,
    SignatureVerifyError, ThresholdPolicy, TypedSignature, VerifiedAttestation,
    decode_public_key_bytes, decode_public_key_hex,
};

// Re-export the OIDC policy join (keyless CI verify-time exchange)
pub use oidc_policy::{OidcPolicyError, OidcPolicyJoin, OidcSubjectPolicy};

// Re-export test utilities
#[cfg(any(test, feature = "test-utils"))]
pub use testing::AttestationBuilder;

#[cfg(any(test, feature = "test-utils"))]
pub use testing::MockClock;

// Re-export error types
pub use commit_error::CommitVerificationError;
pub use error::{AttestationError, AuthsErrorInfo};

// Re-export Verifier struct
pub use verifier::Verifier;

// Re-export verification functions (native-only, async)
#[cfg(feature = "native")]
pub use verify::{
    verify_at_time, verify_chain, verify_chain_with_witnesses, verify_device_authorization,
    verify_with_keys,
};

// Re-export sync utility functions (always available)
pub use verify::{
    DeviceLinkVerification, compute_attestation_seal_digest, is_device_listed, verify_device_link,
};

// Re-export witness types
#[cfg(feature = "native")]
pub use witness::verify_build_attestation_offline;
pub use witness::{
    OfflineBuildVerdict, OfflineReceiptVerdict, SignedReceipt, WitnessQuorum, WitnessReceiptResult,
    WitnessVerifyConfig, verify_receipt_offline,
};

// Re-export KERI types directly from auths-keri
pub use auths_keri::{
    Event as KeriEvent, IcpEvent as KeriIcpEvent, IxnEvent as KeriIxnEvent, KeriTypeError, Prefix,
    RotEvent as KeriRotEvent, Said, Seal as KeriSeal, ValidationError, compute_said,
    find_seal_in_kel, parse_kel_json,
};

// Re-export commit verification types
pub use commit::{VerifiedCommit, commit_object_is_signed};
pub use commit_bundle::{BundleTrust, BundleTrustError, verify_commit_with_bundle_json};
pub use commit_kel::{
    ANCHOR_SEQ_TRAILER, CommitVerdict, DEVICE_TRAILER, ID_TRAILER, SCOPE_TRAILER,
    VerifierWitnessPolicy, WitnessGateStatus, WitnessedVerdict, anchor_seq_trailer,
    commit_signer_trailers, scope_trailer, verify_commit_against_kel,
    verify_commit_against_kel_scoped, verify_commit_against_kel_witnessed,
    verify_commit_against_kel_witnessed_scoped,
};
pub use ssh_sig::{SshKeyType, SshSigEnvelope};

// Re-export ACDC credential verification (Epic F.5). The `_sync` entrypoint is the
// executor-free core every non-Rust binding target (C-ABI, WASM, Node, Python, Go)
// calls directly; the `async fn` is a thin wrapper kept for native Rust callers.
pub use credential::{
    CredentialVerdict, LifecycleEvent, SignedAcdc, verify_credential, verify_credential_sync,
};

// Re-export holder-binding presentation verification (Epic F.8). `verify_presentation_sync`
// is the executor-free core; `verify_presentation` is the thin async wrapper over it.
pub use presentation::{
    PresentationBinding, PresentationEnvelope, PresentationVerdict, verify_presentation,
    verify_presentation_sync,
};

// Re-export the cross-boundary JSON verify contract (Epic D2). One bundled request in, one
// tagged discriminated-union verdict out — the single surface FFI/WASM/Node/Python/Go share.
pub use contract::{SCHEMA_VERSION, verify_credential_json, verify_presentation_json};

// Re-export crypto provider trait for downstream consumers
pub use auths_crypto::CryptoProvider;
pub use auths_crypto::Hash256;

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
            anchored: None,
            duplicity_warning: None,
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
