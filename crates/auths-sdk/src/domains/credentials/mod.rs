//! Credential domain — ACDC issuance / revocation / listing / verification (Epic F).
//!
//! A credential is an ACDC (`{v,d,i,ri,s,a}`) anchored to the issuer's KEL through a
//! backerless TEL (`vcp` registry inception, `iss` issuance, `rev` revocation). This
//! domain is the SDK-orchestrates layer over F.3's `credential_registry` engine and
//! F.5's pure verifier; it owns no crypto or KEL logic of its own.
//!
//! - [`issue`] / [`revoke`] / [`list`] — issuance orchestration (F.4).
//! - [`verify`] — the resolution + freshness layer (F.4): resolves the issuer KEL/TEL
//!   plus the lifecycle-anchor witness receipts to the witnessed tip, hands them to
//!   the pure verifier, and owns the fail-closed freshness decision.

/// Credential error type (`thiserror`, no `anyhow`).
pub mod error;
/// Issuance, revocation, and listing workflows.
pub mod issue;
/// The persisted credential envelope (`{acdc, signature}`).
pub mod stored;
/// Verification — the resolution + freshness layer.
pub mod verify;

pub use error::CredentialError;
pub use issue::{CredentialIssuance, CredentialSummary, issue, list, revoke};
pub use stored::StoredCredential;
pub use verify::{CredentialVerdict, ResolvedAsOf, VerifierWitnessPolicy, verify, verify_by_said};
