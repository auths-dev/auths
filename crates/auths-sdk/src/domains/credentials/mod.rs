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

/// Relying-party presentation authentication (the full verify flow).
pub mod authenticate;
/// Credential error type (`thiserror`, no `anyhow`).
pub mod error;
/// First-party revocation freshness: delegator refresh port + staleness policy.
pub mod freshness;
/// Issuance, revocation, and listing workflows.
pub mod issue;
/// Holder-binding presentation + challenge issuance (F.8).
pub mod present;
/// Presentation-inputs loader: resolves issuer + subject + delegator KELs (D1).
pub mod present_inputs;
/// The persisted credential envelope (`{acdc, signature}`).
pub mod stored;
/// Verifier-side monotonic usage ledger for quantitative capability caps.
pub mod usage_ledger;
/// Verification — the resolution + freshness layer.
pub mod verify;

pub use authenticate::{PresentationAuthError, authenticate_presentation};
pub use error::CredentialError;
pub use freshness::{
    DelegatorLogSource, FreshnessDecision, PolicyBoundRefresh, RefreshError, RefreshOutcome,
    RevocationFreshnessPolicy, RevocationFreshnessSource, RootRefresh, enforce_freshness,
};
pub use issue::{CredentialIssuance, CredentialSummary, issue, list, revoke};
pub use present::{ChallengeSession, PresentationChallenge, present_credential};
pub use present_inputs::{PresentationInputs, load_presentation_inputs};
pub use stored::StoredCredential;
pub use usage_ledger::{UsageDecision, UsageLedger, UsageObservation};
pub use verify::{
    CredentialVerdict, ResolvedAsOf, VerifierWitnessPolicy, verify, verify_by_said,
    verify_by_said_with_usage, verify_with_issuer_kel,
};
