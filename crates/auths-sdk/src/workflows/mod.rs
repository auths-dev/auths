/// Agent Guard execution workflow for budget enforcement and spend receipts.
pub mod agent_guard;
pub mod approval;
pub mod artifact;
pub mod audit;
/// DID-based authentication challenge signing workflow.
pub mod auth;
/// CI workflows — batch attestation, OIDC machine identity, and future CI automations.
pub mod ci;
/// Commit-time trailer injection (prepare-commit-msg hook + data files).
pub mod commit_hooks;
/// KEL-native commit-trust resolution (successor to the `allowed_signers` allowlist).
pub mod commit_trust;
/// Compliance-as-a-query: evidence packs, DSSE org-signing, offline verification.
pub mod compliance;
pub mod diagnostics;
/// Predicate-agnostic DSSE signing/verification for arbitrary in-toto Statements.
pub mod dsse;
pub mod federation;
pub mod git_integration;
pub mod log_submit;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod multi_sig;
pub mod namespace;
pub mod org;
pub mod platform;
pub mod policy_diff;
pub mod provision;
pub mod roots;
pub mod rotation;
pub mod signing;
pub mod status;
pub mod transparency;
pub mod witness_monitor;
/// Witness-set declaration: the spend-anchor cosigner set, anchored in the KEL.
pub mod witness_set;
