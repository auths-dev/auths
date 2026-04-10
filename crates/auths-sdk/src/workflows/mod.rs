pub mod allowed_signers;
pub mod approval;
pub mod artifact;
pub mod audit;
/// DID-based authentication challenge signing workflow.
pub mod auth;
/// CI workflows — batch attestation, OIDC machine identity, and future CI automations.
pub mod ci;
pub mod diagnostics;
pub mod git_integration;
pub mod log_submit;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod namespace;
pub mod org;
pub mod platform;
pub mod policy_diff;
pub mod provision;
pub mod rotation;
pub mod signing;
pub mod status;
pub mod transparency;
