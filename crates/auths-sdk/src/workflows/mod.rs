pub mod allowed_signers;
pub mod approval;
pub mod artifact;
pub mod audit;
/// DID-based authentication challenge signing workflow.
pub mod auth;
pub mod diagnostics;
pub mod git_integration;
/// Machine identity creation from OIDC tokens for ephemeral CI/CD identities.
pub mod machine_identity;
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
