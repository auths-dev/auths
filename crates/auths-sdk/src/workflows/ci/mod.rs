//! CI workflow orchestration — batch signing, OIDC machine identity, and future CI automations.

/// Batch artifact signing and attestation collection.
pub mod batch_attest;
/// OIDC machine identity creation from CI platform tokens.
pub mod machine_identity;
