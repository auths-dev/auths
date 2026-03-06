//! Shared JWT claim types for the Auths identity system.
//!
//! This crate provides the data types used in Auths-issued JWTs,
//! shared between the OIDC bridge (token issuer) and MCP server (token consumer).

mod claims;

pub use claims::{ActorClaim, OidcClaims, WitnessQuorumClaim};
