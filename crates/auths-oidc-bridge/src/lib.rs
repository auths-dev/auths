// OIDC bridge is a server boundary — Utc::now() is expected for token issuance.
#![allow(clippy::disallowed_methods)]
//! # auths-oidc-bridge
//!
//! OIDC bridge that exchanges KERI attestation chains for short-lived RS256 JWTs
//! consumable by cloud providers (AWS STS, GCP Workload Identity, Azure AD).
//!
//! ## How it works
//!
//! 1. Client POSTs an attestation chain + root public key to `/token`
//! 2. Bridge verifies the chain via `auths-verifier`
//! 3. Bridge issues a signed RS256 JWT with OIDC-standard claims
//! 4. Cloud provider validates the JWT against `/.well-known/jwks.json`

pub mod audience;
pub mod config;
#[cfg(feature = "github-oidc")]
pub mod cross_reference;
pub mod error;
#[cfg(feature = "github-oidc")]
pub mod github_oidc;
pub mod issuer;
pub mod jwks;
#[cfg(feature = "oidc-policy")]
pub mod policy_adapter;
pub mod rate_limit;
pub mod routes;
pub mod state;
pub mod token;

pub use config::BridgeConfig;
#[cfg(feature = "github-oidc")]
pub use cross_reference::{CrossReferenceResult, verify_github_cross_reference};
pub use error::{BridgeError, BridgeResult};
#[cfg(feature = "github-oidc")]
pub use github_oidc::{GitHubOidcClaims, JwksClient, verify_github_token};
pub use issuer::OidcIssuer;
pub use state::BridgeState;
