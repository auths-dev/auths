//! Rekor transparency log adapter for Auths.
//!
//! Implements the [`TransparencyLog`] port trait against Sigstore's Rekor v1 API.
//! Targets the production instance at `rekor.sigstore.dev`.
//!
//! ## Entry type
//!
//! Uses `hashedrekord` v0.0.1 with Ed25519 public keys. If Rekor rejects
//! pure Ed25519, the fallback is `dsse` (see design doc Section 5).
//!
//! ## Timeouts
//!
//! - Connect timeout: 5s (fail fast on unreachable)
//! - Request timeout: 20s (Rekor blocks until checkpoint publication)

mod client;
mod error;
mod types;

pub use client::RekorClient;
