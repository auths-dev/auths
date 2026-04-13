// fn-114: crate-level allow during curve-agnostic refactor. Removed or narrowed in fn-114.40 after Phase 4 sweeps.
#![allow(clippy::disallowed_methods)]
#![deny(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::exit,
    clippy::dbg_macro
)]
#![warn(clippy::too_many_lines, clippy::cognitive_complexity)]
//! # auths-id
//!
//! Identity management and attestation logic for Auths.
//!
//! This crate provides:
//! - **Identity creation** via `did:key` and `did:keri` derivation
//! - **Attestation management** for device linking
//! - **Git storage** for identity and attestation persistence
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐     ┌──────────────┐     ┌─────────────┐
//! │  Identity   │────▶│  Attestation │────▶│ Git Storage │
//! │ (did:keri)  │     │   (signed)   │     │  (refs/*)   │
//! └─────────────┘     └──────────────┘     └─────────────┘
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use auths_id::identity::Identity;
//! use auths_id::attestation::Attestation;
//!
//! // Create an identity from a public key
//! let identity = Identity::from_public_key(&pubkey_bytes)?;
//!
//! // Create an attestation linking a device
//! let attestation = Attestation::builder()
//!     .issuer(&identity.did)
//!     .subject("did:key:z6MkDevice...")
//!     .capability(Capability::SignCommit)
//!     .build()?;
//! ```
//!
//! ## Git Storage Layout
//!
//! | Ref | Content |
//! |-----|---------|
//! | `refs/auths/identity` | Identity metadata |
//! | `refs/auths/devices/nodes/<did>` | Device attestations |
//! | `refs/did/keri/<prefix>/kel` | KERI Key Event Log |
//! | `refs/did/keri/<prefix>/receipts/<said>` | Witness receipts |

#[cfg(feature = "git-storage")]
pub mod agent_identity;
pub mod attestation;
pub mod domain;
pub mod error;
pub mod freeze;
pub mod identity;
pub mod keri;
pub mod policy;
pub mod ports;
pub mod storage;
pub mod trailer;
#[cfg(feature = "git-storage")]
pub mod trust;
#[cfg(feature = "git-storage")]
pub mod witness;
pub mod witness_config;

/// Test utilities for auths-id consumers (behind `test-utils` feature).
#[cfg(feature = "test-utils")]
#[allow(clippy::unwrap_used, clippy::expect_used)]
pub mod testing;
