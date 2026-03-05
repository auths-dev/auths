#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![warn(clippy::too_many_lines, clippy::cognitive_complexity)]
#![warn(missing_docs)]
//! # auths-sdk
//!
//! Application services layer for Auths identity operations.
//!
//! This crate provides high-level orchestration functions for identity management,
//! device linking, platform verification, and registry operations. It sits between
//! the CLI (I/O adapter) and the domain crates (`auths-core`, `auths-id`).
//!
//! ## Architecture
//!
//! ```text
//! auths-cli  →  auths-sdk  →  auths-core + auths-id
//! (I/O adapter)  (orchestration)  (domain)
//! ```
//!
//! SDK functions accept typed configs and return structured `Result` types.
//! They never prompt for input, print to stdout, or call `process::exit()`.

/// Runtime dependency container (`AuthsContext`) for injecting infrastructure adapters.
pub mod context;
/// Device linking, revocation, and authorization extension operations.
pub mod device;
/// Domain error types for all SDK operations.
pub mod error;
/// Key import and management operations.
pub mod keys;
/// Device pairing orchestration over ephemeral ECDH sessions.
pub mod pairing;
/// Platform identity claim creation and verification.
pub mod platform;
/// Port traits for external I/O adapters (artifact, git, diagnostics).
pub mod ports;
/// HTML and structured report rendering.
pub mod presentation;
/// Remote registry publication for public DID discovery.
pub mod registration;
/// Return types for SDK workflow functions.
pub mod result;
/// Identity provisioning for developer, CI, and agent environments.
pub mod setup;
/// Artifact signing pipeline and attestation creation.
pub mod signing;
/// Plain-old-data config structs for all SDK workflows.
pub mod types;
/// Higher-level identity workflows (rotation, provisioning, auditing).
pub mod workflows;

/// Test utilities for auths-sdk consumers (behind `test-utils` feature).
#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use context::AuthsContext;
pub use context::EventSink;
