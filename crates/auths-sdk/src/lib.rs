// fn-114: crate-level allow during curve-agnostic refactor. Removed or narrowed in fn-114.40 after Phase 4 sweeps.
#![allow(clippy::disallowed_methods)]
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

// ── Re-export modules: types from auths-core, auths-id, auths-storage ──
// These allow CLI and API consumers to import through auths-sdk instead of
// depending on lower-layer crates directly.

/// Re-exports of agent process types from `auths-core`.
pub mod agent_core;
/// Re-exports of attestation operations from `auths-id`.
pub mod attestation;
/// Re-exports of configuration types from `auths-core`.
pub mod core_config;
/// Re-exports of cryptographic utilities from `auths-core`.
pub mod crypto;
/// Re-exports of FFI types from `auths-core`.
pub mod ffi;
/// Re-exports of freeze types from `auths-id`.
pub mod freeze;
/// Re-exports of identity types and operations from `auths-id`.
pub mod identity;
/// Re-exports of KERI cache module from `auths-id`.
pub mod keri;
/// Re-exports of keychain and key storage types from `auths-core`.
pub mod keychain;
/// Re-exports of path utilities from `auths-core`.
pub mod paths;
/// Re-exports of Git storage backend types from `auths-storage`.
pub mod storage;
/// Re-exports of storage layout types from `auths-id`.
pub mod storage_layout;
/// Re-exports of trust and pinned identity types from `auths-core`.
pub mod trust;
/// Re-exports of witness server and config types.
pub mod witness;

// ── SDK modules ──

/// Audit event emission convenience for SDK operations.
pub mod audit;
/// Runtime dependency container (`AuthsContext`) for injecting infrastructure adapters.
pub mod context;
/// Device linking, revocation, and authorization extension operations.
pub mod device;
/// Domain services for specialized business logic.
pub mod domains;
/// Domain error types for all SDK operations.
pub mod error;
/// Key import and management operations.
pub mod keys;
/// Namespace verifier adapter registry mapping ecosystems to implementations.
pub mod namespace_registry;
/// OIDC JWT ID (jti) registry for token replay detection.
pub mod oidc_jti_registry;
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

// Re-export types and errors from domains for ease of access
pub use domains::auth::error::*;
pub use domains::compliance::error::*;
pub use domains::device::error::*;
pub use domains::device::types::*;
pub use domains::diagnostics::types::*;
pub use domains::identity::error::*;
pub use domains::identity::types::*;
pub use domains::org::error::*;
pub use domains::signing::types::*;
