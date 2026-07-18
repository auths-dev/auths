//! # Auths
//!
//! Decentralized identity for developers. Cryptographic commit signing
//! with Git-native storage using KERI-inspired identity principles.
//!
//! ## CLI
//!
//! ```sh
//! cargo install auths-cli
//! ```
//!
//! ## Crate ecosystem
//!
//! | Crate | Purpose |
//! |-------|---------|
//! | [`auths-core`](https://crates.io/crates/auths-core) | Cryptography and keychain integration |
//! | [`auths-id`](https://crates.io/crates/auths-id) | Identity and attestation logic |
//! | [`auths-verifier`](https://crates.io/crates/auths-verifier) | Standalone verification (FFI/WASM) |
//! | [`auths-sdk`](https://crates.io/crates/auths-sdk) | High-level application services |
//! | [`auths-cli`](https://crates.io/crates/auths-cli) | Command-line interface |
//!
//! ## Re-exports
//!
//! A library consumer can depend on this one crate instead of the individual
//! hyphenated crates:
//!
//! - [`sdk`] — high-level application services (`auths_sdk`): identity,
//!   signing, verification, device/agent workflows.
//! - [`verifier`] — standalone chain/signature verification (`auths_verifier`),
//!   the minimal-dependency surface used by FFI/WASM consumers.

/// High-level application services — re-export of [`auths_sdk`].
pub use auths_sdk as sdk;

/// Standalone verification — re-export of [`auths_verifier`].
pub use auths_verifier as verifier;
